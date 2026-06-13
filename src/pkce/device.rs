//! The OAuth2 Device Authorization Grant (RFC 8628).
//!
//! This is the headless/SSH path. There is no localhost redirect and no callback
//! listener: the CLI asks Okta for a short `user_code`, prints it with a verification
//! URL, and polls the token endpoint until the user approves on whatever device has a
//! browser. It works identically whether the CLI runs locally or over SSH, because
//! nothing has to be delivered *back* to the host running the CLI - the CLI pulls the
//! token itself by polling.

use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{debug, error, info, warn};
use serde::Deserialize;

use super::DeviceRunner;
use crate::OktaAuthError;
use crate::cache::TokenCache;

/// RFC 8628 grant type for the token poll.
const DEVICE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
/// Per-request HTTP timeout so a stalled connection can't hang the poll forever.
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
/// Poll cadence Okta uses when it omits `interval` from the device response.
const DEFAULT_POLL_INTERVAL_SECS: u64 = 5;
/// How much to back off when Okta returns `slow_down` (RFC 8628 §3.5).
const SLOW_DOWN_INCREMENT_SECS: u64 = 5;
/// Token lifetime assumed when the token response omits `expires_in`.
const DEFAULT_TOKEN_TTL_SECS: u64 = 3600;

/// The device authorization response (RFC 8628 §3.2).
#[derive(Debug, Deserialize)]
struct DeviceAuthorization {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default)]
    interval: Option<u64>,
}

/// A successful token response (RFC 8628 §3.5 / RFC 6749 §5.1).
#[derive(Debug, Deserialize)]
struct TokenSuccess {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// An OAuth2 error response body (RFC 6749 §5.2).
#[derive(Debug, Deserialize)]
struct TokenErrorBody {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// The outcome of a single token-endpoint poll. `Pending`/`SlowDown` keep polling;
/// `Token`/`Failed` are terminal.
#[derive(Debug)]
enum Poll {
    Token(TokenCache),
    Pending,
    SlowDown,
    Failed(OktaAuthError),
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Build the device-authorization request form (RFC 8628 §3.1). `scope` is OPTIONAL,
/// so when no scopes were requested we omit the field entirely rather than send
/// `scope=""` (which some authorization servers reject or treat as a literal scope).
fn device_authorization_form<'a>(client_id: &'a str, scope: &'a str) -> Vec<(&'a str, &'a str)> {
    let mut form = vec![("client_id", client_id)];
    if !scope.is_empty() {
        form.push(("scope", scope));
    }
    form
}

/// Build a [`TokenCache`] from a successful device-grant token response.
fn token_cache_from_success(success: TokenSuccess, now: u64) -> TokenCache {
    let expires_at = now + success.expires_in.unwrap_or(DEFAULT_TOKEN_TTL_SECS);
    TokenCache {
        access_token: success.access_token,
        refresh_token: success.refresh_token,
        expires_at,
    }
}

/// Pure interpretation of a single token-endpoint poll, split out so every arm is
/// unit-testable without a network. `success` is whether the HTTP status was 2xx.
fn interpret_token_response(success: bool, body: &str, now: u64) -> Poll {
    if success {
        return match serde_json::from_str::<TokenSuccess>(body) {
            Ok(token) => Poll::Token(token_cache_from_success(token, now)),
            Err(e) => Poll::Failed(OktaAuthError::TokenExchange(format!("malformed token response: {e}"))),
        };
    }
    match serde_json::from_str::<TokenErrorBody>(body) {
        Ok(body) => match body.error.as_str() {
            // The user hasn't approved yet - keep polling at the same cadence.
            "authorization_pending" => Poll::Pending,
            // We're polling too fast - back off (handled by the caller).
            "slow_down" => Poll::SlowDown,
            // expired_token maps to our existing timeout variant: the code lapsed.
            "expired_token" => Poll::Failed(OktaAuthError::CallbackTimeout),
            // access_denied and anything else are terminal Okta failures.
            _ => Poll::Failed(OktaAuthError::OktaError {
                error: body.error,
                description: body.error_description.unwrap_or_default(),
            }),
        },
        Err(e) => Poll::Failed(OktaAuthError::TokenExchange(format!("malformed error response: {e}"))),
    }
}

/// Print the device-grant instructions to stderr (never stdout, which a caller may be
/// capturing). The `user_code` is shown to the user by design; tokens never are.
fn print_instructions(device: &DeviceAuthorization) {
    eprintln!();
    eprintln!("To sign in, open this page in a browser on any device:");
    eprintln!("    {}", device.verification_uri);
    eprintln!();
    eprintln!("and enter this code:   {}", device.user_code);
    if let Some(complete) = &device.verification_uri_complete {
        eprintln!();
        eprintln!("(or open this link, which fills the code in for you:)");
        eprintln!("    {complete}");
    }
    eprintln!();
    eprintln!("Waiting for approval - this finishes on its own once you confirm.");
}

/// Run the device authorization grant end to end: request a code, print it, and poll
/// the token endpoint until the user approves (or the code expires).
fn run(issuer: &str, client_id: &str, scope: &str) -> Result<TokenCache, OktaAuthError> {
    debug!("device::run: issuer={issuer} client_id={client_id} scope={scope}");

    let http = oauth2::reqwest::blocking::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .map_err(|e| OktaAuthError::DeviceFlow(format!("could not build HTTP client: {e}")))?;

    let device_url = format!("{issuer}/v1/device/authorize");
    let token_url = format!("{issuer}/v1/token");

    // Step 1: request a device + user code.
    let response = http
        .post(device_url.as_str())
        .form(&device_authorization_form(client_id, scope))
        .send()
        .map_err(|e| OktaAuthError::DeviceFlow(format!("device authorization request failed: {e}")))?;
    let status = response.status();
    let body = response
        .text()
        .map_err(|e| OktaAuthError::DeviceFlow(format!("could not read device authorization response: {e}")))?;

    if !status.is_success() {
        warn!("device::run: device authorization failed: status={status}");
        if let Ok(err) = serde_json::from_str::<TokenErrorBody>(&body) {
            return Err(OktaAuthError::OktaError {
                error: err.error,
                description: err.error_description.unwrap_or_default(),
            });
        }
        return Err(OktaAuthError::DeviceFlow(format!(
            "device authorization failed (HTTP {status})"
        )));
    }

    let device: DeviceAuthorization = serde_json::from_str(&body)
        .map_err(|e| OktaAuthError::DeviceFlow(format!("malformed device authorization response: {e}")))?;
    info!(
        "device::run: received user_code, expires_in={}s interval={:?}",
        device.expires_in, device.interval
    );

    print_instructions(&device);

    // Step 2: poll the token endpoint until terminal.
    let mut interval = device.interval.unwrap_or(DEFAULT_POLL_INTERVAL_SECS).max(1);
    let deadline = now_secs() + device.expires_in;
    loop {
        sleep(Duration::from_secs(interval));
        if now_secs() >= deadline {
            warn!("device::run: device code expired before approval");
            return Err(OktaAuthError::CallbackTimeout);
        }

        let response = http
            .post(token_url.as_str())
            .form(&[
                ("grant_type", DEVICE_GRANT_TYPE),
                ("device_code", device.device_code.as_str()),
                ("client_id", client_id),
            ])
            .send()
            .map_err(|e| OktaAuthError::DeviceFlow(format!("token poll request failed: {e}")))?;
        let success = response.status().is_success();
        let body = response
            .text()
            .map_err(|e| OktaAuthError::DeviceFlow(format!("could not read token response: {e}")))?;

        match interpret_token_response(success, &body, now_secs()) {
            Poll::Token(token) => {
                info!("device::run: authorized; tokens acquired");
                return Ok(token);
            }
            Poll::Pending => debug!("device::run: authorization pending"),
            Poll::SlowDown => {
                interval += SLOW_DOWN_INCREMENT_SECS;
                debug!("device::run: slow_down; interval now {interval}s");
            }
            Poll::Failed(e) => {
                error!("device::run: terminal failure: {e}");
                return Err(e);
            }
        }
    }
}

/// Production [`DeviceRunner`]: runs the real RFC 8628 flow against Okta.
pub struct HttpDeviceRunner;

impl DeviceRunner for HttpDeviceRunner {
    fn run(&self, issuer: &str, client_id: &str, scope: &str) -> Result<TokenCache, OktaAuthError> {
        run(issuer, client_id, scope)
    }
}

#[cfg(test)]
mod tests;
