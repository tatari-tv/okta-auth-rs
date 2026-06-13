//! The OAuth2 authorization flow, split by session type.
//!
//! `authorize()`:
//!   1. validates config / builds the authorize URL first (so a malformed config
//!      surfaces as `InvalidUrl`, not masked by the session check);
//!   2. classifies the session (Local / Headless / NonInteractive);
//!   3. dispatches:
//!      - **Local** (at the machine, GUI present): the classic localhost-redirect PKCE
//!        flow - open the browser, auto-capture the callback on `127.0.0.1:<port>`.
//!        Zero-touch, unchanged.
//!      - **Headless** (SSH, or no GUI): the **device authorization grant** - show a
//!        short code, poll for approval. No listener, no redirect, no paste; works the
//!        same locally and remotely. If the local callback port is somehow busy, Local
//!        also falls back to this.
//!      - **NonInteractive** (no controlling terminal: CI, agent shell): fail fast.

mod clock;
mod device;
mod listener;
mod session;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{debug, error, info, trace, warn};
use oauth2::basic::BasicClient;
use oauth2::url::Url;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse, TokenUrl,
};

use crate::OktaAuthError;
use crate::cache::TokenCache;
use clock::{Clock, RealClock};
use listener::{Capture, HttpListener, Listener};
use session::{Session, classify, controlling_terminal_available, gui_likely_from_env, ssh_from_env};

/// How often the local redirect loop polls the listener between idle scans.
const POLL_INTERVAL: Duration = Duration::from_millis(75);

/// A generous backstop for the local browser flow: the user is at the machine
/// clicking through, so this only guards against a wedged process.
const LOCAL_CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

/// Binds the callback listener. Injected so tests can supply a fake.
trait Binder {
    type Listener: Listener;
    fn bind(&self, port: u16) -> Option<Self::Listener>;
}

/// Launches the system browser. Injected so tests can supply a no-op.
trait Opener {
    fn open(&self, url: &str);
}

/// Runs the device authorization grant. Injected so tests can supply a fake without
/// hitting Okta.
trait DeviceRunner {
    fn run(&self, issuer: &str, client_id: &str, scope: &str) -> Result<TokenCache, OktaAuthError>;
}

/// Production binder: a real `tiny_http` listener on `127.0.0.1:<port>`.
struct HttpBinder;

impl Binder for HttpBinder {
    type Listener = HttpListener;
    fn bind(&self, port: u16) -> Option<HttpListener> {
        HttpListener::bind(port)
    }
}

/// Production opener: `open::that()`.
struct SystemOpener;

impl Opener for SystemOpener {
    fn open(&self, url: &str) {
        info!("SystemOpener::open: launching browser");
        if let Err(e) = open::that(url) {
            warn!("SystemOpener::open: could not open browser automatically: {e}");
        }
    }
}

pub fn authorize(
    issuer: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
) -> Result<TokenCache, OktaAuthError> {
    debug!("authorize: issuer={issuer} client_id={client_id} redirect_uri={redirect_uri}");

    // Step 1: build/validate URLs FIRST so a malformed config surfaces as
    // `InvalidUrl` rather than being masked by the session check below.
    let auth_url =
        AuthUrl::new(format!("{issuer}/v1/authorize")).map_err(|e| OktaAuthError::InvalidUrl(e.to_string()))?;
    let token_url =
        TokenUrl::new(format!("{issuer}/v1/token")).map_err(|e| OktaAuthError::InvalidUrl(e.to_string()))?;

    let client = BasicClient::new(ClientId::new(client_id.to_string()))
        .set_auth_uri(auth_url)
        .set_token_uri(token_url)
        .set_redirect_uri(
            RedirectUrl::new(redirect_uri.to_string()).map_err(|e| OktaAuthError::InvalidUrl(e.to_string()))?,
        );

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut auth_request = client.authorize_url(CsrfToken::new_random);
    for scope in scopes {
        auth_request = auth_request.add_scope(Scope::new(scope.to_string()));
    }
    let (authorize_url, csrf_state) = auth_request.set_pkce_challenge(pkce_challenge).url();

    let parsed = Url::parse(redirect_uri).map_err(|e| OktaAuthError::InvalidUrl(e.to_string()))?;
    let port = parsed.port().unwrap_or(80);

    // The token exchange for the LOCAL (authorization-code) path stays at this boundary
    // so the inner loop can be unit-tested without hitting Okta. It captures the client
    // and PKCE verifier. The device path does its own token poll and never uses this.
    let exchange = move |code: &str| -> Result<TokenCache, OktaAuthError> {
        info!("authorize: exchanging authorization code for tokens");
        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(pkce_verifier)
            .request(&oauth2::reqwest::blocking::Client::new())
            .map_err(|e| OktaAuthError::TokenExchange(e.to_string()))?;
        Ok(token_cache_from_response(&token_response))
    };

    let scope = scopes.join(" ");

    authorize_inner(
        authorize_url.as_str(),
        csrf_state.secret(),
        issuer,
        client_id,
        &scope,
        port,
        ssh_from_env(),
        gui_likely_from_env(),
        controlling_terminal_available(),
        &HttpBinder,
        &SystemOpener,
        &device::HttpDeviceRunner,
        &RealClock::new(),
        LOCAL_CALLBACK_TIMEOUT,
        POLL_INTERVAL,
        exchange,
    )
}

/// The world-injected core of `authorize()`. Classifies the session and dispatches:
/// `NonInteractive` fails fast; `Headless` runs the device grant; `Local` binds the
/// listener, opens the browser, captures the callback, verifies CSRF, and exchanges.
#[allow(clippy::too_many_arguments)]
fn authorize_inner<B, O, D, C, X>(
    authorize_url: &str,
    csrf_secret: &str,
    issuer: &str,
    client_id: &str,
    scope: &str,
    port: u16,
    ssh: bool,
    gui_likely: bool,
    has_tty: bool,
    binder: &B,
    opener: &O,
    device: &D,
    clock: &C,
    backstop: Duration,
    poll_interval: Duration,
    exchange: X,
) -> Result<TokenCache, OktaAuthError>
where
    B: Binder,
    O: Opener,
    D: DeviceRunner,
    C: Clock,
    X: FnOnce(&str) -> Result<TokenCache, OktaAuthError>,
{
    let session = classify(has_tty, ssh, gui_likely);

    match session {
        Session::NonInteractive => {
            debug!("authorize_inner: NonInteractive, failing fast");
            Err(OktaAuthError::NonInteractive)
        }
        Session::Headless => {
            info!("authorize_inner: headless session -> device authorization grant");
            device.run(issuer, client_id, scope)
        }
        Session::Local => match binder.bind(port) {
            Some(server) => {
                info!("authorize_inner: local session -> browser redirect flow");
                opener.open(authorize_url);
                eprintln!("Opening your browser to sign in. If it doesn't open, visit:");
                eprintln!("{authorize_url}");
                let (code, state) = local_loop(&server, clock, backstop, poll_interval)?;
                if state != csrf_secret {
                    error!("authorize_inner: CSRF state mismatch - possible attack");
                    return Err(OktaAuthError::CsrfMismatch);
                }
                exchange(&code)
            }
            None => {
                // Local callback port held (e.g. a stale `ssh -L` tunnel): rather than
                // fail, fall back to the device grant, which needs no listener.
                warn!("authorize_inner: callback port busy; falling back to device grant");
                device.run(issuer, client_id, scope)
            }
        },
    }
}

/// The local browser flow's capture loop: poll the listener non-blocking until it
/// yields a callback, a terminal Okta error, or the backstop fires.
fn local_loop<L, C>(
    server: &L,
    clock: &C,
    backstop: Duration,
    poll_interval: Duration,
) -> Result<(String, String), OktaAuthError>
where
    L: Listener,
    C: Clock,
{
    debug!("local_loop: backstop={backstop:?} poll_interval={poll_interval:?}");
    loop {
        match server.poll() {
            Ok(Some(Capture::Code(code, state))) => {
                debug!("local_loop: listener captured callback");
                return Ok((code, state));
            }
            Ok(Some(Capture::OktaError(e))) => {
                error!("local_loop: listener surfaced okta error: {e}");
                return Err(e);
            }
            Ok(Some(Capture::Ignore)) => trace!("local_loop: ignored stray request"),
            Ok(None) => trace!("local_loop: no request pending"),
            Err(e) => warn!("local_loop: listener poll failed: {e} (transient, continuing)"),
        }

        if clock.elapsed() >= backstop {
            warn!("local_loop: callback timeout reached");
            return Err(OktaAuthError::CallbackTimeout);
        }
        clock.sleep(poll_interval);
    }
}

/// Build a `TokenCache` from a token response, computing `expires_at` (defaulting to
/// one hour out when the response omits `expires_in`).
fn token_cache_from_response(
    token_response: &oauth2::StandardTokenResponse<oauth2::EmptyExtraTokenFields, oauth2::basic::BasicTokenType>,
) -> TokenCache {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let expires_at = token_response
        .expires_in()
        .map(|d| now + d.as_secs())
        .unwrap_or(now + 3600);

    TokenCache {
        access_token: token_response.access_token().secret().to_string(),
        refresh_token: token_response.refresh_token().map(|t| t.secret().to_string()),
        expires_at,
    }
}

#[cfg(test)]
mod tests;
