//! The OAuth2 PKCE "localhost redirect" flow, reworked for non-blocking
//! headless/SSH authentication.
//!
//! Instead of binding the callback listener and then blocking on a fixed 60s
//! timeout before offering a paste fallback, `authorize()` now:
//!   1. validates config / builds the authorize URL first (so a malformed config
//!      still surfaces as `InvalidUrl`, not masked by interactivity);
//!   2. classifies the session (Local / Headless / NonInteractive);
//!   3. fails fast with `NonInteractive` before binding or opening anything;
//!   4. binds an `Option<Server>` (bind failure is non-fatal when interactive) and
//!      opens the browser only when `Local`;
//!   5. runs a single-threaded readiness loop that races the listener against
//!      paste input read from the controlling terminal - whichever yields a
//!      `(code, state)` first wins.

mod clock;
mod input;
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
use input::{Input, InputSource, ReadOutcome, TtySource};
use listener::{Capture, HttpListener, Listener, parse_callback_url};
use session::{Session, classify, gui_likely_from_env, ssh_from_env};

/// How often the readiness loop yields between idle scans. Both sources are read
/// non-blocking; this sleep keeps the loop from busy-waiting. Anything in the
/// 50-100ms range keeps capture latency sub-second.
const POLL_INTERVAL: Duration = Duration::from_millis(75);

/// A generous backstop so a wedged pty-wrapped process can't hang forever. Paste is
/// instant, so a human never hits it; it is not the primary control path.
const BACKSTOP_TIMEOUT: Duration = Duration::from_secs(300);

/// Upper bound on the paste carry buffer: a single line exceeding this without a
/// newline is discarded rather than growing unbounded (no OOM from a runaway pipe).
const MAX_PASTE: usize = 8 * 1024;

/// Binds the callback listener. Injected so tests can supply a fake.
trait Binder {
    type Listener: Listener;
    fn bind(&self, port: u16) -> Option<Self::Listener>;
}

/// Launches the system browser. Injected so tests can supply a no-op.
trait Opener {
    fn open(&self, url: &str);
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
    // `InvalidUrl` rather than being masked by the interactivity check below.
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

    // The token exchange stays at this boundary so the inner loop can be unit-tested
    // without hitting Okta. It captures the client and PKCE verifier.
    let exchange = move |code: &str| -> Result<TokenCache, OktaAuthError> {
        info!("authorize: exchanging authorization code for tokens");
        let token_response = client
            .exchange_code(AuthorizationCode::new(code.to_string()))
            .set_pkce_verifier(pkce_verifier)
            .request(&oauth2::reqwest::blocking::Client::new())
            .map_err(|e| OktaAuthError::TokenExchange(e.to_string()))?;
        Ok(token_cache_from_response(&token_response))
    };

    authorize_inner(
        authorize_url.as_str(),
        csrf_state.secret(),
        port,
        ssh_from_env(),
        gui_likely_from_env(),
        &HttpBinder,
        &SystemOpener,
        &TtySource::new(MAX_PASTE),
        &RealClock::new(),
        BACKSTOP_TIMEOUT,
        POLL_INTERVAL,
        exchange,
    )
}

/// The world-injected core of `authorize()`. Classifies the session, fails fast on
/// `NonInteractive` (before binding/opening), binds + opens per classification, runs
/// the readiness loop, verifies CSRF state, then exchanges the code.
#[allow(clippy::too_many_arguments)]
fn authorize_inner<B, O, S, C, X>(
    authorize_url: &str,
    csrf_secret: &str,
    port: u16,
    ssh: bool,
    gui_likely: bool,
    binder: &B,
    opener: &O,
    input_source: &S,
    clock: &C,
    backstop: Duration,
    poll_interval: Duration,
    exchange: X,
) -> Result<TokenCache, OktaAuthError>
where
    B: Binder,
    O: Opener,
    S: InputSource,
    C: Clock,
    X: FnOnce(&str) -> Result<TokenCache, OktaAuthError>,
{
    // Step 2: classify by whether the controlling terminal is reachable. Acquiring
    // the input source IS the reachability test (and acquires the source in one step).
    let acquired = input_source.acquire();
    let session = classify(acquired.is_some(), ssh, gui_likely);

    // Step 3: NonInteractive fails fast, before binding or opening anything.
    let headless = match session {
        Session::NonInteractive => {
            debug!("authorize_inner: NonInteractive, failing fast before bind/open");
            return Err(OktaAuthError::NonInteractive);
        }
        Session::Local => false,
        Session::Headless => true,
    };
    let mut input = acquired.expect("interactive session must have an acquired controlling terminal");

    // Step 4: bind (interactive only, so bind failure is never fatal) and open.
    let server = binder.bind(port);

    eprintln!("Open this URL to authenticate:");
    eprintln!("{authorize_url}");
    eprintln!();
    if headless {
        eprintln!("Open this on your machine. If it shows \"can't be reached\", paste the address-bar URL here:");
        eprint!("> ");
    } else {
        opener.open(authorize_url);
        eprintln!("Your browser should open automatically; if it doesn't, open the URL above.");
    }

    // Step 5: race the listener against pasted input.
    let (code, state) = run_loop(server, &mut input, clock, headless, backstop, poll_interval)?;

    // One CSRF check, then one token exchange - unchanged from before.
    if state != csrf_secret {
        error!("authorize_inner: CSRF state mismatch - possible attack");
        return Err(OktaAuthError::CsrfMismatch);
    }

    exchange(&code)
}

/// The single-threaded readiness loop. Polls the listener and the terminal, both
/// non-blocking, sleeping `poll_interval` between idle scans. First source to yield
/// `(code, state)` wins. There is no background thread, so cancellation is free: when
/// the listener wins we simply stop polling the tty.
fn run_loop<L, I, C>(
    server: Option<L>,
    input: &mut I,
    clock: &C,
    headless: bool,
    backstop: Duration,
    poll_interval: Duration,
) -> Result<(String, String), OktaAuthError>
where
    L: Listener,
    I: Input,
    C: Clock,
{
    debug!(
        "run_loop: headless={headless} have_listener={} backstop={backstop:?} poll_interval={poll_interval:?}",
        server.is_some()
    );
    let mut tty_live = true;
    loop {
        // 1) Listener: non-blocking. A stray request is ignored; a real ?error= is
        //    surfaced immediately rather than waited out to the backstop.
        if let Some(ref server) = server {
            match server.poll() {
                Ok(Some(Capture::Code(code, state))) => {
                    debug!("run_loop: listener won");
                    return Ok((code, state));
                }
                Ok(Some(Capture::OktaError(e))) => {
                    error!("run_loop: listener surfaced okta error: {e}");
                    return Err(e);
                }
                Ok(Some(Capture::Ignore)) => trace!("run_loop: ignored stray request"),
                Ok(None) => trace!("run_loop: no request pending"),
                Err(e) => warn!("run_loop: listener poll failed: {e} (transient, continuing)"),
            }
        }

        // 2) Terminal: non-blocking. A bad paste reprompts (Headless) or is silently
        //    ignored (Local); a pasted ?error= is terminal and surfaces now.
        if tty_live {
            match input.read_available() {
                Ok(ReadOutcome::Line(raw)) => match parse_callback_url(raw.trim()) {
                    Ok((code, state)) => {
                        debug!("run_loop: paste won");
                        return Ok((code, state));
                    }
                    Err(e @ OktaAuthError::OktaError { .. }) => {
                        error!("run_loop: pasted url surfaced okta error: {e}");
                        return Err(e);
                    }
                    Err(_) if headless => {
                        eprintln!("Couldn't parse that; paste the full callback URL:");
                        eprint!("> ");
                    }
                    Err(_) => {} // Local: silently ignore junk, preserving zero-touch.
                },
                Ok(ReadOutcome::Overflow) if headless => {
                    eprintln!("That input was too long; paste just the callback URL:");
                    eprint!("> ");
                }
                Ok(ReadOutcome::Overflow) => {} // Local: silent.
                Ok(ReadOutcome::Eof) => {
                    debug!("run_loop: tty EOF, paste path closed (listener/backstop continue)");
                    tty_live = false;
                }
                Ok(ReadOutcome::Pending) => {}
                Err(e) => {
                    warn!("run_loop: tty read failed: {e}; closing paste path");
                    tty_live = false;
                }
            }
        }

        if clock.elapsed() >= backstop {
            warn!("run_loop: backstop timeout reached");
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
