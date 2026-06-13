//! The HTTP callback listener port for the local browser-redirect flow, plus the
//! query-string parsing it uses.
//!
//! The port yields parsed [`Capture`] outcomes rather than raw `tiny_http::Request`
//! values, so the capture loop (and its tests) never has to fabricate HTTP requests -
//! it asserts against `Capture::{Code, OktaError, Ignore}`.

use std::io;

use log::{debug, trace};

use crate::OktaAuthError;

/// The outcome of a single callback request.
#[derive(Debug)]
pub enum Capture {
    /// A request carrying `?code=&state=` - the authorization succeeded. `(code, state)`.
    Code(String, String),
    /// A request carrying `?error=...` - a terminal Okta failure, surfaced immediately.
    OktaError(OktaAuthError),
    /// A no-query / favicon / preflight / port-scan request - respond and keep waiting.
    Ignore,
}

/// A non-blocking source of callback captures.
///
/// `poll` returns `Ok(None)` when no request is pending (the loop should keep
/// scanning), `Ok(Some(capture))` when a request arrived and was parsed, and `Err`
/// only for a transient accept error (the loop warns and keeps waiting - a transient
/// failure must not kill an in-progress login).
pub trait Listener {
    fn poll(&self) -> io::Result<Option<Capture>>;
}

/// The production listener: a `tiny_http` server on `127.0.0.1:<port>`.
pub struct HttpListener {
    server: tiny_http::Server,
}

impl HttpListener {
    /// Bind the callback listener. Returns `None` on bind failure (a held port, e.g.
    /// a stale `ssh -L` tunnel): the caller then falls back to the device grant, which
    /// needs no listener.
    pub fn bind(port: u16) -> Option<Self> {
        let bind_addr = format!("127.0.0.1:{port}");
        match tiny_http::Server::http(&bind_addr) {
            Ok(server) => {
                debug!("HttpListener::bind: bound {bind_addr}");
                Some(Self { server })
            }
            Err(e) => {
                log::warn!("HttpListener::bind: could not bind {bind_addr}: {e} (device-grant fallback)");
                None
            }
        }
    }
}

impl Listener for HttpListener {
    fn poll(&self) -> io::Result<Option<Capture>> {
        // Non-blocking: try_recv() -> io::Result<Option<Request>>.
        match self.server.try_recv()? {
            Some(request) => {
                let url = request.url().to_string();
                // Log only the path - the query carries the OAuth `code`/`state` secrets.
                let path = url.split('?').next().unwrap_or("/");
                trace!("HttpListener::poll: received callback request path={path}");
                let capture = parse_request_url(&url);
                respond(request, matches!(capture, Capture::OktaError(_)));
                Ok(Some(capture))
            }
            None => Ok(None),
        }
    }
}

/// Parse a listener request URL into a `Capture`. A no-query request (favicon,
/// preflight, port-scan) is `Ignore`d rather than aborting the flow.
fn parse_request_url(url: &str) -> Capture {
    let Some(query) = url.split('?').nth(1) else {
        return Capture::Ignore;
    };
    let (code, state, error, error_description) = parse_query_params(query);
    match to_code_and_state(code, state, error, error_description) {
        Ok((code, state)) => Capture::Code(code, state),
        Err(e @ OktaAuthError::OktaError { .. }) => Capture::OktaError(e),
        // A request with a query but no code/state/error (e.g. `/callback?foo=bar`)
        // is not a real callback - ignore it rather than aborting.
        Err(_) => Capture::Ignore,
    }
}

/// Write the "you can close this tab" HTML response for a callback request.
fn respond(request: tiny_http::Request, is_error: bool) {
    let response_body = if is_error {
        "<html><body><h1>Authentication Failed</h1><p>You can close this tab.</p></body></html>"
    } else {
        "<html><body><h1>Authentication Successful</h1><p>You can close this tab.</p></body></html>"
    };
    let response = tiny_http::Response::new(
        tiny_http::StatusCode(200),
        vec![
            tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html"[..])
                .expect("static Content-Type header is always valid"),
        ],
        std::io::Cursor::new(response_body),
        Some(response_body.len()),
        None,
    );
    if let Err(e) = request.respond(response) {
        log::warn!("respond: failed to write callback response: {e}");
    }
}

fn parse_query_params(query: &str) -> (Option<String>, Option<String>, Option<String>, Option<String>) {
    let mut code = None;
    let mut state = None;
    let mut error = None;
    let mut error_description = None;

    for param in query.split('&') {
        let mut parts = param.splitn(2, '=');
        let key = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        let decoded = urlencoding::decode(value).unwrap_or_default().to_string();
        match key {
            "code" => code = Some(decoded),
            "state" => state = Some(decoded),
            "error" => error = Some(decoded),
            "error_description" => error_description = Some(decoded),
            _ => {}
        }
    }

    (code, state, error, error_description)
}

fn to_code_and_state(
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
) -> Result<(String, String), OktaAuthError> {
    if let Some(err) = error {
        return Err(OktaAuthError::OktaError {
            error: err,
            description: error_description.unwrap_or_default(),
        });
    }
    Ok((
        code.ok_or(OktaAuthError::NoAuthCode)?,
        state.ok_or(OktaAuthError::NoState)?,
    ))
}
