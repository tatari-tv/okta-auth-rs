use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{debug, info};
use oauth2::basic::BasicClient;
use oauth2::url::Url;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse, TokenUrl,
};

use crate::OktaAuthError;
use crate::cache::TokenCache;

const CALLBACK_TIMEOUT: Duration = Duration::from_secs(60);

pub fn authorize(
    issuer: &str,
    client_id: &str,
    redirect_uri: &str,
    scopes: &[String],
) -> Result<TokenCache, OktaAuthError> {
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
    let bind_addr = format!("127.0.0.1:{port}");

    let server = tiny_http::Server::http(&bind_addr).map_err(|e| OktaAuthError::BindFailed {
        addr: bind_addr,
        source: e,
    })?;

    info!("Opening browser for authentication...");
    open::that(authorize_url.as_str())?;

    eprintln!("Waiting for authentication in browser...");

    let (code, state) = wait_for_callback(&server)?;

    if state != *csrf_state.secret() {
        return Err(OktaAuthError::CsrfMismatch);
    }

    info!("Exchanging authorization code for tokens...");
    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request(&oauth2::reqwest::blocking::Client::new())
        .map_err(|e| OktaAuthError::TokenExchange(e.to_string()))?;

    let expires_at = token_response
        .expires_in()
        .map(|d| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + d.as_secs()
        })
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                + 3600
        });

    Ok(TokenCache {
        access_token: token_response.access_token().secret().to_string(),
        refresh_token: token_response.refresh_token().map(|t| t.secret().to_string()),
        expires_at,
    })
}

fn wait_for_callback(server: &tiny_http::Server) -> Result<(String, String), OktaAuthError> {
    let request = server
        .recv_timeout(CALLBACK_TIMEOUT)
        .map_err(|e| OktaAuthError::TokenExchange(e.to_string()))?
        .ok_or(OktaAuthError::CallbackTimeout)?;

    let url = request.url().to_string();
    debug!("callback url: {}", url);

    let query = url.split('?').nth(1).ok_or(OktaAuthError::NoQueryParams)?;

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

    let response_body = if error.is_some() {
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
    let _ = request.respond(response);

    if let Some(err) = error {
        let desc = error_description.unwrap_or_default();
        return Err(OktaAuthError::OktaError {
            error: err,
            description: desc,
        });
    }

    let code = code.ok_or(OktaAuthError::NoAuthCode)?;
    let state = state.ok_or(OktaAuthError::NoState)?;

    Ok((code, state))
}
