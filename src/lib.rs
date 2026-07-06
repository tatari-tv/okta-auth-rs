#![deny(clippy::unwrap_used)]
#![deny(dead_code)]
#![deny(unused_variables)]

mod cache;
mod error;
mod pkce;
pub mod tatari;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use log::{debug, info, warn};
use oauth2::basic::BasicClient;
use oauth2::{ClientId, RefreshToken, TokenResponse, TokenUrl};

pub use cache::TokenCache;
pub use error::OktaAuthError;

/// Configuration for the Okta OAuth2 PKCE authentication flow.
/// Each consuming CLI provides its own values.
#[derive(Debug, Clone)]
pub struct OktaAuthConfig {
    /// Okta authorization server issuer URL (e.g. "https://myorg.okta.com/oauth2/default")
    pub okta_issuer: String,
    /// Okta application client ID
    pub client_id: String,
    /// Local redirect URI (e.g. "http://local.myorg.tools:11313/callback")
    pub redirect_uri: String,
    /// OAuth2 scopes to request
    pub scopes: Vec<String>,
    /// Application name (informational, e.g. for logging). The token cache is shared
    /// across all okta-auth consumers at `~/.cache/okta/` and is NOT keyed by this
    /// name, so tools using the same Okta client share one cached credential.
    pub app_name: String,
    /// Override the token cache directory. If None, uses the shared `~/.cache/okta/`.
    pub cache_dir: Option<PathBuf>,
}

/// Outcome of [`OktaAuth::login_or_reuse`]. Carries the real cache path so the
/// consumer's status line is always accurate (no hardcoded, drift-prone paths).
#[derive(Debug)]
pub enum LoginOutcome {
    /// A valid token was already cached; no flow ran. `since` is when it was cached
    /// (the cache file's mtime), if readable.
    AlreadyLoggedIn {
        cache_path: PathBuf,
        since: Option<SystemTime>,
    },
    /// A login flow ran and cached a fresh token.
    LoggedIn { cache_path: PathBuf },
}

impl LoginOutcome {
    /// A ready-to-print one-line status, with the real cache path. Stream choice
    /// (stdout vs stderr) is left to the consumer.
    pub fn message(&self) -> String {
        match self {
            Self::AlreadyLoggedIn { cache_path, since } => {
                let ago = since.map(format_ago).unwrap_or_default();
                format!(
                    "Already logged in{} (token cached at {}). Use --force to re-authenticate.",
                    ago,
                    cache_path.display()
                )
            }
            Self::LoggedIn { cache_path } => {
                format!("Logged in. Token cached at {}.", cache_path.display())
            }
        }
    }
}

/// Human "~Nh ago" / "~Nm ago" for a past instant; empty-ish on clock skew.
fn format_ago(since: SystemTime) -> String {
    match SystemTime::now().duration_since(since) {
        Ok(d) => {
            let secs = d.as_secs();
            if secs < 3600 {
                format!(" since ~{}m ago", secs / 60)
            } else {
                format!(" since ~{}h ago", secs / 3600)
            }
        }
        Err(_) => String::new(),
    }
}

/// Okta OAuth2 PKCE authenticator for CLI tools.
///
/// Handles the full token lifecycle: cache lookup, transparent refresh, and browser-based login.
pub struct OktaAuth {
    config: OktaAuthConfig,
}

impl OktaAuth {
    pub fn new(config: OktaAuthConfig) -> Self {
        Self { config }
    }

    /// Returns a reference to the config.
    pub fn config(&self) -> &OktaAuthConfig {
        &self.config
    }

    /// The token cache directory actually in use: the shared `~/.cache/okta` by
    /// default, or an explicit `cache_dir` override. Public so consumers can report
    /// the real path in `--help`/status output instead of hardcoding (and lying).
    pub fn cache_dir(&self) -> PathBuf {
        self.config.cache_dir.clone().unwrap_or_else(cache::default_cache_dir)
    }

    /// The full path to the token cache file (`<cache_dir>/tokens.json`).
    pub fn cache_path(&self) -> PathBuf {
        cache::cache_path(&self.cache_dir())
    }

    /// Return the cached token if one exists AND is still valid, WITHOUT triggering a
    /// refresh or interactive login. Lets a CLI make `login` idempotent ("already
    /// logged in") and report status without forcing the flow.
    pub fn cached_valid_token(&self) -> Result<Option<TokenCache>, OktaAuthError> {
        Ok(cache::load(&self.cache_dir())?.filter(|c| c.is_valid()))
    }

    /// Idempotent login. When `force` is false and a valid token is already cached,
    /// this is a no-op that reports how long ago you logged in. Otherwise it runs the
    /// flow (device grant when `device`, else auto-detect browser/device) and caches
    /// the token. Consumers wire a `--force` flag to `force` and print
    /// [`LoginOutcome::message`] - so the "already logged in" / truthful-path behavior
    /// lives here once, not re-implemented per CLI.
    pub fn login_or_reuse(&self, force: bool, device: bool) -> Result<LoginOutcome, OktaAuthError> {
        debug!("login_or_reuse: force={force} device={device}");
        let cache_path = self.cache_path();
        if !force && self.cached_valid_token()?.is_some() {
            let since = std::fs::metadata(&cache_path).and_then(|m| m.modified()).ok();
            return Ok(LoginOutcome::AlreadyLoggedIn { cache_path, since });
        }
        if device {
            self.login_device()?;
        } else {
            self.login()?;
        }
        Ok(LoginOutcome::LoggedIn { cache_path })
    }

    /// Returns a valid access token. Refreshes or re-authenticates as needed.
    pub fn get_token(&self) -> Result<String, OktaAuthError> {
        let dir = self.cache_dir();
        if let Some(cached) = cache::load(&dir)? {
            if cached.is_valid() {
                debug!("using cached access token (expires_at={})", cached.expires_at);
                return Ok(cached.access_token);
            }

            if let Some(ref refresh_token) = cached.refresh_token {
                debug!("access token expired, attempting refresh");
                match self.refresh(refresh_token) {
                    Ok(new_cache) => {
                        cache::save(&dir, &new_cache)?;
                        return Ok(new_cache.access_token);
                    }
                    Err(e) => {
                        warn!("token refresh failed: {}, falling through to browser login", e);
                    }
                }
            }
        }

        info!("no valid cached token, starting browser login");
        let token_cache = pkce::authorize(
            &self.config.okta_issuer,
            &self.config.client_id,
            &self.config.redirect_uri,
            &self.config.scopes,
        )?;
        cache::save(&dir, &token_cache)?;
        Ok(token_cache.access_token)
    }

    /// Return a valid access token WITHOUT any interactive flow: cached token when
    /// valid, else a silent refresh via the cached refresh token, else
    /// [`OktaAuthError::NonInteractive`]. It NEVER launches a browser or the device
    /// grant. Intended for headless servers (e.g. `persona mcp`) that must fail fast
    /// with a "run `<tool> login`" hint instead of blocking on a login prompt.
    ///
    /// Distinct from [`get_token`], which falls through to a browser login when no
    /// usable cached/refreshable token exists.
    ///
    /// [`get_token`]: OktaAuth::get_token
    pub fn get_token_noninteractive(&self) -> Result<String, OktaAuthError> {
        let dir = self.cache_dir();
        debug!("get_token_noninteractive: cache_dir={}", dir.display());
        if let Some(cached) = cache::load(&dir)? {
            if cached.is_valid() {
                debug!(
                    "get_token_noninteractive: using cached access token (expires_at={})",
                    cached.expires_at
                );
                return Ok(cached.access_token);
            }

            if let Some(ref refresh_token) = cached.refresh_token {
                debug!("get_token_noninteractive: access token expired, attempting silent refresh");
                match self.refresh(refresh_token) {
                    Ok(new_cache) => {
                        cache::save(&dir, &new_cache)?;
                        debug!(
                            "get_token_noninteractive: refresh succeeded (expires_at={})",
                            new_cache.expires_at
                        );
                        return Ok(new_cache.access_token);
                    }
                    Err(e) => {
                        // Log the real cause (Okta down / timeout / refresh-token rotation)
                        // before collapsing to NonInteractive, so headless drops stay
                        // debuggable - then fail closed, never a browser.
                        warn!(
                            "get_token_noninteractive: refresh failed ({e}); no interactive fallback, returning NonInteractive"
                        );
                        return Err(OktaAuthError::NonInteractive);
                    }
                }
            }

            warn!("get_token_noninteractive: cached token expired with no refresh token; returning NonInteractive");
            return Err(OktaAuthError::NonInteractive);
        }

        warn!("get_token_noninteractive: no cached token; returning NonInteractive");
        Err(OktaAuthError::NonInteractive)
    }

    /// Force interactive login, auto-detecting the flow: a local GUI session uses
    /// the browser redirect, anything headless uses the device grant. Fails fast in
    /// a non-interactive session (no controlling terminal) - use [`login_device`] to
    /// force the device grant there.
    ///
    /// [`login_device`]: OktaAuth::login_device
    pub fn login(&self) -> Result<(), OktaAuthError> {
        debug!("login: auto-detecting flow (browser vs device grant)");
        let dir = self.cache_dir();
        let token_cache = pkce::authorize(
            &self.config.okta_issuer,
            &self.config.client_id,
            &self.config.redirect_uri,
            &self.config.scopes,
        )?;
        cache::save(&dir, &token_cache)?;
        Ok(())
    }

    /// Force login via the OAuth2 device authorization grant (RFC 8628), bypassing
    /// session classification. Unlike [`login`], this works with no controlling
    /// terminal (agent shells, CI): it prints a code + verification URL and polls,
    /// delivering nothing back to this host. The user approves on any device.
    ///
    /// [`login`]: OktaAuth::login
    pub fn login_device(&self) -> Result<(), OktaAuthError> {
        debug!("login_device: forcing device authorization grant");
        let dir = self.cache_dir();
        let token_cache =
            pkce::authorize_device(&self.config.okta_issuer, &self.config.client_id, &self.config.scopes)?;
        cache::save(&dir, &token_cache)?;
        Ok(())
    }

    /// Delete cached tokens.
    pub fn logout(&self) -> Result<(), OktaAuthError> {
        let dir = self.cache_dir();
        cache::clear(&dir)?;
        Ok(())
    }

    fn refresh(&self, refresh_token: &str) -> Result<TokenCache, OktaAuthError> {
        let token_url = TokenUrl::new(format!("{}/v1/token", self.config.okta_issuer))
            .map_err(|e| OktaAuthError::InvalidUrl(e.to_string()))?;

        let client = BasicClient::new(ClientId::new(self.config.client_id.to_string())).set_token_uri(token_url);

        let token_response = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request(&oauth2::reqwest::blocking::Client::new())
            .map_err(|e| OktaAuthError::RefreshFailed(e.to_string()))?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let expires_at = token_response
            .expires_in()
            .map(|d| now + d.as_secs())
            .unwrap_or(now + 3600);

        let new_refresh = token_response
            .refresh_token()
            .map(|t| t.secret().to_string())
            .or_else(|| Some(refresh_token.to_string()));

        Ok(TokenCache {
            access_token: token_response.access_token().secret().to_string(),
            refresh_token: new_refresh,
            expires_at,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Spawn a one-shot local HTTP server (reusing the in-house `tiny_http` dep) that
    /// answers a single request with `body` and 200/JSON, then returns the base issuer
    /// URL pointing at it. Used to exercise the silent-refresh path without live Okta:
    /// `refresh()` POSTs to `{issuer}/v1/token`, which this server answers.
    fn spawn_token_server(body: &'static str) -> (String, std::thread::JoinHandle<()>) {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let handle = std::thread::spawn(move || {
            if let Ok(req) = server.recv() {
                let header = "Content-Type: application/json".parse::<tiny_http::Header>().unwrap();
                let resp = tiny_http::Response::from_string(body).with_header(header);
                let _ = req.respond(resp);
            }
        });
        (format!("http://127.0.0.1:{port}"), handle)
    }

    fn test_config(tmp: &tempfile::TempDir) -> OktaAuthConfig {
        OktaAuthConfig {
            okta_issuer: "https://test.okta.com/oauth2/default".to_string(),
            client_id: "test-client-id".to_string(),
            redirect_uri: "http://localhost:11313/callback".to_string(),
            scopes: vec!["openid".to_string(), "email".to_string()],
            app_name: "test-app".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        }
    }

    #[test]
    fn new_creates_instance_with_config() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(&tmp);
        let auth = OktaAuth::new(config.clone());
        assert_eq!(auth.config().okta_issuer, "https://test.okta.com/oauth2/default");
        assert_eq!(auth.config().client_id, "test-client-id");
        assert_eq!(auth.config().app_name, "test-app");
    }

    #[test]
    fn cache_dir_uses_override_when_set() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(&tmp);
        let auth = OktaAuth::new(config);
        assert_eq!(auth.cache_dir(), tmp.path());
    }

    #[test]
    fn cache_dir_falls_back_to_default_when_none() {
        let auth = OktaAuth::new(OktaAuthConfig {
            okta_issuer: "https://test.okta.com/oauth2/default".to_string(),
            client_id: "test-client-id".to_string(),
            redirect_uri: "http://localhost:11313/callback".to_string(),
            scopes: vec![],
            app_name: "my-cool-app".to_string(),
            cache_dir: None,
        });
        // The default cache dir is the shared `~/.cache/okta`, NOT keyed by app_name:
        // it must equal the bare default and contain no trace of the app name.
        let dir = auth.cache_dir();
        assert_eq!(dir, cache::default_cache_dir());
        assert!(!dir.to_string_lossy().contains("my-cool-app"));
    }

    #[test]
    fn get_token_returns_cached_token_when_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(&tmp);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let cached = TokenCache {
            access_token: "cached-access-token".to_string(),
            refresh_token: Some("refresh".to_string()),
            expires_at: now + 3600,
        };
        cache::save(tmp.path(), &cached).unwrap();

        let auth = OktaAuth::new(config);
        let token = auth.get_token().unwrap();
        assert_eq!(token, "cached-access-token");
    }

    #[test]
    fn cached_valid_token_returns_token_when_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(&tmp);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "valid".to_string(),
                refresh_token: None,
                expires_at: now + 3600,
            },
        )
        .unwrap();
        let auth = OktaAuth::new(config);
        assert_eq!(auth.cached_valid_token().unwrap().unwrap().access_token, "valid");
    }

    #[test]
    fn cached_valid_token_is_none_when_expired() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(&tmp);
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old".to_string(),
                refresh_token: None,
                expires_at: 0,
            },
        )
        .unwrap();
        let auth = OktaAuth::new(config);
        assert!(auth.cached_valid_token().unwrap().is_none());
    }

    #[test]
    fn cached_valid_token_is_none_when_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let auth = OktaAuth::new(test_config(&tmp));
        assert!(auth.cached_valid_token().unwrap().is_none());
    }

    #[test]
    fn cache_path_is_tokens_json_under_cache_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let auth = OktaAuth::new(test_config(&tmp));
        assert_eq!(auth.cache_path(), tmp.path().join("tokens.json"));
    }

    #[test]
    fn login_or_reuse_is_noop_when_valid_token_cached() {
        let tmp = tempfile::tempdir().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "valid".to_string(),
                refresh_token: None,
                expires_at: now + 3600,
            },
        )
        .unwrap();
        let auth = OktaAuth::new(test_config(&tmp));
        // force=false + valid cache => no flow runs (no network), reports already-in.
        let outcome = auth.login_or_reuse(false, true).unwrap();
        assert!(matches!(outcome, LoginOutcome::AlreadyLoggedIn { .. }));
        let msg = outcome.message();
        assert!(msg.contains("Already logged in"), "got: {msg}");
        assert!(msg.contains("tokens.json"), "message must show the real path: {msg}");
        assert!(msg.contains("--force"));
    }

    #[test]
    fn login_outcome_logged_in_message_reports_real_path() {
        let outcome = LoginOutcome::LoggedIn {
            cache_path: std::path::PathBuf::from("/home/u/.cache/okta/tokens.json"),
        };
        let msg = outcome.message();
        assert!(msg.contains("Logged in. Token cached at /home/u/.cache/okta/tokens.json."));
    }

    #[test]
    fn logout_clears_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(&tmp);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();

        let cached = TokenCache {
            access_token: "token".to_string(),
            refresh_token: None,
            expires_at: now + 3600,
        };
        cache::save(tmp.path(), &cached).unwrap();
        assert!(tmp.path().join("tokens.json").exists());

        let auth = OktaAuth::new(config);
        auth.logout().unwrap();
        assert!(!tmp.path().join("tokens.json").exists());
    }

    #[test]
    fn logout_is_noop_when_no_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let config = test_config(&tmp);
        let auth = OktaAuth::new(config);
        auth.logout().unwrap();
    }

    #[test]
    fn get_token_falls_through_to_browser_when_expired_and_no_refresh() {
        let tmp = tempfile::tempdir().unwrap();

        // Seed an expired token with no refresh token
        let expired = TokenCache {
            access_token: "old-expired".to_string(),
            refresh_token: None,
            expires_at: 0,
        };
        cache::save(tmp.path(), &expired).unwrap();

        let config = OktaAuthConfig {
            okta_issuer: "not-a-real-url".to_string(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };

        let auth = OktaAuth::new(config);
        // Config-error precedence: a garbage issuer must surface as InvalidUrl, not be
        // masked as NonInteractive by the interactivity check (which runs after URL build).
        let result = auth.get_token();
        assert!(matches!(result, Err(OktaAuthError::InvalidUrl(_))));
    }

    #[test]
    fn get_token_noninteractive_returns_cached_when_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "cached-valid".to_string(),
                refresh_token: Some("refresh".to_string()),
                expires_at: now + 3600,
            },
        )
        .unwrap();
        let auth = OktaAuth::new(test_config(&tmp));
        // Valid cache: returned as-is, no refresh, no browser.
        assert_eq!(auth.get_token_noninteractive().unwrap(), "cached-valid");
    }

    #[test]
    fn get_token_noninteractive_refreshes_expired_token() {
        let tmp = tempfile::tempdir().unwrap();
        let (issuer, handle) = spawn_token_server(
            r#"{"access_token":"refreshed-access","token_type":"bearer","expires_in":3600,"refresh_token":"rotated-refresh"}"#,
        );

        // Expired access token WITH a refresh token -> silent refresh via the mock.
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: Some("stale-refresh".to_string()),
                expires_at: 0,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: issuer,
            client_id: "fake-client".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let auth = OktaAuth::new(config);

        let token = auth.get_token_noninteractive().unwrap();
        assert_eq!(token, "refreshed-access");

        // The refreshed token (and rotated refresh token) is persisted to the cache.
        let reloaded = cache::load(tmp.path()).unwrap().unwrap();
        assert_eq!(reloaded.access_token, "refreshed-access");
        assert_eq!(reloaded.refresh_token.as_deref(), Some("rotated-refresh"));

        handle.join().unwrap();
    }

    #[test]
    fn get_token_noninteractive_returns_noninteractive_when_expired_no_refresh() {
        let tmp = tempfile::tempdir().unwrap();
        // Expired access token, NO refresh token: must fail closed with NonInteractive.
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: None,
                expires_at: 0,
            },
        )
        .unwrap();
        let auth = OktaAuth::new(test_config(&tmp));
        let result = auth.get_token_noninteractive();
        // Asserting the SPECIFIC variant is what makes this test bite: if the code
        // fell through to a browser login (like get_token), the test_config's fake
        // issuer would surface InvalidUrl/other, not NonInteractive - and this fails.
        assert!(
            matches!(result, Err(OktaAuthError::NonInteractive)),
            "expected NonInteractive, got {result:?}"
        );
    }

    #[test]
    fn get_token_noninteractive_returns_noninteractive_when_no_cache() {
        let tmp = tempfile::tempdir().unwrap();
        // No cached token at all: fail closed, never a browser.
        let auth = OktaAuth::new(test_config(&tmp));
        let result = auth.get_token_noninteractive();
        assert!(
            matches!(result, Err(OktaAuthError::NonInteractive)),
            "expected NonInteractive, got {result:?}"
        );
    }

    #[test]
    fn get_token_noninteractive_returns_noninteractive_when_refresh_fails() {
        let tmp = tempfile::tempdir().unwrap();
        // Expired + refresh token present, but the token endpoint is unreachable
        // (connection refused on port 1). Refresh fails -> warn -> NonInteractive,
        // NOT a browser fallthrough.
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: Some("stale-refresh".to_string()),
                expires_at: 0,
            },
        )
        .unwrap();
        let config = OktaAuthConfig {
            okta_issuer: "http://127.0.0.1:1/oauth2/default".to_string(),
            client_id: "fake-client".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let auth = OktaAuth::new(config);
        let result = auth.get_token_noninteractive();
        assert!(
            matches!(result, Err(OktaAuthError::NonInteractive)),
            "expected NonInteractive, got {result:?}"
        );
    }

    #[test]
    fn get_token_with_expired_token_attempts_refresh_then_falls_through() {
        let tmp = tempfile::tempdir().unwrap();

        // Seed an expired token WITH a refresh token
        let expired = TokenCache {
            access_token: "old-expired".to_string(),
            refresh_token: Some("stale-refresh".to_string()),
            expires_at: 0,
        };
        cache::save(tmp.path(), &expired).unwrap();

        let config = OktaAuthConfig {
            okta_issuer: "https://not-real.example.com/oauth2/default".to_string(),
            client_id: "fake".to_string(),
            // Invalid issuer means refresh will fail, then browser flow will also fail
            redirect_uri: "not-a-url".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };

        let auth = OktaAuth::new(config);
        // Refresh fails (unreachable issuer) and falls through to authorize(), where the
        // invalid redirect_uri surfaces as InvalidUrl - config error beats NonInteractive.
        let result = auth.get_token();
        assert!(matches!(result, Err(OktaAuthError::InvalidUrl(_))));
    }
}
