#![deny(clippy::unwrap_used)]
#![deny(dead_code)]
#![deny(unused_variables)]

mod cache;
mod error;
mod pkce;
pub mod tatari;

use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use log::{debug, info, warn};
use oauth2::basic::{BasicClient, BasicErrorResponseType};
use oauth2::{ClientId, RefreshToken, RequestTokenError, TokenResponse, TokenUrl};

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
///
/// `#[non_exhaustive]`: adding `Refreshed` is source-breaking for any downstream
/// exhaustive match in general. No consumer currently matches exhaustively (all call
/// only `.message()`), and every consumer is tag-pinned, but the attribute forces a
/// wildcard arm from here on so the next variant is not this conversation again.
#[derive(Debug)]
#[non_exhaustive]
pub enum LoginOutcome {
    /// A valid token was already cached; no flow ran. `since` is when it was cached
    /// (the cache file's mtime), if readable.
    AlreadyLoggedIn {
        cache_path: PathBuf,
        since: Option<SystemTime>,
    },
    /// Access token was expired; a silent refresh produced a new one. No flow ran.
    Refreshed { cache_path: PathBuf },
    /// A login flow ran and cached a fresh token.
    // `#[non_exhaustive]` on the variant too: the enum attribute covers added
    // variants, not added fields, and `revoke_warning` is a new field on an existing
    // variant.
    #[non_exhaustive]
    LoggedIn {
        cache_path: PathBuf,
        /// `Some` when the previous refresh token (if any) could not be revoked
        /// during this login. Never fails the login itself - see `fresh_grant`.
        revoke_warning: Option<String>,
    },
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
            Self::Refreshed { cache_path } => {
                format!("Refreshed Okta token (cached at {}).", cache_path.display())
            }
            Self::LoggedIn {
                cache_path,
                revoke_warning,
            } => {
                let mut msg = format!("Logged in. Token cached at {}.", cache_path.display());
                if let Some(warning) = revoke_warning {
                    msg.push_str(&format!(
                        " Warning: the previous refresh token could not be revoked ({warning}); \
                         it expires on its own after 7 idle days."
                    ));
                }
                msg
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

/// Runs the interactive login flows. Injected so tests can assert "flow invoked / not
/// invoked" and control the returned grant without touching Okta. Production is
/// [`PkceFlow`], wrapping [`pkce::authorize`] / [`pkce::authorize_device`].
trait LoginFlow {
    fn interactive(&self, cfg: &OktaAuthConfig) -> Result<TokenCache, OktaAuthError>;
    fn device(&self, cfg: &OktaAuthConfig) -> Result<TokenCache, OktaAuthError>;
}

/// Production [`LoginFlow`]: the real browser-redirect / device-grant flows against Okta.
struct PkceFlow;

impl LoginFlow for PkceFlow {
    fn interactive(&self, cfg: &OktaAuthConfig) -> Result<TokenCache, OktaAuthError> {
        pkce::authorize(&cfg.okta_issuer, &cfg.client_id, &cfg.redirect_uri, &cfg.scopes)
    }

    fn device(&self, cfg: &OktaAuthConfig) -> Result<TokenCache, OktaAuthError> {
        pkce::authorize_device(&cfg.okta_issuer, &cfg.client_id, &cfg.scopes)
    }
}

/// Okta OAuth2 PKCE authenticator for CLI tools.
///
/// Handles the full token lifecycle: cache lookup, transparent refresh, and browser-based login.
pub struct OktaAuth {
    config: OktaAuthConfig,
    flow: Box<dyn LoginFlow + Send + Sync>,
}

impl OktaAuth {
    pub fn new(config: OktaAuthConfig) -> Self {
        Self {
            config,
            flow: Box::new(PkceFlow),
        }
    }

    /// Test-only constructor: swap in a fake [`LoginFlow`] so tests can assert flow
    /// invocation and control the returned grant without touching Okta.
    #[cfg(test)]
    fn with_flow(config: OktaAuthConfig, flow: Box<dyn LoginFlow + Send + Sync>) -> Self {
        Self { config, flow }
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
        if !force {
            if self.cached_valid_token()?.is_some() {
                let since = std::fs::metadata(&cache_path).and_then(|m| m.modified()).ok();
                return Ok(LoginOutcome::AlreadyLoggedIn { cache_path, since });
            }
            // Access token expired (or no cache at all): a live refresh token means
            // `<tool> login` can stay silent instead of opening a browser for nothing.
            if let Some(new_cache) = self.try_silent_refresh()? {
                cache::save(&self.cache_dir(), &new_cache)?;
                return Ok(LoginOutcome::Refreshed { cache_path });
            }
        }
        let (_, revoke_warning) = if device {
            self.fresh_grant(|| self.flow.device(&self.config))?
        } else {
            self.fresh_grant(|| self.flow.interactive(&self.config))?
        };
        Ok(LoginOutcome::LoggedIn {
            cache_path,
            revoke_warning,
        })
    }

    /// The cached refresh token, refreshed, if the cache holds one - `Ok(None)` when
    /// there is no refresh token or the refresh itself fails (e.g. `invalid_grant`,
    /// which `refresh()` already turns into a cleared cache). Shared by
    /// `login_or_reuse`'s silent-refresh arm. `CacheWrite` is the one error that does
    /// NOT collapse to `Ok(None)`: it means the dead-token clear failed on the
    /// filesystem, so the browser login this would otherwise fall through to would
    /// just fail at `cache::save` anyway - the same reasoning `get_token` applies.
    fn try_silent_refresh(&self) -> Result<Option<TokenCache>, OktaAuthError> {
        let dir = self.cache_dir();
        let Some(refresh_token) = cache::load(&dir)?.and_then(|c| c.refresh_token) else {
            return Ok(None);
        };
        match self.refresh(&refresh_token) {
            Ok(new_cache) => Ok(Some(new_cache)),
            Err(OktaAuthError::CacheWrite(msg)) => {
                warn!("try_silent_refresh: refresh failed to clear a dead cache entry ({msg}); propagating CacheWrite");
                Err(OktaAuthError::CacheWrite(msg))
            }
            Err(e) => {
                warn!("try_silent_refresh: silent refresh failed: {e}");
                Ok(None)
            }
        }
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
                    Err(OktaAuthError::CacheWrite(msg)) => {
                        // The dead-token clear itself failed: the filesystem is the
                        // fault, not Okta, and a browser login would just fail to save
                        // too. Propagate rather than opening a browser for nothing.
                        warn!("get_token: refresh failed to clear a dead cache entry ({msg}); propagating CacheWrite");
                        return Err(OktaAuthError::CacheWrite(msg));
                    }
                    Err(e) => {
                        warn!("token refresh failed: {}, falling through to browser login", e);
                    }
                }
            }
        }

        info!("no valid cached token, starting browser login");
        let (new_cache, revoke_warning) = self.fresh_grant(|| self.flow.interactive(&self.config))?;
        if let Some(warning) = revoke_warning {
            warn!("get_token: {warning}");
        }
        Ok(new_cache.access_token)
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
                    Err(OktaAuthError::CacheWrite(msg)) => {
                        // The dead-token clear itself failed: the filesystem is the
                        // fault, and the dead token is still on disk. That is a
                        // different failure than "no controlling terminal", so it must
                        // not collapse to NonInteractive.
                        warn!(
                            "get_token_noninteractive: refresh failed to clear a dead cache entry ({msg}); propagating CacheWrite"
                        );
                        return Err(OktaAuthError::CacheWrite(msg));
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
        let (_, revoke_warning) = self.fresh_grant(|| self.flow.interactive(&self.config))?;
        if let Some(warning) = revoke_warning {
            warn!("login: {warning}");
        }
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
        let (_, revoke_warning) = self.fresh_grant(|| self.flow.device(&self.config))?;
        if let Some(warning) = revoke_warning {
            warn!("login_device: {warning}");
        }
        Ok(())
    }

    /// Revoke the cached refresh token at Okta (RFC 7009), then delete the cache. The
    /// cache is cleared even when revocation fails - a `logout` that leaves a token
    /// nobody references locally would be worse than one Okta still considers live.
    /// Error precedence: a failed clear returns `CacheWrite` (a revoked token would
    /// still be on disk, and `is_valid()` would hand it out); otherwise a failed
    /// revoke returns `RevokeFailed` (the server-side token may still be live).
    pub fn logout(&self) -> Result<(), OktaAuthError> {
        let dir = self.cache_dir();
        // Best-effort, NOT `?`: a cache we cannot read holds no refresh token we could
        // revoke, and propagating here would return before `clear` and leave a corrupt
        // cache file undeletable by the very command whose job is to delete it. Named
        // variants, not a catch-all: only an unreadable/unparseable file is "no token".
        let refresh_token = match cache::load(&dir) {
            Ok(cached) => cached.and_then(|c| c.refresh_token),
            Err(e @ (OktaAuthError::CacheRead(_) | OktaAuthError::CacheParse(_))) => {
                warn!(
                    "logout: could not read the token cache at {} ({e}); clearing it anyway",
                    cache::cache_path(&dir).display()
                );
                None
            }
            Err(e) => return Err(e),
        };
        let revoke_result = refresh_token.map(|token| self.revoke(&token));
        cache::clear(&dir)?;
        match revoke_result {
            Some(Err(e)) => Err(e),
            _ => Ok(()),
        }
    }

    /// The only writer of a fresh interactive grant - called by `login`, `login_device`,
    /// and `get_token`'s interactive fallthrough. Order: guard the shared-cache
    /// invariant -> read the previous refresh token into memory (best-effort: an
    /// unreadable cache warns and yields `None` rather than blocking the re-login that
    /// would overwrite it) -> run `flow` -> save
    /// the new grant -> best-effort revoke the previous token. The old token is read
    /// once, before `flow` runs, and never re-read from disk after the save, so this
    /// call can never revoke the grant it just wrote (e.g. a concurrent `login --force`
    /// elsewhere), and the revoke is skipped outright when the two tokens are equal. A
    /// revoke failure is never an `Err`: it comes back as `Some(text)` in the tuple
    /// (and is `warn!`-logged) for the caller to surface to the user.
    fn fresh_grant(
        &self,
        flow: impl FnOnce() -> Result<TokenCache, OktaAuthError>,
    ) -> Result<(TokenCache, Option<String>), OktaAuthError> {
        if self.config.cache_dir.is_none() && !self.config.scopes.iter().any(|s| s == "offline_access") {
            return Err(OktaAuthError::SharedCacheRequiresOfflineAccess);
        }
        let dir = self.cache_dir();
        // Best-effort, NOT `?`: the previous token is only wanted so it can be revoked
        // after the new grant lands. Propagating here would return before `flow` and
        // `save`, so a corrupt cache file would block the one path that overwrites it.
        // Named variants, not a catch-all: only an unreadable/unparseable file is
        // "no previous token".
        let old_refresh_token = match cache::load(&dir) {
            Ok(cached) => cached.and_then(|c| c.refresh_token),
            Err(e @ (OktaAuthError::CacheRead(_) | OktaAuthError::CacheParse(_))) => {
                warn!(
                    "fresh_grant: could not read the previous token cache at {} ({e}); proceeding with no token to revoke",
                    cache::cache_path(&dir).display()
                );
                None
            }
            Err(e) => return Err(e),
        };

        let new_cache = flow()?;
        cache::save(&dir, &new_cache)?;

        let revoke_warning = match old_refresh_token {
            // This tenant runs "Use persistent token": `/v1/token` echoes the SAME
            // refresh token back on the refresh path (Phase 0 measured it byte-for-byte).
            // Whether a second *interactive* authorization for the same user+client also
            // re-issues that same token is untested. If it does, revoking `old` here
            // would kill the grant the `cache::save` above just wrote - and the access
            // token with it, since Phase 0 also proved a revoke takes both. Comparing
            // first costs nothing and is correct whichever way the tenant behaves.
            Some(ref token) if Some(token) == new_cache.refresh_token.as_ref() => {
                debug!("fresh_grant: re-authorization returned the same refresh token; skipping revoke");
                None
            }
            Some(token) => self.revoke(&token).err().map(|e| {
                warn!("fresh_grant: could not revoke the previous refresh token: {e}");
                e.to_string()
            }),
            None => None,
        };
        Ok((new_cache, revoke_warning))
    }

    /// Revoke a refresh token at Okta (RFC 7009 `/v1/revoke`) as a public client: no
    /// client secret, `client_id` in the form body. A raw form POST, the same pattern
    /// `pkce::device` already uses against this issuer, rather than threading the
    /// `oauth2` crate's `RevocationUrl` typestate through `BasicClient` for one call
    /// site. Any 2xx is success; Okta returns 200 even for an already-dead token
    /// (RFC 7009: revoking an invalid/expired/revoked token is still success).
    fn revoke(&self, refresh_token: &str) -> Result<(), OktaAuthError> {
        let revoke_url = format!("{}/v1/revoke", self.config.okta_issuer);
        let http = oauth2::reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| OktaAuthError::RevokeFailed(e.to_string()))?;

        let response = http
            .post(&revoke_url)
            .form(&[
                ("client_id", self.config.client_id.as_str()),
                ("token", refresh_token),
                ("token_type_hint", "refresh_token"),
            ])
            .send()
            .map_err(|e| OktaAuthError::RevokeFailed(e.to_string()))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(OktaAuthError::RevokeFailed(format!("HTTP {}", response.status())))
        }
    }

    fn refresh(&self, refresh_token: &str) -> Result<TokenCache, OktaAuthError> {
        let token_url = TokenUrl::new(format!("{}/v1/token", self.config.okta_issuer))
            .map_err(|e| OktaAuthError::InvalidUrl(e.to_string()))?;

        let client = BasicClient::new(ClientId::new(self.config.client_id.to_string())).set_token_uri(token_url);

        let result = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.to_string()))
            .request(&oauth2::reqwest::blocking::Client::new());

        // Inspect the typed error BEFORE the map_err below flattens it to a string:
        // only `invalid_grant` means the refresh token itself is dead (7 idle days,
        // revoked, deactivated). Every other error - network, unparseable body, other
        // ServerResponse codes such as `invalid_client` (config/app broken, not the
        // token) - keeps the cache so a transient blip never forces a re-login. If the
        // clear itself fails, that CacheWrite takes precedence over RefreshFailed: the
        // filesystem is the fault, and the dead token is still on disk.
        if let Err(RequestTokenError::ServerResponse(ref resp)) = result
            && resp.error() == &BasicErrorResponseType::InvalidGrant
        {
            debug!("refresh: invalid_grant; dropping the dead refresh token from the cache");
            cache::clear(&self.cache_dir())?;
        }

        let token_response = result.map_err(|e| OktaAuthError::RefreshFailed(e.to_string()))?;

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
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    /// One scripted HTTP response: status code + body.
    type ScriptedResponse = (u16, &'static str);

    /// A single request [`MockOkta`] served, recorded for tests to assert against.
    struct RecordedRequest {
        path: String,
        form: HashMap<String, String>,
        /// The cache file's `access_token` at the instant this request landed. Only
        /// meaningful for `/v1/revoke` requests: it is what makes
        /// `login_saves_new_grant_before_revoking_old` an assertion rather than a hope.
        cache_access_token_at_request: Option<String>,
    }

    /// An ordered-script stand-in for Okta's token/revoke endpoints, replacing the old
    /// one-shot server. Serves each `(status, body)` in `responses` to one incoming
    /// request in turn, then stops; records every request's path and form body.
    struct MockOkta {
        base_url: String,
        expected: usize,
        handle: std::thread::JoinHandle<Vec<RecordedRequest>>,
    }

    /// How long [`MockOkta`] waits for each scripted request before giving up. Every
    /// request is local and immediate, so this only ever elapses when the code under
    /// test made fewer requests than the script holds - which must fail the test, not
    /// hang it. A blocking `recv()` here made mutation testing impractical: neutralize
    /// a revoke and the suite hung indefinitely instead of reporting the missing call.
    const MOCK_RECV_TIMEOUT: Duration = Duration::from_secs(5);

    impl MockOkta {
        /// Start serving `responses` in order against a fresh local port. `cache_dir`
        /// is snapshotted (via [`cache::load`]) at the moment each `/v1/revoke` request
        /// lands, so tests can prove save-before-revoke ordering.
        fn start(responses: Vec<ScriptedResponse>, cache_dir: PathBuf) -> Self {
            let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
            let port = server.server_addr().to_ip().unwrap().port();
            let expected = responses.len();
            let handle = std::thread::spawn(move || {
                let mut recorded = Vec::new();
                for (status, body) in responses {
                    let Ok(Some(mut req)) = server.recv_timeout(MOCK_RECV_TIMEOUT) else {
                        break;
                    };
                    let path = req.url().to_string();
                    let mut raw = String::new();
                    let _ = req.as_reader().read_to_string(&mut raw);
                    let form: HashMap<String, String> = oauth2::url::form_urlencoded::parse(raw.as_bytes())
                        .into_owned()
                        .collect();
                    let cache_access_token_at_request = if path.contains("/v1/revoke") {
                        cache::load(&cache_dir).ok().flatten().map(|c| c.access_token)
                    } else {
                        None
                    };
                    recorded.push(RecordedRequest {
                        path,
                        form,
                        cache_access_token_at_request,
                    });
                    let header = "Content-Type: application/json".parse::<tiny_http::Header>().unwrap();
                    let resp = tiny_http::Response::from_string(body)
                        .with_status_code(status)
                        .with_header(header);
                    let _ = req.respond(resp);
                }
                recorded
            });
            Self {
                base_url: format!("http://127.0.0.1:{port}"),
                expected,
                handle,
            }
        }

        /// Block until the script is exhausted and return everything recorded, in
        /// order. Panics when the caller made fewer requests than the script holds:
        /// the whole point of scripting a request is that it has to happen.
        fn finish(self) -> Vec<RecordedRequest> {
            let expected = self.expected;
            let recorded = self.handle.join().unwrap();
            assert_eq!(
                recorded.len(),
                expected,
                "MockOkta::finish: script held {expected} request(s), received {} within {MOCK_RECV_TIMEOUT:?}",
                recorded.len()
            );
            recorded
        }
    }

    /// A [`LoginFlow`] fake that returns a canned grant and counts invocations, so
    /// tests can assert "flow invoked / not invoked" without touching Okta.
    struct CountingFlow {
        interactive_calls: Arc<AtomicUsize>,
        device_calls: Arc<AtomicUsize>,
        result: TokenCache,
    }

    impl LoginFlow for CountingFlow {
        fn interactive(&self, _: &OktaAuthConfig) -> Result<TokenCache, OktaAuthError> {
            self.interactive_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.result.clone())
        }

        fn device(&self, _: &OktaAuthConfig) -> Result<TokenCache, OktaAuthError> {
            self.device_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.result.clone())
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    /// Set `XDG_CACHE_HOME` for `body`, restoring the prior value after. Env mutation
    /// is process-global and unsafe under Edition 2024, so every caller is
    /// `#[serial_test::serial]` - the same lock `cache.rs`'s own env tests use, since
    /// both mutate the same process-wide variable.
    fn with_xdg_cache_home(dir: &std::path::Path, body: impl FnOnce()) {
        let prior = std::env::var_os("XDG_CACHE_HOME");
        unsafe { std::env::set_var("XDG_CACHE_HOME", dir) };
        body();
        match prior {
            Some(v) => unsafe { std::env::set_var("XDG_CACHE_HOME", v) },
            None => unsafe { std::env::remove_var("XDG_CACHE_HOME") },
        }
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
            revoke_warning: None,
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

    /// Regression: the refresh-token read added to `logout` must not be able to block
    /// the `clear` that follows it. A corrupt cache file is exactly the case where the
    /// user needs `logout` to work, so propagating the parse error would leave manual
    /// `rm` as the only recovery.
    #[test]
    fn logout_clears_cache_when_cache_file_is_unreadable() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("tokens.json"), "{ not json").unwrap();

        let config = OktaAuthConfig {
            // Unreachable: an attempted revoke would surface as RevokeFailed. Ok(()) is
            // the proof that the unreadable cache yielded no token to revoke.
            okta_issuer: "http://127.0.0.1:1".to_string(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let auth = OktaAuth::new(config);
        auth.logout().unwrap();
        assert!(!tmp.path().join("tokens.json").exists());
    }

    /// Regression: the previous-token read added to `fresh_grant` must not be able to
    /// block `flow` and `save`. A corrupt cache file would otherwise brick `login`,
    /// `login_device`, and the forced path - every route that overwrites it.
    #[test]
    fn fresh_grant_proceeds_when_cache_file_is_unreadable() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("tokens.json"), "{ not json").unwrap();

        let interactive_calls = Arc::new(AtomicUsize::new(0));
        let device_calls = Arc::new(AtomicUsize::new(0));
        let flow = CountingFlow {
            interactive_calls: Arc::clone(&interactive_calls),
            device_calls: Arc::clone(&device_calls),
            result: TokenCache {
                access_token: "flow-access".to_string(),
                refresh_token: Some("flow-refresh".to_string()),
                expires_at: now_secs() + 3600,
            },
        };
        let auth = OktaAuth::with_flow(test_config(&tmp), Box::new(flow));

        auth.login().unwrap();
        assert_eq!(interactive_calls.load(Ordering::SeqCst), 1);
        let saved = cache::load(tmp.path()).unwrap().expect("cache overwritten");
        assert_eq!(saved.access_token, "flow-access");
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
        let mock = MockOkta::start(
            vec![(
                200,
                r#"{"access_token":"refreshed-access","token_type":"bearer","expires_in":3600,"refresh_token":"rotated-refresh"}"#,
            )],
            tmp.path().to_path_buf(),
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
            okta_issuer: mock.base_url.clone(),
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

        mock.finish();
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

    // -- logout: revoke-then-clear --

    #[test]
    fn logout_revokes_refresh_token_then_clears_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = MockOkta::start(vec![(200, "")], tmp.path().to_path_buf());
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "access".to_string(),
                refresh_token: Some("refresh-to-revoke".to_string()),
                expires_at: now_secs() + 3600,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake-client".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let auth = OktaAuth::new(config);
        auth.logout().unwrap();

        assert!(!tmp.path().join("tokens.json").exists());
        let recorded = mock.finish();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].path.contains("/v1/revoke"), "got path {}", recorded[0].path);
        assert_eq!(
            recorded[0].form.get("client_id").map(String::as_str),
            Some("fake-client")
        );
        assert_eq!(
            recorded[0].form.get("token").map(String::as_str),
            Some("refresh-to-revoke")
        );
        assert_eq!(
            recorded[0].form.get("token_type_hint").map(String::as_str),
            Some("refresh_token")
        );
    }

    #[test]
    fn logout_clears_cache_and_returns_revoke_failed_when_endpoint_unreachable() {
        let tmp = tempfile::tempdir().unwrap();
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "access".to_string(),
                refresh_token: Some("refresh".to_string()),
                expires_at: now_secs() + 3600,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: "http://127.0.0.1:1".to_string(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let auth = OktaAuth::new(config);
        let result = auth.logout();
        assert!(matches!(result, Err(OktaAuthError::RevokeFailed(_))), "got {result:?}");
        // Cleared even though the revoke failed.
        assert!(!tmp.path().join("tokens.json").exists());
    }

    #[test]
    fn logout_makes_no_revoke_call_without_refresh_token() {
        let tmp = tempfile::tempdir().unwrap();
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "access".to_string(),
                refresh_token: None,
                expires_at: now_secs() + 3600,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            // Unreachable: if logout attempted a revoke call, it would surface as
            // RevokeFailed. Ok(()) is the proof that no call was made.
            okta_issuer: "http://127.0.0.1:1".to_string(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let auth = OktaAuth::new(config);
        auth.logout().unwrap();
        assert!(!tmp.path().join("tokens.json").exists());
    }

    #[test]
    fn logout_treats_200_with_error_body_as_success() {
        let tmp = tempfile::tempdir().unwrap();
        // Okta returns 200 even for a bogus/already-revoked token (RFC 7009).
        let mock = MockOkta::start(vec![(200, r#"{"error":"invalid_token"}"#)], tmp.path().to_path_buf());
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "access".to_string(),
                refresh_token: Some("bogus".to_string()),
                expires_at: now_secs() + 3600,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let auth = OktaAuth::new(config);
        auth.logout().unwrap();
        mock.finish();
    }

    // -- login_or_reuse: silent refresh before prompting --

    #[test]
    fn login_or_reuse_refreshes_instead_of_prompting() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = MockOkta::start(
            vec![(
                200,
                r#"{"access_token":"new-access","token_type":"bearer","expires_in":3600,"refresh_token":"refresh"}"#,
            )],
            tmp.path().to_path_buf(),
        );
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: Some("refresh".to_string()),
                expires_at: 0,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let interactive_calls = Arc::new(AtomicUsize::new(0));
        let device_calls = Arc::new(AtomicUsize::new(0));
        let flow = CountingFlow {
            interactive_calls: Arc::clone(&interactive_calls),
            device_calls: Arc::clone(&device_calls),
            result: TokenCache {
                access_token: "flow-access".to_string(),
                refresh_token: Some("flow-refresh".to_string()),
                expires_at: now_secs() + 3600,
            },
        };
        let auth = OktaAuth::with_flow(config, Box::new(flow));

        let outcome = auth.login_or_reuse(false, true).unwrap();
        assert!(matches!(outcome, LoginOutcome::Refreshed { .. }), "got {outcome:?}");
        assert_eq!(interactive_calls.load(Ordering::SeqCst), 0);
        assert_eq!(device_calls.load(Ordering::SeqCst), 0);
        mock.finish();
    }

    #[test]
    fn login_or_reuse_runs_flow_when_expired_without_refresh_token() {
        let tmp = tempfile::tempdir().unwrap();
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: None,
                expires_at: 0,
            },
        )
        .unwrap();

        let interactive_calls = Arc::new(AtomicUsize::new(0));
        let device_calls = Arc::new(AtomicUsize::new(0));
        let flow = CountingFlow {
            interactive_calls: Arc::clone(&interactive_calls),
            device_calls: Arc::clone(&device_calls),
            result: TokenCache {
                access_token: "flow-access".to_string(),
                refresh_token: Some("flow-refresh".to_string()),
                expires_at: now_secs() + 3600,
            },
        };
        let auth = OktaAuth::with_flow(test_config(&tmp), Box::new(flow));

        let outcome = auth.login_or_reuse(false, false).unwrap();
        assert!(matches!(outcome, LoginOutcome::LoggedIn { .. }), "got {outcome:?}");
        assert_eq!(interactive_calls.load(Ordering::SeqCst), 1);
        assert_eq!(device_calls.load(Ordering::SeqCst), 0);
    }

    // -- refresh: dead-token detection and cache preservation --

    #[test]
    fn refresh_keeps_sent_refresh_token_when_response_omits_it() {
        let tmp = tempfile::tempdir().unwrap();
        // No `refresh_token` field: exercises the fallback that keeps the sent token.
        let mock = MockOkta::start(
            vec![(
                200,
                r#"{"access_token":"new-access","token_type":"bearer","expires_in":3600}"#,
            )],
            tmp.path().to_path_buf(),
        );
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: Some("sent-refresh".to_string()),
                expires_at: 0,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let auth = OktaAuth::new(config);
        assert_eq!(auth.get_token_noninteractive().unwrap(), "new-access");
        let reloaded = cache::load(tmp.path()).unwrap().unwrap();
        assert_eq!(reloaded.refresh_token.as_deref(), Some("sent-refresh"));
        mock.finish();
    }

    #[test]
    fn refresh_clears_cache_on_invalid_grant() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = MockOkta::start(vec![(400, r#"{"error":"invalid_grant"}"#)], tmp.path().to_path_buf());
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: Some("dead-refresh".to_string()),
                expires_at: 0,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let auth = OktaAuth::new(config);
        let result = auth.get_token_noninteractive();
        assert!(matches!(result, Err(OktaAuthError::NonInteractive)), "got {result:?}");
        assert!(!tmp.path().join("tokens.json").exists());
        mock.finish();
    }

    #[test]
    fn refresh_keeps_cache_on_other_oauth_error() {
        let tmp = tempfile::tempdir().unwrap();
        // `invalid_client` is a ServerResponse, but not InvalidGrant: config/app is
        // broken, not the token, so the cache must survive.
        let mock = MockOkta::start(vec![(400, r#"{"error":"invalid_client"}"#)], tmp.path().to_path_buf());
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: Some("refresh".to_string()),
                expires_at: 0,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let auth = OktaAuth::new(config);
        let _ = auth.get_token_noninteractive();
        let reloaded = cache::load(tmp.path()).unwrap().unwrap();
        assert_eq!(reloaded.refresh_token.as_deref(), Some("refresh"));
        mock.finish();
    }

    #[test]
    fn refresh_keeps_cache_on_non_json_5xx() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = MockOkta::start(
            vec![(503, "<html><body>Service Unavailable</body></html>")],
            tmp.path().to_path_buf(),
        );
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: Some("refresh".to_string()),
                expires_at: 0,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let auth = OktaAuth::new(config);
        let _ = auth.get_token_noninteractive();
        let reloaded = cache::load(tmp.path()).unwrap().unwrap();
        assert_eq!(reloaded.refresh_token.as_deref(), Some("refresh"));
        mock.finish();
    }

    #[test]
    fn refresh_keeps_cache_on_unparseable_body() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = MockOkta::start(vec![(200, "not json at all")], tmp.path().to_path_buf());
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: Some("refresh".to_string()),
                expires_at: 0,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let auth = OktaAuth::new(config);
        let _ = auth.get_token_noninteractive();
        let reloaded = cache::load(tmp.path()).unwrap().unwrap();
        assert_eq!(reloaded.refresh_token.as_deref(), Some("refresh"));
        mock.finish();
    }

    #[test]
    fn refresh_keeps_cache_on_transport_error() {
        let tmp = tempfile::tempdir().unwrap();
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: Some("refresh".to_string()),
                expires_at: 0,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: "http://127.0.0.1:1".to_string(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let auth = OktaAuth::new(config);
        let _ = auth.get_token_noninteractive();
        let reloaded = cache::load(tmp.path()).unwrap().unwrap();
        assert_eq!(reloaded.refresh_token.as_deref(), Some("refresh"));
    }

    // -- fresh_grant: save-before-revoke ordering --

    #[test]
    fn login_saves_new_grant_before_revoking_old() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = MockOkta::start(vec![(200, "")], tmp.path().to_path_buf());
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-access".to_string(),
                refresh_token: Some("old-refresh".to_string()),
                expires_at: now_secs() + 3600,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let flow = CountingFlow {
            interactive_calls: Arc::new(AtomicUsize::new(0)),
            device_calls: Arc::new(AtomicUsize::new(0)),
            result: TokenCache {
                access_token: "new-access".to_string(),
                refresh_token: Some("new-refresh".to_string()),
                expires_at: now_secs() + 3600,
            },
        };
        let auth = OktaAuth::with_flow(config, Box::new(flow));
        auth.login().unwrap();

        let recorded = mock.finish();
        assert_eq!(recorded.len(), 1);
        assert!(recorded[0].path.contains("/v1/revoke"));
        // The revoked token is the OLD one...
        assert_eq!(recorded[0].form.get("token").map(String::as_str), Some("old-refresh"));
        // ...and by the time the revoke request lands, the cache already holds the NEW
        // access token: save happened before revoke.
        assert_eq!(recorded[0].cache_access_token_at_request.as_deref(), Some("new-access"));
    }

    // -- shared-cache write guard --

    #[test]
    #[serial_test::serial]
    fn login_with_shared_cache_requires_offline_access() {
        let tmp = tempfile::tempdir().unwrap();
        with_xdg_cache_home(tmp.path(), || {
            let config = OktaAuthConfig {
                // Any HTTP call here is a bug: the guard must fire before the flow runs.
                okta_issuer: "http://127.0.0.1:1".to_string(),
                client_id: "fake".to_string(),
                redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
                scopes: vec!["openid".to_string()],
                app_name: "test".to_string(),
                cache_dir: None,
            };
            let interactive_calls = Arc::new(AtomicUsize::new(0));
            let device_calls = Arc::new(AtomicUsize::new(0));
            let flow = CountingFlow {
                interactive_calls: Arc::clone(&interactive_calls),
                device_calls: Arc::clone(&device_calls),
                result: TokenCache {
                    access_token: "x".to_string(),
                    refresh_token: None,
                    expires_at: 0,
                },
            };
            let auth = OktaAuth::with_flow(config, Box::new(flow));
            let result = auth.login();
            assert!(
                matches!(result, Err(OktaAuthError::SharedCacheRequiresOfflineAccess)),
                "got {result:?}"
            );
            assert_eq!(interactive_calls.load(Ordering::SeqCst), 0);
            assert_eq!(device_calls.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    #[serial_test::serial]
    fn login_device_with_shared_cache_requires_offline_access() {
        let tmp = tempfile::tempdir().unwrap();
        with_xdg_cache_home(tmp.path(), || {
            let config = OktaAuthConfig {
                okta_issuer: "http://127.0.0.1:1".to_string(),
                client_id: "fake".to_string(),
                redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
                scopes: vec!["openid".to_string()],
                app_name: "test".to_string(),
                cache_dir: None,
            };
            let interactive_calls = Arc::new(AtomicUsize::new(0));
            let device_calls = Arc::new(AtomicUsize::new(0));
            let flow = CountingFlow {
                interactive_calls: Arc::clone(&interactive_calls),
                device_calls: Arc::clone(&device_calls),
                result: TokenCache {
                    access_token: "x".to_string(),
                    refresh_token: None,
                    expires_at: 0,
                },
            };
            let auth = OktaAuth::with_flow(config, Box::new(flow));
            let result = auth.login_device();
            assert!(
                matches!(result, Err(OktaAuthError::SharedCacheRequiresOfflineAccess)),
                "got {result:?}"
            );
            assert_eq!(interactive_calls.load(Ordering::SeqCst), 0);
            assert_eq!(device_calls.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    #[serial_test::serial]
    fn get_token_fallthrough_with_shared_cache_requires_offline_access() {
        let tmp = tempfile::tempdir().unwrap();
        with_xdg_cache_home(tmp.path(), || {
            let dir = cache::default_cache_dir();
            cache::save(
                &dir,
                &TokenCache {
                    access_token: "old-expired".to_string(),
                    refresh_token: None,
                    expires_at: 0,
                },
            )
            .unwrap();

            let config = OktaAuthConfig {
                okta_issuer: "http://127.0.0.1:1".to_string(),
                client_id: "fake".to_string(),
                redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
                scopes: vec!["openid".to_string()],
                app_name: "test".to_string(),
                cache_dir: None,
            };
            let interactive_calls = Arc::new(AtomicUsize::new(0));
            let device_calls = Arc::new(AtomicUsize::new(0));
            let flow = CountingFlow {
                interactive_calls: Arc::clone(&interactive_calls),
                device_calls: Arc::clone(&device_calls),
                result: TokenCache {
                    access_token: "x".to_string(),
                    refresh_token: None,
                    expires_at: 0,
                },
            };
            let auth = OktaAuth::with_flow(config, Box::new(flow));
            let result = auth.get_token();
            assert!(
                matches!(result, Err(OktaAuthError::SharedCacheRequiresOfflineAccess)),
                "got {result:?}"
            );
            assert_eq!(interactive_calls.load(Ordering::SeqCst), 0);
            assert_eq!(device_calls.load(Ordering::SeqCst), 0);
        });
    }

    #[test]
    fn login_with_explicit_cache_dir_allows_any_scopes() {
        let tmp = tempfile::tempdir().unwrap();
        let config = OktaAuthConfig {
            okta_issuer: "https://test.okta.com/oauth2/default".to_string(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            // No `offline_access`, but `cache_dir` is explicit: the guard does not apply.
            scopes: vec!["openid".to_string()],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let interactive_calls = Arc::new(AtomicUsize::new(0));
        let device_calls = Arc::new(AtomicUsize::new(0));
        let flow = CountingFlow {
            interactive_calls: Arc::clone(&interactive_calls),
            device_calls,
            result: TokenCache {
                access_token: "flow-access".to_string(),
                refresh_token: None,
                expires_at: now_secs() + 3600,
            },
        };
        let auth = OktaAuth::with_flow(config, Box::new(flow));
        auth.login().unwrap();
        assert_eq!(interactive_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    #[serial_test::serial]
    fn get_token_read_path_is_not_guarded() {
        let tmp = tempfile::tempdir().unwrap();
        with_xdg_cache_home(tmp.path(), || {
            let dir = cache::default_cache_dir();
            cache::save(
                &dir,
                &TokenCache {
                    access_token: "valid-shared".to_string(),
                    refresh_token: None,
                    expires_at: now_secs() + 3600,
                },
            )
            .unwrap();

            let config = OktaAuthConfig {
                okta_issuer: "http://127.0.0.1:1".to_string(),
                client_id: "fake".to_string(),
                redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
                // No `offline_access`: the read path is not guarded, only fresh_grant is.
                scopes: vec!["openid".to_string()],
                app_name: "test".to_string(),
                cache_dir: None,
            };
            let auth = OktaAuth::new(config);
            assert_eq!(auth.get_token().unwrap(), "valid-shared");
        });
    }

    // -- fresh_grant: revoke_warning surfacing --

    #[test]
    fn login_or_reuse_reports_revoke_failure_in_message() {
        let tmp = tempfile::tempdir().unwrap();
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-access".to_string(),
                refresh_token: Some("old-refresh".to_string()),
                expires_at: now_secs() + 3600,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: "http://127.0.0.1:1".to_string(), // unreachable -> revoke fails
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let flow = CountingFlow {
            interactive_calls: Arc::new(AtomicUsize::new(0)),
            device_calls: Arc::new(AtomicUsize::new(0)),
            result: TokenCache {
                access_token: "new-access".to_string(),
                refresh_token: Some("new-refresh".to_string()),
                expires_at: now_secs() + 3600,
            },
        };
        let auth = OktaAuth::with_flow(config, Box::new(flow));

        let outcome = auth.login_or_reuse(true, false).unwrap();
        match &outcome {
            LoginOutcome::LoggedIn { revoke_warning, .. } => {
                assert!(revoke_warning.is_some(), "expected a revoke warning, got None")
            }
            other => panic!("expected LoggedIn, got {other:?}"),
        }
        assert!(
            outcome.message().contains("could not be revoked"),
            "got: {}",
            outcome.message()
        );
    }

    #[test]
    fn login_or_reuse_happy_path_has_no_revoke_warning() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = MockOkta::start(vec![(200, "")], tmp.path().to_path_buf());
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-access".to_string(),
                refresh_token: Some("old-refresh".to_string()),
                expires_at: now_secs() + 3600,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let flow = CountingFlow {
            interactive_calls: Arc::new(AtomicUsize::new(0)),
            device_calls: Arc::new(AtomicUsize::new(0)),
            result: TokenCache {
                access_token: "new-access".to_string(),
                refresh_token: Some("new-refresh".to_string()),
                expires_at: now_secs() + 3600,
            },
        };
        let auth = OktaAuth::with_flow(config, Box::new(flow));

        let outcome = auth.login_or_reuse(true, false).unwrap();
        match &outcome {
            LoginOutcome::LoggedIn { revoke_warning, .. } => {
                assert!(revoke_warning.is_none(), "got {revoke_warning:?}")
            }
            other => panic!("expected LoggedIn, got {other:?}"),
        }
        assert!(
            !outcome.message().contains("could not be revoked"),
            "got: {}",
            outcome.message()
        );
        mock.finish();
    }

    // -- CacheWrite precedence when clear/save fails on a read-only cache dir --

    #[cfg(unix)]
    #[test]
    fn logout_returns_cache_write_when_clear_fails() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ro-cache");
        std::fs::create_dir_all(&dir).unwrap();
        cache::save(
            &dir,
            &TokenCache {
                access_token: "access".to_string(),
                refresh_token: Some("refresh".to_string()),
                expires_at: now_secs() + 3600,
            },
        )
        .unwrap();
        let mock = MockOkta::start(vec![(200, "")], dir.clone());

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(dir.clone()),
        };
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let auth = OktaAuth::new(config);
        let result = auth.logout();

        // Restore write permission so the tempdir can clean itself up.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(result, Err(OktaAuthError::CacheWrite(_))), "got {result:?}");
        mock.finish();
    }

    #[cfg(unix)]
    #[test]
    fn refresh_invalid_grant_with_failed_clear_returns_cache_write() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ro-cache");
        std::fs::create_dir_all(&dir).unwrap();
        cache::save(
            &dir,
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: Some("dead-refresh".to_string()),
                expires_at: 0,
            },
        )
        .unwrap();
        let mock = MockOkta::start(vec![(400, r#"{"error":"invalid_grant"}"#)], dir.clone());

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(dir.clone()),
        };
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let auth = OktaAuth::new(config);
        let result = auth.get_token_noninteractive();

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(result, Err(OktaAuthError::CacheWrite(_))), "got {result:?}");
        mock.finish();
    }

    #[cfg(unix)]
    #[test]
    fn get_token_propagates_cache_write_instead_of_opening_browser() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ro-cache");
        std::fs::create_dir_all(&dir).unwrap();
        cache::save(
            &dir,
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: Some("dead-refresh".to_string()),
                expires_at: 0,
            },
        )
        .unwrap();
        let mock = MockOkta::start(vec![(400, r#"{"error":"invalid_grant"}"#)], dir.clone());

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(dir.clone()),
        };
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let interactive_calls = Arc::new(AtomicUsize::new(0));
        let device_calls = Arc::new(AtomicUsize::new(0));
        let flow = CountingFlow {
            interactive_calls: Arc::clone(&interactive_calls),
            device_calls,
            result: TokenCache {
                access_token: "browser-access".to_string(),
                refresh_token: None,
                expires_at: now_secs() + 3600,
            },
        };
        let auth = OktaAuth::with_flow(config, Box::new(flow));
        let result = auth.get_token();

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(result, Err(OktaAuthError::CacheWrite(_))), "got {result:?}");
        assert_eq!(interactive_calls.load(Ordering::SeqCst), 0);
        mock.finish();
    }

    #[cfg(unix)]
    #[test]
    fn login_or_reuse_propagates_cache_write_instead_of_opening_browser() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("ro-cache");
        std::fs::create_dir_all(&dir).unwrap();
        cache::save(
            &dir,
            &TokenCache {
                access_token: "old-expired".to_string(),
                refresh_token: Some("dead-refresh".to_string()),
                expires_at: 0,
            },
        )
        .unwrap();
        let mock = MockOkta::start(vec![(400, r#"{"error":"invalid_grant"}"#)], dir.clone());

        let config = OktaAuthConfig {
            okta_issuer: mock.base_url.clone(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(dir.clone()),
        };
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o500)).unwrap();

        let interactive_calls = Arc::new(AtomicUsize::new(0));
        let device_calls = Arc::new(AtomicUsize::new(0));
        let flow = CountingFlow {
            interactive_calls: Arc::clone(&interactive_calls),
            device_calls,
            result: TokenCache {
                access_token: "browser-access".to_string(),
                refresh_token: None,
                expires_at: now_secs() + 3600,
            },
        };
        let auth = OktaAuth::with_flow(config, Box::new(flow));
        let result = auth.login_or_reuse(false, false);

        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(result, Err(OktaAuthError::CacheWrite(_))), "got {result:?}");
        assert_eq!(interactive_calls.load(Ordering::SeqCst), 0);
        mock.finish();
    }

    // -- fresh_grant: never revoke the token it just saved --

    #[test]
    fn fresh_grant_skips_revoke_when_token_unchanged() {
        let tmp = tempfile::tempdir().unwrap();
        cache::save(
            tmp.path(),
            &TokenCache {
                access_token: "old-access".to_string(),
                refresh_token: Some("persistent-refresh".to_string()),
                expires_at: now_secs() + 3600,
            },
        )
        .unwrap();

        let config = OktaAuthConfig {
            // Unreachable: a revoke attempt would connect-refuse and surface as a
            // revoke_warning. `None` is the proof that no request was made at all.
            okta_issuer: "http://127.0.0.1:1".to_string(),
            client_id: "fake".to_string(),
            redirect_uri: "http://127.0.0.1:19999/callback".to_string(),
            scopes: vec![],
            app_name: "test".to_string(),
            cache_dir: Some(tmp.path().to_path_buf()),
        };
        let flow = CountingFlow {
            interactive_calls: Arc::new(AtomicUsize::new(0)),
            device_calls: Arc::new(AtomicUsize::new(0)),
            // Same refresh token back: what "Use persistent token" does on the refresh
            // path, and what re-authorization may do too.
            result: TokenCache {
                access_token: "new-access".to_string(),
                refresh_token: Some("persistent-refresh".to_string()),
                expires_at: now_secs() + 3600,
            },
        };
        let auth = OktaAuth::with_flow(config, Box::new(flow));

        let outcome = auth.login_or_reuse(true, false).unwrap();
        let LoginOutcome::LoggedIn { revoke_warning, .. } = outcome else {
            panic!("got {outcome:?}");
        };
        assert_eq!(revoke_warning, None);
        // The grant that was just saved is still the one on disk, un-revoked. The
        // inequality half of this rule is `login_saves_new_grant_before_revoking_old`,
        // which records the outgoing /v1/revoke for a genuinely different token.
        let reloaded = cache::load(tmp.path()).unwrap().unwrap();
        assert_eq!(reloaded.access_token, "new-access");
        assert_eq!(reloaded.refresh_token.as_deref(), Some("persistent-refresh"));
    }
}
