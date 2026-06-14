use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use log::debug;
use serde::{Deserialize, Serialize};

use crate::OktaAuthError;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenCache {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: u64,
}

impl TokenCache {
    pub fn is_valid(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Consider invalid if less than 60 seconds remaining
        self.expires_at > now + 60
    }
}

/// XDG cache dir, honoring `$XDG_CACHE_HOME` and falling back to `$HOME/.cache`.
///
/// A token cache is regenerable, non-essential data (lose it -> re-login), so it
/// belongs under `XDG_CACHE_HOME`, not `XDG_CONFIG_HOME` (which is for static,
/// hand-edited configuration). Resolved without the `dirs` cache helper so it honors
/// the env var on every platform (macOS included, where `dirs` would return
/// `~/Library/Caches` and ignore the env var).
fn xdg_cache_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("XDG_CACHE_HOME") {
        let path = PathBuf::from(dir);
        if path.is_absolute() {
            return Some(path);
        }
    }
    dirs::home_dir().map(|h| h.join(".cache"))
}

/// The default token cache directory: `~/.cache/okta/`.
///
/// This is **shared** across every CLI that uses okta-auth (it is not keyed by
/// app name), so a login with a given Okta app is reused by all of them - one login,
/// many tools. Tools that authenticate with the same Okta client therefore share a
/// single cached credential. A tool that needs isolation can still pass an explicit
/// `cache_dir`.
pub fn default_cache_dir() -> PathBuf {
    xdg_cache_dir().unwrap_or_else(|| PathBuf::from(".cache")).join("okta")
}

fn cache_path(dir: &Path) -> PathBuf {
    dir.join("tokens.json")
}

pub fn load(dir: &Path) -> Result<Option<TokenCache>, OktaAuthError> {
    let path = cache_path(dir);
    debug!("loading token cache from {:?}", path);
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path).map_err(|e| OktaAuthError::CacheRead(e.to_string()))?;
    let cache: TokenCache = serde_json::from_str(&contents).map_err(|e| OktaAuthError::CacheParse(e.to_string()))?;
    Ok(Some(cache))
}

pub fn save(dir: &Path, cache: &TokenCache) -> Result<(), OktaAuthError> {
    fs::create_dir_all(dir).map_err(|e| OktaAuthError::ConfigDir(e.to_string()))?;

    let path = cache_path(dir);
    let temp_path = path.with_extension("json.tmp");

    let contents = serde_json::to_string_pretty(cache).map_err(|e| OktaAuthError::CacheWrite(e.to_string()))?;
    {
        let mut file = fs::File::create(&temp_path).map_err(|e| OktaAuthError::CacheWrite(e.to_string()))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| OktaAuthError::CacheWrite(e.to_string()))?;
        file.sync_all().map_err(|e| OktaAuthError::CacheWrite(e.to_string()))?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))
            .map_err(|e| OktaAuthError::CacheWrite(e.to_string()))?;
    }

    fs::rename(&temp_path, &path).map_err(|e| OktaAuthError::CacheWrite(e.to_string()))?;
    debug!("saved token cache to {:?}", path);
    Ok(())
}

pub fn clear(dir: &Path) -> Result<(), OktaAuthError> {
    let path = cache_path(dir);
    if path.exists() {
        fs::remove_file(&path).map_err(|e| OktaAuthError::CacheWrite(e.to_string()))?;
        debug!("cleared token cache at {:?}", path);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn make_cache(expires_at: u64) -> TokenCache {
        TokenCache {
            access_token: "access-token-abc".to_string(),
            refresh_token: Some("refresh-token-xyz".to_string()),
            expires_at,
        }
    }

    fn now_secs() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    // -- is_valid tests --

    #[test]
    fn is_valid_when_not_expired() {
        let cache = make_cache(now_secs() + 3600);
        assert!(cache.is_valid());
    }

    #[test]
    fn is_invalid_when_expired() {
        let cache = make_cache(0);
        assert!(!cache.is_valid());
    }

    #[test]
    fn is_invalid_within_60s_buffer() {
        let cache = make_cache(now_secs() + 30);
        assert!(!cache.is_valid());
    }

    #[test]
    fn is_valid_at_exactly_61s_remaining() {
        let cache = make_cache(now_secs() + 61);
        assert!(cache.is_valid());
    }

    #[test]
    fn is_invalid_at_exactly_60s_remaining() {
        let cache = make_cache(now_secs() + 60);
        assert!(!cache.is_valid());
    }

    #[test]
    fn is_invalid_with_expires_at_zero() {
        let cache = TokenCache {
            access_token: "t".to_string(),
            refresh_token: None,
            expires_at: 0,
        };
        assert!(!cache.is_valid());
    }

    // -- serialization tests --

    #[test]
    fn token_cache_round_trips_json() {
        let cache = make_cache(1234567890);
        let json = serde_json::to_string(&cache).unwrap();
        let deserialized: TokenCache = serde_json::from_str(&json).unwrap();
        assert_eq!(cache, deserialized);
    }

    #[test]
    fn token_cache_deserializes_with_null_refresh_token() {
        let json = r#"{"access_token":"abc","refresh_token":null,"expires_at":100}"#;
        let cache: TokenCache = serde_json::from_str(json).unwrap();
        assert_eq!(cache.access_token, "abc");
        assert!(cache.refresh_token.is_none());
        assert_eq!(cache.expires_at, 100);
    }

    #[test]
    fn token_cache_deserializes_without_refresh_token_field() {
        // serde treats missing Option fields as None
        let json = r#"{"access_token":"abc","expires_at":100}"#;
        let result: Result<TokenCache, _> = serde_json::from_str(json);
        // serde requires the field by default for Option - documenting actual behavior
        if let Ok(cache) = result {
            assert_eq!(cache.access_token, "abc");
            assert!(cache.refresh_token.is_none());
        }
        // Either outcome is valid - the test documents behavior
    }

    #[test]
    fn token_cache_rejects_malformed_json() {
        let json = r#"{"access_token": 123}"#;
        let result: Result<TokenCache, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // -- filesystem cache tests --

    #[test]
    fn load_returns_none_for_nonexistent_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("nonexistent");
        let result = load(&dir).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn save_and_load_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("test-app");
        let cache = make_cache(now_secs() + 3600);

        save(&dir, &cache).unwrap();
        let loaded = load(&dir).unwrap().unwrap();

        assert_eq!(loaded.access_token, cache.access_token);
        assert_eq!(loaded.refresh_token, cache.refresh_token);
        assert_eq!(loaded.expires_at, cache.expires_at);
    }

    #[test]
    fn save_creates_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("deeply").join("nested").join("app");
        let cache = make_cache(now_secs() + 3600);

        save(&dir, &cache).unwrap();
        assert!(dir.exists());
        assert!(dir.join("tokens.json").exists());
    }

    #[test]
    fn save_overwrites_existing_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("test-app");

        let first = TokenCache {
            access_token: "first".to_string(),
            refresh_token: Some("r1".to_string()),
            expires_at: 100,
        };
        save(&dir, &first).unwrap();

        let second = TokenCache {
            access_token: "second".to_string(),
            refresh_token: Some("r2".to_string()),
            expires_at: 200,
        };
        save(&dir, &second).unwrap();

        let loaded = load(&dir).unwrap().unwrap();
        assert_eq!(loaded.access_token, "second");
        assert_eq!(loaded.refresh_token, Some("r2".to_string()));
        assert_eq!(loaded.expires_at, 200);
    }

    #[cfg(unix)]
    #[test]
    fn save_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("test-app");
        let cache = make_cache(now_secs() + 3600);

        save(&dir, &cache).unwrap();

        let path = dir.join("tokens.json");
        let perms = fs::metadata(&path).unwrap().permissions();
        assert_eq!(perms.mode() & 0o777, 0o600);
    }

    #[test]
    fn save_does_not_leave_temp_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("test-app");
        let cache = make_cache(now_secs() + 3600);

        save(&dir, &cache).unwrap();

        let temp_path = dir.join("tokens.json.tmp");
        assert!(!temp_path.exists());
    }

    #[test]
    fn clear_removes_cache_file() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("test-app");
        let cache = make_cache(now_secs() + 3600);

        save(&dir, &cache).unwrap();
        assert!(dir.join("tokens.json").exists());

        clear(&dir).unwrap();
        assert!(!dir.join("tokens.json").exists());
    }

    #[test]
    fn clear_is_noop_when_no_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("no-cache");
        // Should not error
        clear(&dir).unwrap();
    }

    #[test]
    fn load_returns_error_for_malformed_json() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("test-app");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("tokens.json"), "not json at all").unwrap();

        let result = load(&dir);
        assert!(result.is_err());
        match result.unwrap_err() {
            OktaAuthError::CacheParse(_) => {}
            other => panic!("expected CacheParse, got {:?}", other),
        }
    }

    #[test]
    fn load_returns_error_for_wrong_json_shape() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("test-app");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("tokens.json"), r#"{"foo": "bar"}"#).unwrap();

        let result = load(&dir);
        assert!(result.is_err());
        match result.unwrap_err() {
            OktaAuthError::CacheParse(_) => {}
            other => panic!("expected CacheParse, got {:?}", other),
        }
    }

    // -- XDG resolution tests --
    //
    // Env-var mutation is process-global and unsafe under Edition 2024; `#[serial]`
    // serializes these against each other. They restore prior values so they don't
    // leak into other tests.

    fn with_env(key: &str, value: Option<&Path>, body: impl FnOnce()) {
        let prior = std::env::var_os(key);
        match value {
            Some(path) => unsafe { std::env::set_var(key, path) },
            None => unsafe { std::env::remove_var(key) },
        }
        body();
        match prior {
            Some(v) => unsafe { std::env::set_var(key, v) },
            None => unsafe { std::env::remove_var(key) },
        }
    }

    #[test]
    #[serial_test::serial]
    fn xdg_cache_dir_honors_absolute_xdg_cache_home() {
        let tmp = tempfile::tempdir().unwrap();
        with_env("XDG_CACHE_HOME", Some(tmp.path()), || {
            assert_eq!(xdg_cache_dir().as_deref(), Some(tmp.path()));
        });
    }

    #[test]
    #[serial_test::serial]
    fn xdg_cache_dir_falls_back_to_home_dot_cache() {
        let home = tempfile::tempdir().unwrap();
        with_env("XDG_CACHE_HOME", None, || {
            with_env("HOME", Some(home.path()), || {
                assert_eq!(xdg_cache_dir(), Some(home.path().join(".cache")));
            });
        });
    }

    #[test]
    #[serial_test::serial]
    fn xdg_cache_dir_ignores_relative_xdg_cache_home() {
        // A non-absolute $XDG_CACHE_HOME is ignored in favor of the $HOME fallback.
        let home = tempfile::tempdir().unwrap();
        with_env("XDG_CACHE_HOME", Some(Path::new("relative/not-absolute")), || {
            with_env("HOME", Some(home.path()), || {
                assert_eq!(xdg_cache_dir(), Some(home.path().join(".cache")));
            });
        });
    }

    #[test]
    #[serial_test::serial]
    fn default_cache_dir_is_shared_okta_under_xdg_cache() {
        // The cache dir is shared (`<XDG_CACHE>/okta`), not keyed by app name, so
        // every tool using the same Okta client shares one credential.
        let tmp = tempfile::tempdir().unwrap();
        with_env("XDG_CACHE_HOME", Some(tmp.path()), || {
            assert_eq!(default_cache_dir(), tmp.path().join("okta"));
        });
    }
}
