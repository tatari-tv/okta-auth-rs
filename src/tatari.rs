//! Tatari's Okta defaults.
//!
//! These are the **default tier** of the config-precedence chain in Tatari CLIs
//! (persona, marquee, verify): a consumer references them as its fallback, while CLI
//! flags / env vars / config file still override per field. They are deliberately NOT
//! wired into the [`OktaAuth`](crate::OktaAuth) flow itself - that stays generic and
//! value-driven - so this module is the single source of truth for "which Okta app do
//! Tatari CLIs use", changeable in one place instead of once per consumer.

/// Tatari Okta authorization server issuer.
pub const ISSUER: &str = "https://tatari.okta.com/oauth2/default";

/// The unified Tatari CLI Okta app: a public native client (PKCE, no secret), so the
/// id is safe to commit. One app shared by persona / marquee / verify, so one login
/// is reused across all of them (paired with the shared `~/.cache/okta` token cache).
pub const CLIENT_ID: &str = "0oa144xsutkeO1nev698";

/// Shared local OAuth redirect URI, registered on the unified app. Multiple Okta apps
/// may register the same callback, so this can coexist with a tool's old app during
/// cutover.
pub const REDIRECT_URI: &str = "http://local.tatari.tools:11313/callback";

/// Default OAuth2 scopes (identity claims only).
pub const SCOPES: &[&str] = &["openid", "email", "profile"];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_populated() {
        assert!(ISSUER.starts_with("https://"));
        assert!(!CLIENT_ID.is_empty());
        assert!(REDIRECT_URI.starts_with("http://"));
        assert_eq!(SCOPES, ["openid", "email", "profile"]);
    }
}
