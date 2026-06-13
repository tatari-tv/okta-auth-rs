#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OktaAuthError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    /// The callback listener could not bind its port. This is never fatal: the local
    /// flow falls back to the device authorization grant, which needs no listener.
    /// Nothing constructs this variant after the device-grant redesign; it is retained
    /// so external consumers matching on it do not break (removing it would be a
    /// SemVer-breaking change).
    #[deprecated(note = "bind failure is now non-fatal; the flow falls back to the device grant")]
    #[error("Failed to bind to {addr}: another login may be running: {source}")]
    BindFailed {
        addr: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("Timed out waiting for authentication callback")]
    CallbackTimeout,

    #[error(
        "Okta token is missing or expired and no controlling terminal is available \
         (non-interactive session). Re-authenticate in a terminal first, then retry."
    )]
    NonInteractive,

    #[error("No query parameters in callback")]
    NoQueryParams,

    #[error("No authorization code in callback")]
    NoAuthCode,

    #[error("No state parameter in callback")]
    NoState,

    #[error("CSRF state mismatch - possible attack")]
    CsrfMismatch,

    #[error("Authentication error from Okta: {error} - {description}")]
    OktaError { error: String, description: String },

    #[error("Token exchange failed: {0}")]
    TokenExchange(String),

    #[error("Device authorization failed: {0}")]
    DeviceFlow(String),

    #[error("Refresh token exchange failed: {0}")]
    RefreshFailed(String),

    #[error("Failed to read token cache: {0}")]
    CacheRead(String),

    #[error("Failed to write token cache: {0}")]
    CacheWrite(String),

    #[error("Failed to parse token cache: {0}")]
    CacheParse(String),

    #[error("Failed to create config directory: {0}")]
    ConfigDir(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        let cases: Vec<(OktaAuthError, &str)> = vec![
            (OktaAuthError::InvalidUrl("bad url".to_string()), "Invalid URL: bad url"),
            (
                OktaAuthError::CallbackTimeout,
                "Timed out waiting for authentication callback",
            ),
            (
                OktaAuthError::NonInteractive,
                "Okta token is missing or expired and no controlling terminal is available \
                 (non-interactive session). Re-authenticate in a terminal first, then retry.",
            ),
            (OktaAuthError::NoQueryParams, "No query parameters in callback"),
            (OktaAuthError::NoAuthCode, "No authorization code in callback"),
            (OktaAuthError::NoState, "No state parameter in callback"),
            (OktaAuthError::CsrfMismatch, "CSRF state mismatch - possible attack"),
            (
                OktaAuthError::OktaError {
                    error: "access_denied".to_string(),
                    description: "user not assigned".to_string(),
                },
                "Authentication error from Okta: access_denied - user not assigned",
            ),
            (
                OktaAuthError::TokenExchange("connection refused".to_string()),
                "Token exchange failed: connection refused",
            ),
            (
                OktaAuthError::RefreshFailed("expired".to_string()),
                "Refresh token exchange failed: expired",
            ),
            (
                OktaAuthError::CacheRead("permission denied".to_string()),
                "Failed to read token cache: permission denied",
            ),
            (
                OktaAuthError::CacheWrite("disk full".to_string()),
                "Failed to write token cache: disk full",
            ),
            (
                OktaAuthError::CacheParse("unexpected token".to_string()),
                "Failed to parse token cache: unexpected token",
            ),
            (
                OktaAuthError::ConfigDir("no such directory".to_string()),
                "Failed to create config directory: no such directory",
            ),
        ];

        for (error, expected) in cases {
            assert_eq!(error.to_string(), expected);
        }
    }

    #[test]
    fn error_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        // BindFailed contains Box<dyn Error + Send + Sync>, so the whole enum is Send+Sync
        assert_send_sync::<OktaAuthError>();
    }

    #[test]
    #[allow(deprecated)] // BindFailed is retained for SemVer compatibility; still assert its message
    fn bind_failed_includes_addr_and_source() {
        let err = OktaAuthError::BindFailed {
            addr: "127.0.0.1:11313".to_string(),
            source: "address already in use".into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("127.0.0.1:11313"));
        assert!(msg.contains("address already in use"));
    }
}
