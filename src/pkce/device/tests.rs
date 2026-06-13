#![allow(clippy::unwrap_used)]

use super::*;

#[test]
fn success_response_yields_token_with_computed_expiry() {
    let body = r#"{"access_token":"AT","refresh_token":"RT","expires_in":3600}"#;
    match interpret_token_response(true, body, 1000) {
        Poll::Token(token) => {
            assert_eq!(token.access_token, "AT");
            assert_eq!(token.refresh_token.as_deref(), Some("RT"));
            assert_eq!(token.expires_at, 4600);
        }
        other => panic!("expected Token, got {other:?}"),
    }
}

#[test]
fn success_without_expires_in_uses_default_ttl_and_no_refresh() {
    let body = r#"{"access_token":"AT"}"#;
    match interpret_token_response(true, body, 1000) {
        Poll::Token(token) => {
            assert_eq!(token.expires_at, 1000 + DEFAULT_TOKEN_TTL_SECS);
            assert!(token.refresh_token.is_none());
        }
        other => panic!("expected Token, got {other:?}"),
    }
}

#[test]
fn authorization_pending_keeps_polling() {
    let body = r#"{"error":"authorization_pending"}"#;
    assert!(matches!(interpret_token_response(false, body, 0), Poll::Pending));
}

#[test]
fn slow_down_backs_off() {
    let body = r#"{"error":"slow_down"}"#;
    assert!(matches!(interpret_token_response(false, body, 0), Poll::SlowDown));
}

#[test]
fn access_denied_is_terminal_okta_error() {
    let body = r#"{"error":"access_denied","error_description":"user not assigned"}"#;
    match interpret_token_response(false, body, 0) {
        Poll::Failed(OktaAuthError::OktaError { error, description }) => {
            assert_eq!(error, "access_denied");
            assert_eq!(description, "user not assigned");
        }
        other => panic!("expected OktaError, got {other:?}"),
    }
}

#[test]
fn expired_token_maps_to_callback_timeout() {
    let body = r#"{"error":"expired_token"}"#;
    assert!(matches!(
        interpret_token_response(false, body, 0),
        Poll::Failed(OktaAuthError::CallbackTimeout)
    ));
}

#[test]
fn unknown_error_is_terminal_okta_error() {
    let body = r#"{"error":"weird_thing","error_description":"huh"}"#;
    match interpret_token_response(false, body, 0) {
        Poll::Failed(OktaAuthError::OktaError { error, .. }) => assert_eq!(error, "weird_thing"),
        other => panic!("expected OktaError, got {other:?}"),
    }
}

#[test]
fn malformed_success_body_is_failed() {
    assert!(matches!(
        interpret_token_response(true, "not json", 0),
        Poll::Failed(OktaAuthError::TokenExchange(_))
    ));
}

#[test]
fn malformed_error_body_is_failed() {
    assert!(matches!(
        interpret_token_response(false, "not json", 0),
        Poll::Failed(OktaAuthError::TokenExchange(_))
    ));
}
