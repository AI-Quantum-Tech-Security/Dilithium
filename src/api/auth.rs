use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
};
use std::env;
use subtle::ConstantTimeEq;

/// Marker type inserted into handlers that require a valid internal bearer token.
pub struct InternalAuth;

impl<S> FromRequestParts<S> for InternalAuth
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Get the expected token from environment. If it's not set, treat as server misconfig.
        let expected = match env::var("INTERNAL_API_TOKEN") {
            Ok(v) if !v.is_empty() => v,
            _ => return Err(StatusCode::INTERNAL_SERVER_ERROR),
        };

        // Look up Authorization header
        let auth_header = match parts.headers.get(axum::http::header::AUTHORIZATION) {
            Some(h) => h,
            None => return Err(StatusCode::UNAUTHORIZED),
        };

        let auth_str = match auth_header.to_str() {
            Ok(s) => s,
            Err(_) => return Err(StatusCode::UNAUTHORIZED),
        };

        // Must start with "Bearer "
        const BEARER_PREFIX: &str = "Bearer ";
        if !auth_str.starts_with(BEARER_PREFIX) {
            return Err(StatusCode::UNAUTHORIZED);
        }

        let provided = &auth_str[BEARER_PREFIX.len()..];

        // Constant‑time compare
        if provided.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 1 {
            Ok(InternalAuth)
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }
}