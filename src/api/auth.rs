use axum::{
    extract::{FromRequestParts},
    http::{request::Parts, StatusCode},
};
use std::env;
use async_trait::async_trait;
use subtle::ConstantTimeEq;

pub struct InternalAuth;

#[async_trait]
impl<S> FromRequestParts<S> for InternalAuth
where
    S: Send + Sync,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let token = env::var("INTERNAL_API_TOKEN").expect("API token not set");
        if let Some(auth_header) = parts.headers.get("authorization") {
            let auth = auth_header.to_str().unwrap_or("");
            if auth.starts_with("Bearer ") {
                let provided = &auth[7..];
                if provided.as_bytes().ct_eq(token.as_bytes()).unwrap_u8() == 1 {
                    return Ok(Self);
                }
            }
        }
        Err(StatusCode::UNAUTHORIZED)
    }
}