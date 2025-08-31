use axum::{http::StatusCode, response::{Response, IntoResponse}, Json};
use serde::Serialize;
use std::fmt;

/// API error type used to convert application errors into HTTP responses.
///
/// Note: we allow `dead_code` here to avoid warnings while some variants are not yet used.
/// If you prefer, remove unused variants or add conversions/uses for them.
#[allow(dead_code)]
#[derive(Debug, Serialize)]
pub enum ApiError {
    SignatureError(String),
    VerificationError(String),
    BadRequest(String),
    Unauthorized,
    InternalServerError(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            ApiError::SignatureError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::VerificationError(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string()),
            ApiError::InternalServerError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        (status, Json(ApiErrorResponse { message: error_message })).into_response()
    }
}

#[derive(Serialize)]
struct ApiErrorResponse {
    message: String,
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::SignatureError(msg) => write!(f, "Signature error: {}", msg),
            ApiError::VerificationError(msg) => write!(f, "Verification error: {}", msg),
            ApiError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
            ApiError::Unauthorized => write!(f, "Unauthorized"),
            ApiError::InternalServerError(msg) => write!(f, "Internal server error: {}", msg),
        }
    }
}