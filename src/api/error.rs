use axum::{http::StatusCode, response::{Response, IntoResponse}, Json};
use serde::Serialize;

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