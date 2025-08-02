use axum::{
    extract::State,
    routing::post,
    Router, Json, http::StatusCode,
};
use serde::{Deserialize, Serialize};
use crate::signer;
use std::sync::Arc;

#[derive(Deserialize)]
pub struct SignRequest {
    message: String,
    sk: String,
}

#[derive(Serialize)]
pub struct SignResponse {
    signature: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    message: String,
    signature: String,
    pk: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    valid: bool,
}

#[derive(Clone)]
pub struct AppState {
    token: String,
}

pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/sign", post(sign))
        .route("/verify", post(verify))
        .with_state(Arc::new(state))
}

async fn sign(
    State(state): State<Arc<AppState>>,
    headers: axum::http::HeaderMap,
    Json(req): Json<SignRequest>
) -> Result<Json<SignResponse>, StatusCode> {
    check_auth(&headers, &state.token)?;

    let sk = base64::decode(&req.sk).map_err(|_| StatusCode::BAD_REQUEST)?;
    let signature = signer::sign_message(req.message.as_bytes(), &sk);
    Ok(Json(SignResponse { signature }))
}

async fn verify(Json(req): Json<VerifyRequest>) -> Json<VerifyResponse> {
    let pk = base64::decode(&req.pk).expect("Bad PK");
    let valid = signer::verify_signature(req.message.as_bytes(), &req.signature, &pk);
    Json(VerifyResponse { valid })
}

fn check_auth(headers: &axum::http::HeaderMap, expected_token: &str) -> Result<(), StatusCode> {
    match headers.get("authorization") {
        Some(value) if value.to_str().unwrap_or("") == format!("Bearer {}", expected_token) => Ok(()),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
