use axum::{
    extract::{State, Json},
    http::{StatusCode, HeaderMap},
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::signer;
use crate::auth::InternalAuth;

#[derive(Deserialize)]
pub struct SignRequest {
    message: String,
    //Base64 encoded secret key
    sk: String,
}

#[derive(Serialize)]
pub struct SignResponse {
    //Base64 encoded signature
    signature: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    message: String,
    //Base64 encoded signature
    signature: String,
    //Base64 encoded public key
    pk: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    valid: bool,
}

pub fn routes() -> Router {
    Router::new()
        .route("/sign", post(sign_handler))
        .route("/verify", post(verify_handler))
}

async fn sign_handler(
    _auth: InternalAuth,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, StatusCode> {
    let signature = signer::sign_message(req.message.as_bytes(), &req.sk)
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    Ok(Json(SignResponse { signature }))
}

async fn verify_handler(Json(req): Json<VerifyRequest>) -> Json<VerifyResponse> {
    let valid = signer::verify_signature(
        req.message.as_bytes(),
        &req.signature,
        &req.pk,
    );
    Json(VerifyResponse { valid })
}