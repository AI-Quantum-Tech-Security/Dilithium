use axum::{
    extract::{State, Json},
    routing::{post, get},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub mod crypto_keys;
pub mod auth;
pub mod error;

//data structures for requests and responses
#[derive(Deserialize)]
pub struct SignRequest {
    pub message: String,
}

#[derive(Serialize)]
pub struct SignResponse {
    pub signature: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub message: String,
    pub signature: String,
    pub pk: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
}

#[derive(Serialize)]
pub struct PublicKeyResponse {
    pub public_key: String,
}

pub fn routes(app_keys: Arc<crypto_keys::AppCryptoKeys>) -> Router {
    Router::new()
        .route("/sign", post(sign_handler))
        .route("/verify", post(verify_handler))
        .route("/public-key", get(public_key_handler))
        .with_state(app_keys)
}

//handler for the /sign route
async fn sign_handler(
    _auth: auth::InternalAuth,
    State(app_keys): State<Arc<crypto_keys::AppCryptoKeys>>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignResponse>, error::ApiError> {
    let signature = app_keys.sign_message(req.message.as_bytes())?;
    Ok(Json(SignResponse { signature }))
}

//handler for the /verify route
async fn verify_handler(
    State(app_keys): State<Arc<crypto_keys::AppCryptoKeys>>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, error::ApiError> {
    let valid = app_keys.verify_signature(
        req.message.as_bytes(),
        &req.signature,
        &req.pk,
    )?;
    Ok(Json(VerifyResponse { valid }))
}

//handler for the /public-key route
async fn public_key_handler(
    State(app_keys): State<Arc<crypto_keys::AppCryptoKeys>>,
) -> Json<PublicKeyResponse> {
    let public_key = app_keys.public_key_base64();
    Json(PublicKeyResponse { public_key })
}