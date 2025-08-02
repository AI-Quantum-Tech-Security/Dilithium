use axum::{
    routing::post,
    Json, Router
};
use serde::{Deserialize, Serialize};
use crate::dilithium::signer;
use crate::signer;

#[derive(Deserialize)]
pub struct SignRequest {
    message: String,
    sk: String, // base64
}

#[derive(Serialize)]
pub struct SignResponse {
    signature: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    message: String,
    signature: String,
    pk: String, // base64
}

#[derive(Serialize)]
pub struct VerifyResponse {
    valid: bool,
}

pub fn routes() -> Router {
    Router::new()
        .route("/sign", post(sign))
        .route("/verify", post(verify))
}

async fn sign(Json(req): Json<SignRequest>) -> Json<SignResponse> {
    let sk = base64::decode(&req.sk).expect("Bad SK");
    let signature = signer::sign_message(req.message.as_bytes(), &sk);
    Json(SignResponse { signature })
}
async fn verify(Json(req): Json<VerifyRequest>) -> Json<VerifyResponse> {
    let pk = base64::decode(&req.pk).expect("Bad PK");
    let valid = signer::verify_signature(req.message.as_bytes(), &req.signature, &pk);
    Json(VerifyResponse { valid })
}
