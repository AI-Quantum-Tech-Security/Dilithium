use pqcrypto_dilithium::dilithium3::{
    verify,
    PublicKey,
};
use base64::{encode, decode};
use crate::api::error::ApiError;
use std::sync::Arc;


pub struct Verify {
    public_key: Arc<PublicKey>,
}

impl Verify {
    pub fn new(public_key: PublicKey) -> Self {
        Self {
            public_key: Arc::new(public_key),
        }
    }

    pub fn from_base64_pk(pk_b64: &str) -> Result<Self, ApiError> {
        let public_key_bytes = decode(pk_b64)
            .map_err(|e| ApiError::BadRequest(format!("Invalid public key Base64: {}", e)))?;

        let public_key = PublicKey::from_bytes(&public_key_bytes)
            .map_err(|e| ApiError::BadRequest(format!("Invalid public key bytes: {:?}", e)))?;

        Ok(Self::new(public_key))
    }

    pub fn verify_signature(&self, message: &[u8], signature_b64: &str) -> Result<bool, ApiError> {
        let signature_bytes = decode(signature_b64)
            .map_err(|e| ApiError::Verification(format!("Invalid signature Base64: {}", e)))?;

        let is_valid = verify(&self.public_key, message, &signature_bytes).is_ok();

        Ok(is_valid)
    }
}