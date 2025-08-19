use pqcrypto_dilithium::dilithium3::{
    keypair, sign, verify, PublicKey, SecretKey,
};
use base64::{encode, decode};
use std::sync::Arc;
use crate::api::error::ApiError;

#[derive(Clone)]
pub struct AppCryptoKeys {
    pub public_key: Arc<PublicKey>,
    pub secret_key: Arc<SecretKey>,
}

impl AppCryptoKeys {
    pub fn new() -> Result<Self, ApiError> {
        let (pk, sk) = keypair();
        Ok(Self {
            public_key: Arc::new(pk),
            secret_key: Arc::new(sk),
        })
    }

    pub fn public_key_base64(&self) -> String {
        encode(self.public_key.as_bytes())
    }

    pub fn sign_message(&self, message: &[u8]) -> Result<String, ApiError> {
        let signature = sign(message, &self.secret_key);
        Ok(encode(signature.as_bytes()))
    }

    pub fn verify_signature(
        &self,
        message: &[u8],
        signature_b64: &str,
        pk_b64: &str,
    ) -> Result<bool, ApiError> {
        let signature_bytes = decode(signature_b64)
            .map_err(|e| ApiError::VerificationError(format!("Invalid signature Base64: {}", e)))?;

        let public_key_bytes = decode(pk_b64)
            .map_err(|e| ApiError::VerificationError(format!("Invalid public key Base64: {}", e)))?;

        let public_key = PublicKey::from_bytes(&public_key_bytes)
            .map_err(|e| {
                ApiError::VerificationError(format!("Invalid public key bytes: {:?}", e))
            })?;

        let is_valid = verify(&public_key, message, &signature_bytes).is_ok();
        Ok(is_valid)
    }
}