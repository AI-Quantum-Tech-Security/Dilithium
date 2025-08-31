use pqcrypto_dilithium::dilithium3::{keypair, sign, PublicKey, SecretKey};
use pqcrypto_dilithium::dilithium3;
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SignedMessage as SignedMessageTrait};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use std::sync::Arc;
use crate::api::error::ApiError;

/// Application crypto key holder.
///
/// Provides helper methods to produce Base64 encoded public key,
/// sign messages (producing a Base64 encoded SignedMessage) and
/// verify signatures (by decoding a Base64 SignedMessage and using `open`).
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

    /// Return the public key encoded in Base64.
    pub fn public_key_base64(&self) -> String {
        // Use the trait method `as_bytes` via an explicit reference to the inner PublicKey.
        let pk_ref: &PublicKey = self.public_key.as_ref();
        let pk_bytes = <PublicKey as PublicKeyTrait>::as_bytes(pk_ref);
        STANDARD.encode(pk_bytes)
    }

    /// Sign a message and return the SignedMessage (signature+message) encoded as Base64.
    pub fn sign_message(&self, message: &[u8]) -> Result<String, ApiError> {
        // sign returns a SignedMessage concrete type
        let signed = sign(message, &*self.secret_key);
        // call trait method as_bytes on the SignedMessage
        let sig_bytes = <dilithium3::SignedMessage as SignedMessageTrait>::as_bytes(&signed);
        Ok(STANDARD.encode(sig_bytes))
    }

    /// Verify a Base64-encoded SignedMessage (signature+message) against a Base64 public key.
    ///
    /// Returns Ok(true) if valid, Ok(false) if invalid, or Err(ApiError) for decoding/parsing errors.
    pub fn verify_signature(
        &self,
        message: &[u8],
        signature_b64: &str,
        pk_b64: &str,
    ) -> Result<bool, ApiError> {
        // decode base64 inputs
        let signature_bytes = STANDARD
            .decode(signature_b64)
            .map_err(|e| ApiError::VerificationError(format!("Invalid signature Base64: {}", e)))?;

        let public_key_bytes = STANDARD
            .decode(pk_b64)
            .map_err(|e| ApiError::VerificationError(format!("Invalid public key Base64: {}", e)))?;

        // Convert bytes into the concrete PublicKey type using the trait's from_bytes via fully-qualified path.
        let public_key = <PublicKey as PublicKeyTrait>::from_bytes(&public_key_bytes).map_err(|e| {
            ApiError::VerificationError(format!("Invalid public key bytes: {:?}", e))
        })?;

        // Convert signature bytes into the concrete SignedMessage type.
        let signed_message = <dilithium3::SignedMessage as SignedMessageTrait>::from_bytes(&signature_bytes)
            .map_err(|e| ApiError::VerificationError(format!("Invalid signature bytes: {:?}", e)))?;

        // Use the crate's `open` function to verify SignedMessage and recover the message.
        // If verification fails, `open` should return an Err; if it succeeds, we get the original message bytes.
        // We compare the recovered message with the provided message to ensure they match.
        match dilithium3::open(&signed_message, &public_key) {
            Ok(recovered) => Ok(recovered.as_slice() == message),
            Err(_) => Ok(false),
        }
    }
}