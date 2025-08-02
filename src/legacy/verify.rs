// src/dilithium/verify.rs

use crate::dilithium::keys::PublicKey;
use crate::dilithium::params::DilithiumParams;
use crate::dilithium::sign::Signature;
use crate::dilithium::poly::Polynomial;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

fn hash_poly_and_message(poly: &Polynomial, message: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    for coef in &poly.coeff {
        hasher.update(&coef.to_le_bytes());
    }
    hasher.update(message);
    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; 32];
    reader.read(&mut output);
    output
}

pub fn verify_signature(
    _pk: &PublicKey,
    message: &[u8],
    sig: &Signature,
    params: &DilithiumParams,
) -> bool {
    let c_recomputed = hash_poly_and_message(&sig.z, message);
    c_recomputed == sig.c
}
