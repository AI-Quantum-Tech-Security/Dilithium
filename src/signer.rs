use pqcrypto_dilithium::dilithium3::{
    keypair, sign, verify, PublicKey, SecretKey,
};
use base64::{encode, decode};

pub fn generate_keypair() -> (String, String) {
    let (pk, sk) = keypair();
    (encode(pk.as_bytes()), encode(sk.as_bytes()))
}

pub fn sign_message(message: &[u8], sk_b64: &str) -> Result<String, base64::DecodeError> {
    let sk_bytes = decode(sk_b64)?;
    let secret_key = SecretKey::from_bytes(&sk_bytes).expect("Invalid secret key bytes");
    let signed_message = sign(message, &secret_key);
    Ok(encode(signed_message.as_bytes()))
}

pub fn verify_signature(message: &[u8], sig_b64: &str, pk_b64: &str) -> bool {
    let signature = match decode(sig_b64) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let public_key = match decode(pk_b64) {
        Ok(p) => match PublicKey::from_bytes(&p) {
            Ok(pk) => pk,
            Err(_) => return false,
        },
        Err(_) => return false,
    };

    verify(&public_key, message, &signature).is_ok()
}