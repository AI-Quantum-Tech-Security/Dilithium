use pqcrypto_dilithium::dilithium3::*;
use base64::{encode, decode};

pub fn generate_keypair() -> (Vec<u8>, Vec<u8>) {
    let (pk, sk) = keypair();
    (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
}

pub fn sign_message(message: &[u8], sk: &[u8]) -> String {
    let secret_key = SecretKey::from_bytes(sk).expect("Invalid SK");
    let sig = sign(message, &secret_key);
    encode(sig.as_bytes())
}

pub fn verify_signature(message: &[u8], signature_b64: &str, pk: &[u8]) -> bool {
    let signature = match decode(signature_b64) {
        Ok(sig) => sig,
        Err(_) => return false,
    };
    let public_key = PublicKey::from_bytes(pk).expect("Invalid PK");
    let sig_struct = match SignedMessage::from_bytes(&signature) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sig_struct.verify(&public_key).is_ok()
}
