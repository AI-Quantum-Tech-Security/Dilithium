#[cfg(test)]
mod tests {
    use crate::dilithium::sign::sign_message;
    use crate::dilithium::signer::{generate_keypair, verify_signature};
    use crate::signer::*;

    #[test]
    fn test_sign_and_verify() {
        let (pk, sk) = generate_keypair();
        let msg = b"hello quantum world";
        let sig = sign_message(msg, &sk);
        let valid = verify_signature(msg, &sig, &pk);
        assert!(valid);
    }

    #[test]
    fn test_forged_message_fails() {
        let (pk, sk) = generate_keypair();
        let msg = b"legit";
        let sig = sign_message(msg, &sk);
        let forged = b"tampered";
        let valid = verify_signature(forged, &sig, &pk);
        assert!(!valid);
    }
}
