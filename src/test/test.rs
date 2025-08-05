#[cfg(test)]
mod tests {
    use crate::signer::*;

    #[test]
    fn test_valid_signature() {
        let (pk, sk) = generate_keypair();
        let msg = b"quantum test";
        let sig = sign_message(msg, &sk);
        assert!(verify_signature(msg, &sig, &pk));
    }

    #[test]
    fn test_signature_rejection_on_tamper() {
        let (pk, sk) = generate_keypair();
        let msg = b"legit";
        let sig = sign_message(msg, &sk);
        let fake = b"forged";
        assert!(!verify_signature(fake, &sig, &pk));
    }

    #[test]
    fn test_invalid_base64_signature() {
        let (pk, _) = generate_keypair();
        let bad_sig = "!!!not_base64$$$";
        let valid = verify_signature(b"any", bad_sig, &pk);
        assert!(!valid);
    }
}