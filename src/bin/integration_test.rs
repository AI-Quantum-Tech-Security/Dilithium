//! Integration test suite for Dilithium API endpoints.
//! Tests sign, verify, and public-key retrieval with various scenarios.

use std::time::Instant;
use rand::Rng;
use pqcrypto_dilithium::dilithium3::{keypair, sign, open, PublicKey, SecretKey};
use pqcrypto_traits::sign::{PublicKey as PublicKeyTrait, SignedMessage as SignedMessageTrait};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;

fn generate_random_message(size_bytes: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..size_bytes).map(|_| rng.gen::<u8>()).collect()
}

fn test_basic_sign_verify() {
    println!("\nTest 1: Basic Sign & Verify");
    let (pk, sk) = keypair();
    let message = b"Hello, Dilithium!";

    let signed = sign(message, &sk);
    let recovered = open(&signed, &pk).expect("Verification failed");
    assert_eq!(&recovered[..], message, "Message verification failed");
    println!("Basic sign/verify works");
}

fn test_large_message() {
    println!("\nTest 2: Large Message (1 MB)");
    let (pk, sk) = keypair();
    let message = generate_random_message(1024 * 1024); // 1 MB

    let start = Instant::now();
    let signed = sign(&message, &sk);
    let sign_time = start.elapsed().as_secs_f64() * 1000.0;

    let start = Instant::now();
    let recovered = open(&signed, &pk).expect("Verification failed");
    let verify_time = start.elapsed().as_secs_f64() * 1000.0;

    assert_eq!(&recovered[..], &message[..], "Large message verification failed");
    println!("1 MB message signed in {:.2} ms, verified in {:.2} ms", sign_time, verify_time);
}

fn test_invalid_signature() {
    println!("\nTest 3: Invalid Signature Detection");
    let (pk, sk) = keypair();
    let message = b"Original message";

    let signed = sign(message, &sk);
    let mut sig_bytes = <pqcrypto_dilithium::dilithium3::SignedMessage as SignedMessageTrait>::as_bytes(&signed).to_vec();

    // Tamper with the signature
    sig_bytes[10] ^= 0xFF;
    let tampered_signed = <pqcrypto_dilithium::dilithium3::SignedMessage as SignedMessageTrait>::from_bytes(&sig_bytes).unwrap();

    let result = open(&tampered_signed, &pk);
    assert!(result.is_err() || &result.unwrap()[..] != message, "Tampered signature should not verify");
    println!("Invalid signature correctly rejected");
}

fn test_multiple_keypairs() {
    println!("\nTest 4: Multiple Keypair Isolation");
    let (pk1, sk1) = keypair();
    let (pk2, _sk2) = keypair();
    let message = b"Test message";

    let signed_by_1 = sign(message, &sk1);

    // Try to verify with wrong key
    let result = open(&signed_by_1, &pk2);
    assert!(result.is_err() || &result.unwrap()[..] != message, "Signature from key1 should not verify with key2");

    // Verify with correct key
    let result = open(&signed_by_1, &pk1).expect("Verification with correct key failed");
    assert_eq!(&result[..], message, "Signature from key1 should verify with key1");
    println!("Keypair isolation verified");
}

fn test_base64_encoding() {
    println!("\nTest 5: Base64 Encoding/Decoding");
    let (pk, sk) = keypair();
    let message = b"Test base64 encoding";

    let signed = sign(message, &sk);

    let pk_bytes = <PublicKey as PublicKeyTrait>::as_bytes(&pk);
    let sig_bytes = <pqcrypto_dilithium::dilithium3::SignedMessage as SignedMessageTrait>::as_bytes(&signed);

    let pk_b64 = STANDARD.encode(pk_bytes);
    let sig_b64 = STANDARD.encode(sig_bytes);

    // Decode and verify
    let decoded_pk_bytes = STANDARD.decode(&pk_b64).unwrap();
    let decoded_sig_bytes = STANDARD.decode(&sig_b64).unwrap();

    let pk_decoded = <PublicKey as PublicKeyTrait>::from_bytes(&decoded_pk_bytes).unwrap();
    let signed_decoded = <pqcrypto_dilithium::dilithium3::SignedMessage as SignedMessageTrait>::from_bytes(&decoded_sig_bytes).unwrap();

    let result = open(&signed_decoded, &pk_decoded).expect("Base64 round-trip verification failed");
    assert_eq!(&result[..], message, "Base64 round-trip failed");
    println!("Base64 encoding/decoding works correctly");
}

fn test_deterministic_within_key() {
    println!("\nTest 6: Signature Determinism");
    let (pk, sk) = keypair();
    let message = b"Determinism test";

    let signed1 = sign(message, &sk);
    let signed2 = sign(message, &sk);

    let sig1_bytes = <pqcrypto_dilithium::dilithium3::SignedMessage as SignedMessageTrait>::as_bytes(&signed1);
    let sig2_bytes = <pqcrypto_dilithium::dilithium3::SignedMessage as SignedMessageTrait>::as_bytes(&signed2);

    assert_eq!(sig1_bytes, sig2_bytes, "Same message with same key should produce identical signatures");
    println!("Signatures are deterministic");
}

fn test_concurrent_operations() {
    println!("\nTest 7: Concurrent Operations");
    use std::thread;
    use std::sync::Arc;

    let (pk, sk) = keypair();
    let pk = Arc::new(pk);
    let sk = Arc::new(sk);

    let mut handles = vec![];

    for i in 0..10 {
        let pk = Arc::clone(&pk);
        let sk = Arc::clone(&sk);

        let handle = thread::spawn(move || {
            let message = format!("Concurrent message {}", i);
            let signed = sign(message.as_bytes(), &sk);
            let result = open(&signed, &pk).expect("Concurrent verification failed");
            assert_eq!(&result[..], message.as_bytes());
            result.len()
        });

        handles.push(handle);
    }

    let mut total_verified = 0;
    for handle in handles {
        total_verified += handle.join().unwrap();
    }

    println!("10 concurrent operations completed, {} bytes verified", total_verified);
}

fn main() {
    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║        DILITHIUM INTEGRATION TEST SUITE                     ║");
    println!("║  Comprehensive Cryptographic Operation Validation           ║");
    println!("╚══════════════════════════════════════════════════════════════╝");

    let start = Instant::now();
    let mut passed = 0;
    let mut failed = 0;

    // Run all tests
    let tests: Vec<(&str, fn())> = vec![
        ("Basic Sign & Verify", test_basic_sign_verify),
        ("Large Message (1 MB)", test_large_message),
        ("Invalid Signature Detection", test_invalid_signature),
        ("Multiple Keypair Isolation", test_multiple_keypairs),
        ("Base64 Encoding/Decoding", test_base64_encoding),
        ("Signature Determinism", test_deterministic_within_key),
        ("Concurrent Operations", test_concurrent_operations),
    ];

    for (name, test_fn) in tests {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(test_fn)) {
            Ok(_) => passed += 1,
            Err(_) => {
                failed += 1;
                println!("Test failed: {}", name);
            }
        }
    }

    let duration = start.elapsed().as_secs_f64();

    println!("\n╔══════════════════════════════════════════════════════════════╗");
    println!("║                    TEST RESULTS SUMMARY                     ║");
    println!("║  Passed: {} | Failed: {} | Duration: {:.2}s                  ║", passed, failed, duration);
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    if failed > 0 {
        std::process::exit(1);
    }
}