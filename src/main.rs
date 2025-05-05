// src/main.rs
mod dilithium;


use dilithium::params::DilithiumParams;
use dilithium::keys::keygen;
use dilithium::sign::sign_message;
use dilithium::verify::verify_signature;
use std::{env, fs};

fn sign_and_verify_file(
    file_path: &str,
    sk: &dilithium::keys::SecretKey,
    pk: &dilithium::keys::PublicKey,
    params: &DilithiumParams,
) {
    let file_data = fs::read(file_path)
        .unwrap_or_else(|err| panic!("Error reading file {}: {}", file_path, err));
    println!("File '{}' read successfully ({} bytes).", file_path, file_data.len());

    let signature = sign_message(sk, &file_data, params);
    println!("Signature for file '{}': {:?}", file_path, signature);

    let valid = verify_signature(pk, &file_data, &signature, params);
    println!("Verification result for file '{}': {}", file_path, valid);
}

fn main() {
    let params = DilithiumParams::default();

    let (public_key, secret_key) = keygen(&params);
    println!("Public Key: {:?}", public_key);
    println!("Secret Key: {:?}", secret_key);


    
    let message = b"Hello, Crystal Dilithium!";
    println!("\nSigning default message: {:?}", String::from_utf8_lossy(message));
    let signature = sign_message(&secret_key, message, &params);
    println!("Signature: {:?}", signature);

    let valid = verify_signature(&public_key, message, &signature, &params);
    println!("Verification result: {}", valid);
}
