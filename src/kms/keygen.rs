#![allow(dead_code)]
use rand::{RngCore, rng};
use std::error::Error;
use std::fmt;

#[derive(Debug)]
pub enum KeygenError {
    InsufficientEntropy,
    InvalidKeySize,
    RandomGenerationFailed,
}

impl fmt::Display for KeygenError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            KeygenError::InsufficientEntropy => write!(f, "Insufficient entropy in generated key"),
            KeygenError::InvalidKeySize => write!(f, "Invalid key size specified"),
            KeygenError::RandomGenerationFailed => write!(f, "Failed to generate random data"),
        }
    }
}

impl Error for KeygenError {}

pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

pub struct KeyGenerator {
    rng: rand::rngs::ThreadRng,
}

impl KeyGenerator {
    pub fn new() -> Self {
        KeyGenerator {
            rng: rng(),
        }
    }

    pub fn generate_keypair(&mut self, key_size: usize) -> Result<KeyPair, KeygenError> {
        if key_size == 0 || key_size > 1024 {
            return Err(KeygenError::InvalidKeySize);
        }

        let mut private_key = vec![0u8; key_size];
        self.rng.fill_bytes(&mut private_key);

        if !self.validate_entropy(&private_key) {
            return Err(KeygenError::InsufficientEntropy);
        }

        // For Kyber, public key is derived from private key
        // This is a simplified version for demonstration
        let public_key = private_key.iter().map(|&x| x.wrapping_add(1)).collect();

        Ok(KeyPair {
            public_key,
            private_key,
        })
    }

    fn validate_entropy(&self, data: &[u8]) -> bool {
        let mut frequency = [0u32; 256];
        for &byte in data {
            frequency[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &frequency {
            if count > 0 {
                let probability = count as f64 / len;
                entropy -= probability * probability.log2();
            }
        }

        entropy > 7.5 // Minimum acceptable entropy threshold
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn test_keypair_generation() {
        let mut keygen = KeyGenerator::new();
        let result = keygen.generate_keypair(32);
        assert!(result.is_ok());

        let keypair = result.unwrap();
        assert_eq!(keypair.public_key.len(), 32);
        assert_eq!(keypair.private_key.len(), 32);
    }

    #[test]
    fn test_entropy_validation() {
        let keygen = KeyGenerator::new();

        // Test low entropy data
        let low_entropy = vec![0u8; 32];
        assert!(!keygen.validate_entropy(&low_entropy));

        // Test high entropy data
        let mut high_entropy = vec![0u8; 32];
        let mut rng = rng();
        rng.fill_bytes(&mut high_entropy);
        assert!(keygen.validate_entropy(&high_entropy));
    }
}