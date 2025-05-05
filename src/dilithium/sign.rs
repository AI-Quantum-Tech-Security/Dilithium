// src/dilithium/sign.rs

use crate::dilithium::keys::SecretKey;
use crate::dilithium::params::DilithiumParams;
use crate::dilithium::poly::Polynomial;
use rand::Rng;
use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};

#[derive(Debug)]
pub struct Signature {
    pub z: Polynomial,
    pub c: Vec<u8>,
}


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

fn rejection_sample(poly: &Polynomial, _params: &DilithiumParams) -> bool {
    true
}


pub fn sign_message(sk: &SecretKey, message: &[u8], params: &DilithiumParams) -> Signature {
    let n = params.n;
    let mut rng = rand::thread_rng();

    let r = Polynomial {
        coeff: (0..n).map(|_| rng.gen_range(-params.eta..=params.eta)).collect(),
    };

    let z_coeff: Vec<i64> = sk.poly.coeff.iter()
        .zip(r.coeff.iter())
        .map(|(a, b)| (a + b).rem_euclid(params.q))
        .collect();
    let z = Polynomial { coeff: z_coeff };


    let c = hash_poly_and_message(&z, message);

    if !rejection_sample(&z, params) {
        panic!("Rejection sampling failed");
    }

    Signature { z, c }
}
