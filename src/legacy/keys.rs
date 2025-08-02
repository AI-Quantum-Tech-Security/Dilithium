// src/dilithium/keys.rs

use rand::Rng;
use crate::dilithium::params::DilithiumParams;
use crate::dilithium::poly::Polynomial;

#[derive(Debug)]
pub struct PublicKey {
    pub poly: Polynomial,
}

#[derive(Debug)]
pub struct SecretKey {
    pub poly: Polynomial,
}

pub fn keygen(params: &DilithiumParams) -> (PublicKey, SecretKey) {
    let n = params.n;
    let mut rng = rand::thread_rng();

    let secret_poly = Polynomial {
        coeff: (0..n)
            .map(|_| rng.gen_range(-params.eta..=params.eta))
            .collect(),
    };
    let public_poly = Polynomial {
        coeff: (0..n).map(|_| rng.gen_range(0..params.q)).collect(),
    };

    (PublicKey { poly: public_poly }, SecretKey { poly: secret_poly })
}
