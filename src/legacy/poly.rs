use crate::dilithium::params::DilithiumParams;

#[derive(Debug, Clone)]
pub struct Polynomial {
    pub coeff: Vec<i64>,
}

impl Polynomial {
    pub fn new(n: usize) -> Self {
        Polynomial {
            coeff: vec![0; n],
        }
    }

    pub fn mul(&self, other: &Self, params: &DilithiumParams) -> Self {
        let n = params.n;
        let mut result = vec![0i64; n];
        for i in 0..n {
            for j in 0..n {
                let index = (i + j) % n;
                result[index] = (result[index] + self.coeff[i] * other.coeff[j]) % params.q;
            }
        }
        Polynomial { coeff: result }
    }
}
