
#[derive(Debug, Clone)]
pub struct DilithiumParams {
    pub k: usize,
    pub l: usize,
    pub n: usize,
    pub q: i64,
    pub eta: i64,
}

impl Default for DilithiumParams {
    fn default() -> Self {
        DilithiumParams { k: 4, l: 4, n: 256, q: 8380417, eta: 2 }
    }
}
