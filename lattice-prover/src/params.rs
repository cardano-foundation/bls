use lattirust_arithmetic::ring::Z2_64;

/// Lova folding scheme parameters.
///
/// All arithmetic runs over `Z_q` with `q = 2^64`.
/// The witness is split into chunks of size `B`, and the error/slack
/// is written in base-`b` digits, each bounded by `b`.
#[derive(Debug, Clone)]
pub struct LovaParams {
    /// Commitment matrix A has dimensions `m × n`.
    pub m: usize,
    /// Commitment matrix A has dimensions `m × n`.
    pub n: usize,
    /// Witness chunk size `B`.
    pub witness_chunk_size: usize,
    /// Decomposition base `b`.
    pub decompose_base: u64,
    /// Number of decomposition digits `k`.
    pub decompose_digits: usize,
    /// Infinity-norm bound on the witness chunks.
    pub witness_norm_bound: u64,
    /// Infinity-norm bound on the error/slack.
    pub error_norm_bound: u64,
    /// Number of folding rounds.
    pub num_rounds: usize,
}

impl Default for LovaParams {
    fn default() -> Self {
        Self {
            m: 256,
            n: 128,
            witness_chunk_size: 32,
            decompose_base: 2,
            decompose_digits: 64,
            witness_norm_bound: 1 << 31,
            error_norm_bound: 1 << 31,
            num_rounds: 32,
        }
    }
}

impl LovaParams {
    /// The modulus `q = 2^64`.
    pub const Q: u64 = u64::MAX; // wrapping: 2^64 mod 2^64 = 0, but we use Z2_64 which handles this

    /// Create small toy parameters for unit tests.
    pub fn toy() -> Self {
        Self {
            m: 16,
            n: 8,
            witness_chunk_size: 4,
            decompose_base: 2,
            decompose_digits: 16,
            witness_norm_bound: (1 << 8) - 1,
            error_norm_bound: (1 << 8) - 1,
            num_rounds: 4,
        }
    }

    /// Verify that the parameters satisfy the Lova norm constraint:
    /// `2 * k * b * sqrt(m) <= beta` where `beta` is the witness norm bound.
    pub fn check_norm_constraint(&self) -> bool {
        let lhs = 2.0
            * self.decompose_digits as f64
            * self.decompose_base as f64
            * (self.m as f64).sqrt();
        lhs <= self.witness_norm_bound as f64
    }
}

/// A commitment consisting of an Ajtai hash (vector over Z_{2^64}).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AjtaiCommitment {
    pub values: Vec<Z2_64>,
}
