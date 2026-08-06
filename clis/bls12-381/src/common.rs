//! Common utilities for seed generation

use rand::Rng;

/// Generate cryptographically secure random seed bytes
///
/// Fills the provided buffer with random bytes using the thread RNG.
pub fn generate_crypto_secure_seed(seed_bytes: &mut [u8]) {
    let mut rng = rand::thread_rng();
    rng.fill(seed_bytes);
}
