#![cfg_attr(feature = "guest", no_std)]

use jolt_inlines_sha2::Sha256;

/// Computes `SHA-256("Hello, world!")` and reveals it as the public output.
///
/// The digest is deterministic, so the host (and later the Aiken on-chain
/// verifier) can recompute it independently and compare.
#[jolt::provable(heap_size = 32768, max_trace_length = 65536)]
fn hello_world() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"Hello, world!");
    hasher.finalize()
}
