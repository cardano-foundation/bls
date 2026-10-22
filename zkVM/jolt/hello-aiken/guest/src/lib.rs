#![cfg_attr(feature = "guest", no_std)]

use jolt_inlines_sha2::Sha256;

#[jolt::provable(heap_size = 32768, max_trace_length = 65536)]
fn hello_hash_aiken() -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"Hello, world!");
    hasher.finalize()
}
