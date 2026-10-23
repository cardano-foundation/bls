#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use alloc::vec::Vec;
use uplc_guest::{eval_flat, Data};

const HELLO_HASH_FLAT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../hello-world/hello_hash.flat"
));

#[jolt::provable(heap_size = 32768, max_trace_length = 65536)]
fn uplc_hello_hash_aiken() -> [u8; 32] {
    let value = eval_flat(
        HELLO_HASH_FLAT,
        &[Data::B(Vec::from(b"Hello, world!".as_slice()))],
    )
    .expect("UPLC evaluation failed");
    let digest = value.as_bytes().expect("result is not a bytestring");
    let mut output = [0u8; 32];
    output.copy_from_slice(digest);
    output
}
