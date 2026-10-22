#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_main)]
#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_std)]

extern crate alloc;

use alloc::{format, string::String};
use openvm_sha2::{Digest, Sha256};

openvm::entry!(main);

fn println(s: String) {
    #[cfg(target_os = "zkvm")]
    openvm::io::println(s);
    #[cfg(not(target_os = "zkvm"))]
    println!("{}", s);
}

pub fn main() {
    let mut hasher = Sha256::new();
    hasher.update(b"Hello, world!");
    let digest: [u8; 32] = hasher.finalize().into();

    println(format!("Hello, world! sha256 = {}", hex(&digest)));

    // Publish the digest as the public output. This is the only value a
    // verifier sees, and the Aiken side can recompute it independently.
    #[cfg(target_os = "zkvm")]
    openvm::io::reveal_bytes32(digest);
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
