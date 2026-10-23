#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_main)]
#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

use uplc_guest::{eval_flat, Data};

const HELLO_HASH_FLAT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../hello-world/hello_hash.flat"
));

openvm::entry!(main);

pub fn main() {
    let value = eval_flat(
        HELLO_HASH_FLAT,
        &[Data::B(Vec::from(b"Hello, world!".as_slice()))],
    )
    .expect("UPLC evaluation failed");
    let digest = value.as_bytes().expect("result is not a bytestring");

    let mut output = [0u8; 32];
    output.copy_from_slice(digest);

    println(format!(
        "UPLC hello_hash(Hello, world!) sha256 = {}",
        hex(&output)
    ));

    #[cfg(target_os = "zkvm")]
    openvm::io::reveal_bytes32(output);
}

fn println(s: String) {
    #[cfg(target_os = "zkvm")]
    openvm::io::println(s);
    #[cfg(not(target_os = "zkvm"))]
    std::println!("{}", s);
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
