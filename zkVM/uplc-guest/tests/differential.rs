use std::{fs, process::Command};

use uplc_guest::{eval_flat, Data};

const HELLO_HASH_FLAT: &[u8] = include_bytes!("../../hello-world/hello_hash.flat");
const EXPECTED_DIGEST: &str = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";

const HELLO_DATA_UPLC: &str = r#"(program 1.1.0 [
  (lam i_0 [ (builtin sha2_256) [ (builtin unBData) i_0 ] ])
  (con data (B #48656c6c6f2c20776f726c6421))
])
"#;

fn evaluate_hello_hash() -> String {
    eval_flat(HELLO_HASH_FLAT, &[Data::B(b"Hello, world!".to_vec())])
        .expect("evaluator failed")
        .to_hex_string()
        .expect("result is not a bytestring")
}

#[test]
fn hello_hash_matches_expected_digest() {
    assert_eq!(evaluate_hello_hash(), EXPECTED_DIGEST);
}

#[test]
fn hello_hash_matches_aiken() {
    if Command::new("aiken").arg("--version").output().is_err() {
        eprintln!("aiken not found; skipping differential check");
        return;
    }

    let path = std::env::temp_dir().join("uplc-guest-hello-data.uplc");
    fs::write(&path, HELLO_DATA_UPLC).unwrap();

    let output = Command::new("aiken")
        .args(["uplc", "eval"])
        .arg(&path)
        .output()
        .expect("failed to run aiken uplc eval");
    assert!(
        output.status.success(),
        "aiken uplc eval failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let hash_start = stdout.find('#').expect("aiken output has no hex result") + 1;
    let aiken_digest = &stdout[hash_start..hash_start + 64];

    assert_eq!(evaluate_hello_hash(), aiken_digest);
}
