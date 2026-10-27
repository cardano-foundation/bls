use std::{fs, process::Command};

use uplc_guest::{eval_flat, Data};

const HELLO_HASH_FLAT: &[u8] = include_bytes!("../../hello-world/hello_hash.flat");
const EXPECTED_DIGEST: &str = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";

const HELLO_DATA_UPLC: &str = r#"(program 1.1.0 [
  (lam i_0 [ (builtin sha2_256) [ (builtin unBData) i_0 ] ])
  (con data (B #48656c6c6f2c20776f726c6421))
])
"#;

fn aiken_available() -> bool {
    Command::new("aiken").arg("--version").output().is_ok()
}

fn tmp_file(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("uplc-guest-{name}"))
}

fn aiken_eval(uplc: &str, name: &str) -> String {
    let path = tmp_file(&format!("{name}.uplc"));
    fs::write(&path, uplc).unwrap();

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
    extract_json_result(&stdout)
}

fn aiken_encode(uplc: &str, name: &str) -> Vec<u8> {
    let uplc_path = tmp_file(&format!("{name}.uplc"));
    fs::write(&uplc_path, uplc).unwrap();

    let output = Command::new("aiken")
        .args(["uplc", "encode", "-c"])
        .arg(&uplc_path)
        .output()
        .expect("failed to run aiken uplc encode");
    assert!(
        output.status.success(),
        "aiken uplc encode failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    output.stdout
}

fn extract_json_result(stdout: &str) -> String {
    let key = "\"result\": \"";
    let start = stdout
        .find(key)
        .unwrap_or_else(|| panic!("aiken output has no result field: {stdout}"))
        + key.len();
    let end = stdout[start..]
        .find('"')
        .unwrap_or_else(|| panic!("unterminated result field: {stdout}"));
    stdout[start..start + end].to_string()
}

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
    if !aiken_available() {
        eprintln!("aiken not found; skipping differential check");
        return;
    }

    let value = evaluate_hello_hash();
    let aiken_result = aiken_eval(HELLO_DATA_UPLC, "hello-data");
    let hash_start = aiken_result.find('#').expect("aiken output has no hex result") + 1;
    let aiken_digest = &aiken_result[hash_start..hash_start + 64];

    assert_eq!(value, aiken_digest);
}

#[test]
fn bytearray_append_matches_aiken() {
    if !aiken_available() {
        return;
    }

    let uplc = r#"(program 1.1.0 [
  (builtin appendByteString)
  (con bytestring #48656c6c6f2c20776f726c6421)
  (con bytestring #21)
])
"#;

    let flat = aiken_encode(uplc, "append");
    let value = eval_flat(&flat, &[]).expect("evaluator failed");
    let expected_hex = extract_bytestring_hex(&aiken_eval(uplc, "append"));
    assert_eq!(value.to_hex_string().unwrap(), expected_hex);
}

#[test]
fn bytearray_slice_matches_aiken() {
    if !aiken_available() {
        return;
    }

    let uplc = r#"(program 1.1.0 [
  (builtin sliceByteString)
  (con integer 1)
  (con integer 4)
  (con bytestring #48656c6c6f2c20776f726c6421)
])
"#;

    let flat = aiken_encode(uplc, "slice");
    let value = eval_flat(&flat, &[]).expect("evaluator failed");
    let expected_hex = extract_bytestring_hex(&aiken_eval(uplc, "slice"));
    assert_eq!(value.to_hex_string().unwrap(), expected_hex);
}

#[test]
fn integer_add_matches_aiken() {
    if !aiken_available() {
        return;
    }

    let uplc = r#"(program 1.1.0 [
  (builtin addInteger)
  (con integer -7)
  (con integer 3)
])
"#;

    let flat = aiken_encode(uplc, "add");
    let value = eval_flat(&flat, &[]).expect("evaluator failed");
    let expected = extract_integer(&aiken_eval(uplc, "add"));
    assert_eq!(value.as_integer().unwrap().to_string(), expected);
}

#[test]
fn integer_divide_matches_aiken() {
    if !aiken_available() {
        return;
    }

    let uplc = r#"(program 1.1.0 [
  (builtin divideInteger)
  (con integer -7)
  (con integer 3)
])
"#;

    let flat = aiken_encode(uplc, "div");
    let value = eval_flat(&flat, &[]).expect("evaluator failed");
    let expected = extract_integer(&aiken_eval(uplc, "div"));
    assert_eq!(value.as_integer().unwrap().to_string(), expected);
}

#[test]
fn integer_less_than_matches_aiken() {
    if !aiken_available() {
        return;
    }

    let uplc = r#"(program 1.1.0 [
  (builtin lessThanInteger)
  (con integer -7)
  (con integer 3)
])
"#;

    let flat = aiken_encode(uplc, "lt");
    let value = eval_flat(&flat, &[]).expect("evaluator failed");
    let expected = aiken_eval(uplc, "lt").contains("True");
    match value {
        uplc_guest::Value::Con(uplc_guest::Constant::Bool(b)) => assert_eq!(b, expected),
        other => panic!("expected bool, got {}", other.describe()),
    }
}

fn extract_bytestring_hex(result: &str) -> String {
    let hash_start = result.find('#').expect("aiken output has no hex result") + 1;
    result[hash_start..].trim_end_matches(')').to_string()
}

fn extract_integer(result: &str) -> String {
    let start = result
        .find("integer ")
        .expect("aiken output has no integer") + 8;
    result[start..].trim_end_matches(')').to_string()
}
