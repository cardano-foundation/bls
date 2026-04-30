use assert_cmd::Command;
use hex::decode;
use predicates::prelude::*;
use std::fs;
use tempfile::NamedTempFile;

#[test]
fn generate_seed_produces_32_bytes() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("generate-seed");
    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            let trimmed = output.trim();
            trimmed.len() == 64 && decode(trimmed).is_ok()
        }));
}

#[test]
fn generate_seed_produces_unique_output() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("generate-seed");
    let output1 = cmd.output().unwrap();
    let stdout1 = String::from_utf8_lossy(&output1.stdout);

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("generate-seed");
    let output2 = cmd.output().unwrap();
    let stdout2 = String::from_utf8_lossy(&output2.stdout);

    assert_ne!(stdout1.trim(), stdout2.trim());
}

#[test]
fn hkdf_produces_32_bytes() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("hkdf").write_stdin("deadbeef");
    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            let trimmed = output.trim();
            trimmed.len() == 64 && decode(trimmed).is_ok()
        }));
}

#[test]
fn hkdf_from_stdin() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("hkdf").write_stdin("0102030405");
    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            let trimmed = output.trim();
            trimmed.len() == 64 && decode(trimmed).is_ok()
        }));
}

#[test]
fn hkdf_from_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), "a1b2c3d4").unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("hkdf").arg("--file").arg(temp_file.path());
    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            let trimmed = output.trim();
            trimmed.len() == 64 && decode(trimmed).is_ok()
        }));
}

#[test]
fn hkdf_matches_rfc5869_testcase3() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(
        temp_file.path(),
        "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("hkdf").arg("--file").arg(temp_file.path());
    let output = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);

    let expected = "8da4e775a563c18f715f802a063c5a31";
    assert!(
        stdout.trim().starts_with(expected),
        "expected {}..., got {}",
        expected,
        stdout.trim()
    );
}

#[test]
fn scalar_from_stdin() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("scalar")
        .write_stdin("7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43");
    cmd.assert().success().stdout(predicate::eq(
        "30417370258289878983951032069403093024210548576862328133794263911723866186107",
    ));
}

#[test]
fn scalar_from_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(
        temp_file.path(),
        "7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("scalar").arg("--prv").arg(temp_file.path());
    cmd.assert().success().stdout(predicate::eq(
        "30417370258289878983951032069403093024210548576862328133794263911723866186107",
    ));
}

#[test]
fn scalar_invalid_length() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("scalar").write_stdin("1234");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("private key must be 32 bytes"));
}

#[test]
fn scalar_invalid_value() {
    // Value >= curve order should fail (all 0xFFs = 32 bytes)
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("scalar")
        .write_stdin("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid scalar"));
}

#[test]
fn pk_from_stdin() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pk")
        .write_stdin("7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43");
    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            let trimmed = output.trim();
            trimmed.len() == 96 && decode(trimmed).is_ok()
        }));
}

#[test]
fn pk_from_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(
        temp_file.path(),
        "7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pk").arg("--prv").arg(temp_file.path());
    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            let trimmed = output.trim();
            trimmed.len() == 96 && decode(trimmed).is_ok()
        }));
}

#[test]
fn pk_invalid_length() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pk").write_stdin("1234");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("private key must be 32 bytes"));
}

#[test]
fn pk_invalid_value() {
    // Value >= curve order should fail (all 0xFFs = 32 bytes)
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pk")
        .write_stdin("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid scalar"));
}

#[test]
fn sig_from_stdin() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("sig")
        .arg("--msg")
        .arg("hello world")
        .write_stdin("7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43");
    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            let trimmed = output.trim();
            trimmed.len() == 192 && decode(trimmed).is_ok()
        }));
}

#[test]
fn sig_from_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(
        temp_file.path(),
        "7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("sig")
        .arg("--prv")
        .arg(temp_file.path())
        .arg("--msg")
        .arg("hello world");
    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            let trimmed = output.trim();
            trimmed.len() == 192 && decode(trimmed).is_ok()
        }));
}

#[test]
fn sig_invalid_length() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("sig").arg("--msg").arg("test").write_stdin("1234");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("private key must be 32 bytes"));
}

#[test]
fn sig_invalid_value() {
    // Value >= curve order should fail (all 0xFFs = 32 bytes)
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("sig")
        .arg("--msg")
        .arg("test")
        .write_stdin("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid scalar"));
}

#[test]
fn verify_valid_signature() {
    // Generate a seed, derive private key, generate public key, sign a message, then verify
    let mut cmd_seed = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_seed.arg("generate-seed");
    let seed_output = cmd_seed.output().unwrap();
    let seed = String::from_utf8_lossy(&seed_output.stdout)
        .trim()
        .to_string();

    // Derive private key from seed
    let mut cmd_hkdf = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_hkdf.arg("hkdf").write_stdin(seed.as_bytes());
    let hkdf_output = cmd_hkdf.output().unwrap();
    let private_key = String::from_utf8_lossy(&hkdf_output.stdout)
        .trim()
        .to_string();

    // Generate public key from private key
    let mut cmd_pk = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_pk.arg("pk").write_stdin(private_key.as_bytes());
    let pk_output = cmd_pk.output().unwrap();
    let public_key = String::from_utf8_lossy(&pk_output.stdout)
        .trim()
        .to_string();

    // Save public key to temp file
    let pk_file = NamedTempFile::new().unwrap();
    fs::write(pk_file.path(), public_key.as_bytes()).unwrap();

    // Sign a message
    let mut cmd_sig = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_sig
        .arg("sig")
        .arg("--msg")
        .arg("hello world")
        .write_stdin(private_key.as_bytes());
    let sig_output = cmd_sig.output().unwrap();
    let signature = String::from_utf8_lossy(&sig_output.stdout)
        .trim()
        .to_string();

    // Save signature to temp file
    let sig_file = NamedTempFile::new().unwrap();
    fs::write(sig_file.path(), signature.as_bytes()).unwrap();

    // Verify the signature
    let mut cmd_verify = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_verify
        .arg("verify")
        .arg("--msg")
        .arg("hello world")
        .arg("--sig")
        .arg(sig_file.path())
        .arg("--pk")
        .arg(pk_file.path());
    cmd_verify
        .assert()
        .success()
        .stdout(predicate::str::contains("Verified"));
}

#[test]
fn verify_invalid_signature() {
    // Generate a seed, derive private key, generate public key, sign a message, then verify with wrong message
    let mut cmd_seed = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_seed.arg("generate-seed");
    let seed_output = cmd_seed.output().unwrap();
    let seed = String::from_utf8_lossy(&seed_output.stdout)
        .trim()
        .to_string();

    // Derive private key from seed
    let mut cmd_hkdf = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_hkdf.arg("hkdf").write_stdin(seed.as_bytes());
    let hkdf_output = cmd_hkdf.output().unwrap();
    let private_key = String::from_utf8_lossy(&hkdf_output.stdout)
        .trim()
        .to_string();

    // Generate public key from private key
    let mut cmd_pk = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_pk.arg("pk").write_stdin(private_key.as_bytes());
    let pk_output = cmd_pk.output().unwrap();
    let public_key = String::from_utf8_lossy(&pk_output.stdout)
        .trim()
        .to_string();

    // Save public key to temp file
    let pk_file = NamedTempFile::new().unwrap();
    fs::write(pk_file.path(), public_key.as_bytes()).unwrap();

    // Sign a message
    let mut cmd_sig = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_sig
        .arg("sig")
        .arg("--msg")
        .arg("hello world")
        .write_stdin(private_key.as_bytes());
    let sig_output = cmd_sig.output().unwrap();
    let signature = String::from_utf8_lossy(&sig_output.stdout)
        .trim()
        .to_string();

    // Save signature to temp file
    let sig_file = NamedTempFile::new().unwrap();
    fs::write(sig_file.path(), signature.as_bytes()).unwrap();

    // Verify with wrong message (should fail)
    let mut cmd_verify = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_verify
        .arg("verify")
        .arg("--msg")
        .arg("wrong message")
        .arg("--sig")
        .arg(sig_file.path())
        .arg("--pk")
        .arg(pk_file.path());
    cmd_verify
        .assert()
        .success()
        .stdout(predicate::str::contains("Not Verified"));
}
