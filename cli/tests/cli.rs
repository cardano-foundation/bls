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
