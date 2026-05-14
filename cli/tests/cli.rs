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
            trimmed.len() == 66 && trimmed.starts_with("0x") && decode(&trimmed[2..]).is_ok()
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
            trimmed.len() == 66 && trimmed.starts_with("0x") && decode(&trimmed[2..]).is_ok()
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
            trimmed.len() == 66 && trimmed.starts_with("0x") && decode(&trimmed[2..]).is_ok()
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
            trimmed.len() == 66 && trimmed.starts_with("0x") && decode(&trimmed[2..]).is_ok()
        }));
}

#[test]
fn scalar_from_stdin() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("scalar")
        .write_stdin("0x7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43");
    cmd.assert().success().stdout(predicate::eq(
        "30417370258289878983951032069403093024210548576862328133794263911723866186107",
    ));
}

#[test]
fn scalar_from_stdin_decimal() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("scalar").write_stdin("1234");
    cmd.assert().success().stdout(predicate::eq("1234"));
}

#[test]
fn scalar_from_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(
        temp_file.path(),
        "0x7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43",
    )
    .unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("scalar").arg("--prv").arg(temp_file.path());
    cmd.assert().success().stdout(predicate::eq(
        "30417370258289878983951032069403093024210548576862328133794263911723866186107",
    ));
}

#[test]
fn scalar_invalid_input() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("scalar").write_stdin("not_a_number");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid decimal scalar"));
}

#[test]
fn scalar_invalid_value() {
    // Value >= curve order should fail (all 0xFFs = 32 bytes)
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("scalar")
        .write_stdin("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
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
            trimmed.len() == 98 && trimmed.starts_with("0x") && decode(&trimmed[2..]).is_ok()
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
            trimmed.len() == 98 && trimmed.starts_with("0x") && decode(&trimmed[2..]).is_ok()
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
            trimmed.len() == 194 && trimmed.starts_with("0x") && decode(&trimmed[2..]).is_ok()
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
            trimmed.len() == 194 && trimmed.starts_with("0x") && decode(&trimmed[2..]).is_ok()
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
    // Use a known-valid private key
    let private_key = "7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43";

    // Generate public key from private key
    let mut cmd_pk = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_pk.arg("pk").write_stdin(private_key.as_bytes());
    let pk_output = cmd_pk.output().unwrap();
    assert!(
        pk_output.status.success(),
        "pk command failed: {}",
        String::from_utf8_lossy(&pk_output.stderr)
    );
    let public_key = String::from_utf8_lossy(&pk_output.stdout)
        .trim()
        .to_string();
    assert!(!public_key.is_empty(), "Public key is empty");

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
    assert!(
        sig_output.status.success(),
        "sig command failed: {}",
        String::from_utf8_lossy(&sig_output.stderr)
    );
    let signature = String::from_utf8_lossy(&sig_output.stdout)
        .trim()
        .to_string();
    assert!(!signature.is_empty(), "Signature is empty");

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
    // Use a known-valid private key
    let private_key = "7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43";

    // Generate public key from private key
    let mut cmd_pk = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_pk.arg("pk").write_stdin(private_key.as_bytes());
    let pk_output = cmd_pk.output().unwrap();
    assert!(
        pk_output.status.success(),
        "pk command failed: {}",
        String::from_utf8_lossy(&pk_output.stderr)
    );
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
    assert!(
        sig_output.status.success(),
        "sig command failed: {}",
        String::from_utf8_lossy(&sig_output.stderr)
    );
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

#[test]
fn compress_g1_compressed_generator() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("compress").arg("--g1").write_stdin(G1_GENERATOR);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G1_GENERATOR)));
}

#[test]
fn compress_g2_compressed_generator() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("compress").arg("--g2").write_stdin(G2_GENERATOR);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G2_GENERATOR)));
}

#[test]
fn compress_g1_identity() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("compress")
        .arg("--g1")
        .arg("--point")
        .arg("identity");
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G1_IDENTITY)));
}

#[test]
fn compress_g2_identity() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("compress")
        .arg("--g2")
        .arg("--point")
        .arg("identity");
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G2_IDENTITY)));
}

#[test]
fn compress_g1_from_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), G1_GENERATOR).unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("compress")
        .arg("--g1")
        .arg("--point")
        .arg(temp_file.path());
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G1_GENERATOR)));
}

#[test]
fn compress_g2_from_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), G2_GENERATOR).unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("compress")
        .arg("--g2")
        .arg("--point")
        .arg(temp_file.path());
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G2_GENERATOR)));
}

#[test]
fn compress_invalid_point() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("compress")
        .arg("--g1")
        .write_stdin("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid G1 compressed point"));
}

#[test]
fn compress_missing_group() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("compress").write_stdin(G1_GENERATOR);
    cmd.assert().failure().stderr(predicate::str::contains(
        "the following required arguments were not provided",
    ));
}

#[test]
fn compress_wrong_point_length_for_g1() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("compress").arg("--g1").write_stdin("00");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid G1 point length"));
}

#[test]
fn compress_wrong_point_length_for_g2() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("compress").arg("--g2").write_stdin("00");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid G2 point length"));
}

#[test]
fn uncompress_g1_generator() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("uncompress").arg("--g1").write_stdin(G1_GENERATOR);
    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            let trimmed = output.trim();
            trimmed.len() == 194 && trimmed.starts_with("0x") && decode(&trimmed[2..]).is_ok()
        }));
}

#[test]
fn uncompress_g2_generator() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("uncompress").arg("--g2").write_stdin(G2_GENERATOR);
    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            let trimmed = output.trim();
            trimmed.len() == 386 && trimmed.starts_with("0x") && decode(&trimmed[2..]).is_ok()
        }));
}

#[test]
fn uncompress_g1_identity() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("uncompress")
        .arg("--g1")
        .arg("--point")
        .arg("identity");
    // Uncompressed identity is all zeros (192 hex chars)
    let expected = format!("0x{}", "00".repeat(96));
    cmd.assert().success().stdout(predicate::eq(expected));
}

#[test]
fn uncompress_g2_identity() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("uncompress")
        .arg("--g2")
        .arg("--point")
        .arg("identity");
    // Uncompressed identity is all zeros (384 hex chars)
    let expected = format!("0x{}", "00".repeat(192));
    cmd.assert().success().stdout(predicate::eq(expected));
}

#[test]
fn uncompress_g1_from_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), G1_GENERATOR).unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("uncompress")
        .arg("--g1")
        .arg("--point")
        .arg(temp_file.path());
    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            let trimmed = output.trim();
            trimmed.len() == 194 && trimmed.starts_with("0x") && decode(&trimmed[2..]).is_ok()
        }));
}

#[test]
fn uncompress_g2_from_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), G2_GENERATOR).unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("uncompress")
        .arg("--g2")
        .arg("--point")
        .arg(temp_file.path());
    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            let trimmed = output.trim();
            trimmed.len() == 386 && trimmed.starts_with("0x") && decode(&trimmed[2..]).is_ok()
        }));
}

#[test]
fn uncompress_invalid_point() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("uncompress")
        .arg("--g1")
        .write_stdin("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid G1 compressed point"));
}

#[test]
fn uncompress_missing_group() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("uncompress").write_stdin(G1_GENERATOR);
    cmd.assert().failure().stderr(predicate::str::contains(
        "the following required arguments were not provided",
    ));
}

#[test]
fn uncompress_wrong_point_length() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("uncompress").arg("--g1").write_stdin("00");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid G1 point length"));
}

// G1 generator compressed (48 bytes)
const G1_GENERATOR: &str = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

// G2 generator compressed (96 bytes)
const G2_GENERATOR: &str = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

// Negated G1 generator compressed (48 bytes)
const NEG_G1_GENERATOR: &str = "b7f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

// Negated G2 generator compressed (96 bytes)
const NEG_G2_GENERATOR: &str = "b3e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

// Scalar value 1 (32 bytes, little-endian encoding, hex with 0x prefix)
const SCALAR_ONE: &str = "0x0100000000000000000000000000000000000000000000000000000000000000";

#[test]
fn mul_g1_generator_times_one() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("mul")
        .arg("--g1")
        .arg("--scalar")
        .arg(SCALAR_ONE)
        .write_stdin(G1_GENERATOR);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G1_GENERATOR)));
}

#[test]
fn mul_g1_from_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), G1_GENERATOR).unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("mul")
        .arg("--g1")
        .arg("--point")
        .arg(temp_file.path())
        .arg("--scalar")
        .arg(SCALAR_ONE);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G1_GENERATOR)));
}

#[test]
fn mul_g2_generator_times_one() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("mul")
        .arg("--g2")
        .arg("--scalar")
        .arg(SCALAR_ONE)
        .write_stdin(G2_GENERATOR);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G2_GENERATOR)));
}

#[test]
fn mul_g2_from_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), G2_GENERATOR).unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("mul")
        .arg("--g2")
        .arg("--point")
        .arg(temp_file.path())
        .arg("--scalar")
        .arg(SCALAR_ONE);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G2_GENERATOR)));
}

#[test]
fn mul_g1_identity_times_scalar() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("mul")
        .arg("--g1")
        .arg("--scalar")
        .arg(SCALAR_ONE)
        .write_stdin(G1_IDENTITY);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G1_IDENTITY)));
}

#[test]
fn mul_g2_identity_times_scalar() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("mul")
        .arg("--g2")
        .arg("--scalar")
        .arg(SCALAR_ONE)
        .write_stdin(G2_IDENTITY);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G2_IDENTITY)));
}

#[test]
fn mul_g1_matches_pk() {
    let private_key = "7be162d67564e3b4c09655baaabecc3725748133e33ab971e565737f189f3f43";

    // Get the expected public key using the pk command
    let mut cmd_pk = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_pk.arg("pk").write_stdin(private_key.as_bytes());
    let pk_output = cmd_pk.output().unwrap();
    assert!(pk_output.status.success());
    let expected_pk = String::from_utf8_lossy(&pk_output.stdout)
        .trim()
        .to_string();

    // Now multiply G1 generator by the same private key scalar (with 0x prefix)
    let mut cmd_mul = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_mul
        .arg("mul")
        .arg("--g1")
        .arg("--scalar")
        .arg(format!("0x{}", private_key))
        .write_stdin(G1_GENERATOR);
    cmd_mul
        .assert()
        .success()
        .stdout(predicate::eq(expected_pk));
}

#[test]
fn mul_invalid_point() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("mul")
        .arg("--g1")
        .arg("--scalar")
        .arg(SCALAR_ONE)
        .write_stdin("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid G1 compressed point"));
}

#[test]
fn mul_invalid_scalar() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("mul")
        .arg("--g1")
        .arg("--scalar")
        .arg("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        .write_stdin(G1_GENERATOR);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid scalar"));
}

#[test]
fn mul_missing_group() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("mul")
        .arg("--scalar")
        .arg(SCALAR_ONE)
        .write_stdin(G1_GENERATOR);
    cmd.assert().failure().stderr(predicate::str::contains(
        "the following required arguments were not provided",
    ));
}

#[test]
fn mul_wrong_point_length_for_g1() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("mul")
        .arg("--g1")
        .arg("--scalar")
        .arg(SCALAR_ONE)
        .write_stdin("00"); // too short
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid point length"));
}

#[test]
fn mul_wrong_point_length_for_g2() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("mul")
        .arg("--g2")
        .arg("--scalar")
        .arg(SCALAR_ONE)
        .write_stdin("00"); // too short
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid point length"));
}

// G1 identity compressed (48 bytes, first byte 0xc0)
const G1_IDENTITY: &str = "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

// G2 identity compressed (96 bytes, first byte 0xc0)
const G2_IDENTITY: &str = "c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

#[test]
fn add_g1_identity_plus_generator() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("add")
        .arg("--g1")
        .arg("--point_right")
        .arg(G1_GENERATOR)
        .write_stdin(G1_IDENTITY);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G1_GENERATOR)));
}

#[test]
fn add_g1_generator_plus_identity() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("add")
        .arg("--g1")
        .arg("--point_left")
        .arg("identity")
        .arg("--point_right")
        .arg(G1_GENERATOR);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G1_GENERATOR)));
}

#[test]
fn add_g2_identity_plus_generator() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("add")
        .arg("--g2")
        .arg("--point_right")
        .arg(G2_GENERATOR)
        .write_stdin(G2_IDENTITY);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G2_GENERATOR)));
}

#[test]
fn add_g2_generator_plus_identity() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("add")
        .arg("--g2")
        .arg("--point_left")
        .arg("identity")
        .arg("--point_right")
        .arg(G2_GENERATOR);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G2_GENERATOR)));
}

#[test]
fn add_g1_both_identity() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("add")
        .arg("--g1")
        .arg("--point_left")
        .arg("identity")
        .arg("--point_right")
        .arg("identity");
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G1_IDENTITY)));
}

#[test]
fn add_g2_both_identity() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("add")
        .arg("--g2")
        .arg("--point_left")
        .arg("identity")
        .arg("--point_right")
        .arg("identity");
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G2_IDENTITY)));
}

#[test]
fn add_g1_from_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), G1_GENERATOR).unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("add")
        .arg("--g1")
        .arg("--point_left")
        .arg(temp_file.path())
        .arg("--point_right")
        .arg("identity");
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G1_GENERATOR)));
}

#[test]
fn add_g2_from_file() {
    let temp_file = NamedTempFile::new().unwrap();
    fs::write(temp_file.path(), G2_GENERATOR).unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("add")
        .arg("--g2")
        .arg("--point_left")
        .arg(temp_file.path())
        .arg("--point_right")
        .arg("identity");
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", G2_GENERATOR)));
}

#[test]
fn add_missing_group() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("add")
        .arg("--point_right")
        .arg(G1_GENERATOR)
        .write_stdin(G1_IDENTITY);
    cmd.assert().failure().stderr(predicate::str::contains(
        "the following required arguments were not provided",
    ));
}

#[test]
fn add_invalid_point() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("add")
        .arg("--g1")
        .arg("--point_right")
        .arg("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000")
        .write_stdin(G1_GENERATOR);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid G1 compressed point"));
}

#[test]
fn add_wrong_point_length() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("add")
        .arg("--g1")
        .arg("--point_right")
        .arg("00") // too short
        .write_stdin(G1_IDENTITY);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid right point length"));
}

// Pairing command tests
const G1_GENERATOR_UNCOMPRESSED: &str = "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1";
const G2_GENERATOR_UNCOMPRESSED: &str = "13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801";
const G1_IDENTITY_UNCOMPRESSED: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
const G2_IDENTITY_UNCOMPRESSED: &str = "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

const THIRTEEN_G1_COMPRESSED: &str = "0x851f8a0b82a6d86202a61cbc3b0f3db7d19650b914587bde4715ccd372e1e40cab95517779d840416e1679c84a6db24e";
const THIRTEEN_G1_UNCOMPRESSED: &str = "0x051f8a0b82a6d86202a61cbc3b0f3db7d19650b914587bde4715ccd372e1e40cab95517779d840416e1679c84a6db24e0b6a63ac48b7d7666ccfcf1e7de0097c5e6e1aacd03507d23fb975d8daec42857b3a471bf3fc471425b63864e045f4df";
const TWO_G1_COMPRESSED: &str = "0xa572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e";
const TWO_G1_UNCOMPRESSED: &str = "0x0572cbea904d67468808c8eb50a9450c9721db309128012543902d0ac358a62ae28f75bb8f1c7c42c39a8c5529bf0f4e166a9d8cabc673a322fda673779d8e3822ba3ecb8670e461f73bb9021d5fd76a4c56d9d4cd16bd1bba86881979749d28";
const TWO_G2_COMPRESSED: &str = "0xaa4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a053";
const TWO_G2_UNCOMPRESSED: &str = "0x0a4edef9c1ed7f729f520e47730a124fd70662a904ba1074728114d1031e1572c6c886f6b57ec72a6178288c47c335771638533957d540a9d2370f17cc7ed5863bc0b995b8825e0ee1ea1e1e4d00dbae81f14b0bf3611b78c952aacab827a0530f6d4552fa65dd2638b361543f887136a43253d9c66c411697003f7a13c308f5422e1aa0a59c8967acdefd8b6e36ccf30468fb440d82b0630aeb8dca2b5256789a66da69bf91009cbfe6bd221e47aa8ae88dece9764bf3bd999d95d71e4c9899";
const THIRTEEN_G2_COMPRESSED: &str = "0x8bf78a97086750eb166986ed8e428ca1d23ae3bbf8b2ee67451d7dd84445311e8bc8ab558b0bc008199f577195fc39b7152110e866f1a6e8c5348f6e005dbd93de671b7d0fbfa04d6614bcdd27a3cb2a70f0deacb3608ba95226268481a0be7c";
const THIRTEEN_G2_UNCOMPRESSED: &str = "0x0bf78a97086750eb166986ed8e428ca1d23ae3bbf8b2ee67451d7dd84445311e8bc8ab558b0bc008199f577195fc39b7152110e866f1a6e8c5348f6e005dbd93de671b7d0fbfa04d6614bcdd27a3cb2a70f0deacb3608ba95226268481a0be7c0a298f69fd652551e12219252baacab101768fc6651309450e49c7d3bb52b7547f218d12de64961aa7f059025b8e0cb50845be51ad0d708657bfb0da8eec64cd7779c50d90b59a3ac6a2045cad0561d654af9a84dd105cea5409d2adf286b561";
const TWENTY_SIX_G2_COMPRESSED: &str = "0x8bb319a4550c981ee89e3c7e6dcc434283454847792807940f72fd2dbf3625b092e0a0c03e581fd9bd9cf74f95ccef150029ea93c2f1eb48b195815571ea0148198ff1b19462618cab08d037646b592ecab5a66b4bc660ffd02d1b996ca377da";
const TWENTY_SIX_G2_UNCOMPRESSED: &str = "0x0bb319a4550c981ee89e3c7e6dcc434283454847792807940f72fd2dbf3625b092e0a0c03e581fd9bd9cf74f95ccef150029ea93c2f1eb48b195815571ea0148198ff1b19462618cab08d037646b592ecab5a66b4bc660ffd02d1b996ca377da05d04aa0b644faae17d4c76a14aa680c69fdfc6b59fee3ef45641f566165fced60cbbda4ca096e132bb6f58ab45166860abb072b8d9011e81c9f5b23ba86fdb6399c878aa4eadee45fb2486afe594dffc53be643598a23e5428894a36f5ac3ce";

fn pairing_expected_gt() -> String {
    "0xc5851fa033e47219382577fd762bd397f9cd6bc96f54cec81406d466733ef6ce80378481273411a625d8c63f8a44f31395699d2eb03163d27d7e79f782a4689d92ea398d24299b9caa0731e1a21c80f466b0bcbd32076ca1780436baafa43c0841b61609db61e2590d963eb2f4b61627459cbda0105be5c8a8ed4d9cd90bdb0bc5aafd57bf9ef88c5e7a779e92b7d612355fe1b08851c85f6563098f3a6ea0342cd62ae0a62631db0b999a7da95a6ffc10c289ebf5552fa189886f923a70231778878271298f58938575ab11865bf643df9f27ecf5aa8331f69dc98ae1d773fab0994ca6a676e1641f8f38588ca79f1712ef2aca110a2a676bf1a32ab5b9110d6e059d69d01244a4a55b1a2277011dc02955736cdecee06639c3dd9f1ea7f50579c662b0a1880ad30483fc355d6ac55a0d291fa8a634c8d0c70737dac23054cdf00a5080f77fc2f0ae2ed7e2a65d240956511b7976062e9f13fe184923c8d1e2f41b563c9f459e4cc1e3d3b9535ee8a32000a7211e120a82cc9ac5418361af15b13a99248c65957cb986a81c7238eb73bc34744749d756528b4a50ea0219a48b6dce860cf8d3a304aa6e68fb874aa61826cf20b91be783bb4539a792ac77522aa046f0949fe50efcf7586078f3cd5871f645f9821b06c17c67e5db9faa47f80357e63461a5db78806e8a99439aecd71c6637991a9a59aab144ee42082ff6a0c9fadf05b6e39b158ec23ff14a0dba860cb1ff526aa0f20fe86c901a7248ca94761485b0033e188375e2e4ce40ddaf67f5fca526e5d2966d9a42221f86499f7e19".to_string()
}

#[test]
fn pairing_g1_stdin_g2_flag() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pairing")
        .arg("--g2")
        .arg(G2_GENERATOR_UNCOMPRESSED)
        .write_stdin(G1_GENERATOR_UNCOMPRESSED);
    cmd.assert()
        .success()
        .stdout(predicate::eq(pairing_expected_gt()));
}

#[test]
fn pairing_g2_stdin_g1_flag() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pairing")
        .arg("--g1")
        .arg(G1_GENERATOR_UNCOMPRESSED)
        .write_stdin(G2_GENERATOR_UNCOMPRESSED);
    cmd.assert()
        .success()
        .stdout(predicate::eq(pairing_expected_gt()));
}

#[test]
fn pairing_both_flags() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pairing")
        .arg("--g1")
        .arg(G1_GENERATOR_UNCOMPRESSED)
        .arg("--g2")
        .arg(G2_GENERATOR_UNCOMPRESSED);
    cmd.assert()
        .success()
        .stdout(predicate::eq(pairing_expected_gt()));
}

#[test]
fn pairing_both_files() {
    use std::io::Write;
    use tempfile::NamedTempFile;

    let mut g1_file = NamedTempFile::new().unwrap();
    write!(g1_file, "{}", G1_GENERATOR_UNCOMPRESSED).unwrap();
    let mut g2_file = NamedTempFile::new().unwrap();
    write!(g2_file, "{}", G2_GENERATOR_UNCOMPRESSED).unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pairing")
        .arg("--g1-file")
        .arg(g1_file.path())
        .arg("--g2-file")
        .arg(g2_file.path());
    cmd.assert()
        .success()
        .stdout(predicate::eq(pairing_expected_gt()));
}

#[test]
fn pairing_g1_identity() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pairing")
        .arg("--g1")
        .arg(G1_IDENTITY_UNCOMPRESSED)
        .arg("--g2")
        .arg(G2_GENERATOR_UNCOMPRESSED);
    cmd.assert().success();
}

#[test]
fn pairing_g2_identity() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pairing")
        .arg("--g1")
        .arg(G1_GENERATOR_UNCOMPRESSED)
        .arg("--g2")
        .arg(G2_IDENTITY_UNCOMPRESSED);
    cmd.assert().success();
}

#[test]
fn pairing_both_identity() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pairing")
        .arg("--g1")
        .arg(G1_IDENTITY_UNCOMPRESSED)
        .arg("--g2")
        .arg(G2_IDENTITY_UNCOMPRESSED);
    cmd.assert().success();
}

fn pairing_xy_26_expected() -> String {
    "0x0390df3dd3d5a63d5c7c2f911b665b134df8eb3ada0181d15aec93e1dd2e783cf47d0f47eeb642c68a566e9d00b30817a879e82adb993a1efb41c4a807c1c707762b102ee490de8ab6a32211c029f019ea8e743edf34e61b0c8ecd6df6566300ed58a2c2f204178bee12aeba33f89ff40d3408d9f485caa6b403b5759a42f1884c45b71433f491d98d2196e02f667716aefb3dfab74dd28a32d8003a8c471a12805b5fbe39481259e4f181c3af1a924319551bbe9758a9a3dbfa01fa5886fb129cf1fd13a2c970e6abe724cac7177e77b0ae2f5c4644192e446b0065da5e9a3f5dd9807783537d49497667225492b00dbf18211d38a9078f6872d9598852b3b28758d34c21782620e823cea6a50be9926206e42060665d6d03b3920cf2216705738d99f55d6611edc37d2722af1c5668b393ee09a8b84a74fc88c513744ece6ad7e4f67bc26b8d5f02e9266f5a0915182626cdc8649c3ddb029a30f67db391f143b17cb4eddae49f45b98e5a2659350dca820001b488d0c34f186cdf9d832a0bfc6090c4545df018615935bd3427b9dcdcd6abb214ce0f2a0ef4a4f029007bd5af8f2409f0683c64dc1c1f49b16bc50dea411b28e2cb0615ebc532efbbe28e8e699c3850fd31d25f0ca8ad43c90b22976556cd4303f638244bbc20ab48a3960460205ce3c61d7266c12bcdaf1505e0f162d0a0777efe391c0c0c8ceb3cb4a3fcdc9a2278ec3015ca84f7a759ade85819a8b7d201b7a4c88692814ec034b369e34550ed450498c7434152b633cd22e06ddba10f0add047fa3a3f99112f7c22417".to_string()
}

#[test]
fn pairing_xy_equals_26() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pairing")
        .arg("--g1")
        .arg(THIRTEEN_G1_UNCOMPRESSED)
        .arg("--g2")
        .arg(TWO_G2_UNCOMPRESSED);
    cmd.assert()
        .success()
        .stdout(predicate::eq(pairing_xy_26_expected()));
}

#[test]
fn pairing_xy_equals_26_reference() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pairing")
        .arg("--g1")
        .arg(G1_GENERATOR_UNCOMPRESSED)
        .arg("--g2")
        .arg(TWENTY_SIX_G2_UNCOMPRESSED);
    cmd.assert()
        .success()
        .stdout(predicate::eq(pairing_xy_26_expected()));
}

#[test]
fn pairing_xy_equals_26_swapped_groups() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pairing")
        .arg("--g1")
        .arg(TWO_G1_UNCOMPRESSED)
        .arg("--g2")
        .arg(THIRTEEN_G2_UNCOMPRESSED);
    cmd.assert()
        .success()
        .stdout(predicate::eq(pairing_xy_26_expected()));
}

#[test]
fn pairing_invalid_g1_length() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pairing")
        .arg("--g1")
        .arg("00")
        .arg("--g2")
        .arg(G2_GENERATOR_UNCOMPRESSED);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("G1 point must be 96 bytes"));
}

#[test]
fn pairing_invalid_g2_length() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("pairing")
        .arg("--g1")
        .arg(G1_GENERATOR_UNCOMPRESSED)
        .arg("--g2")
        .arg("00");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("G2 point must be 192 bytes"));
}

// Negate command tests
#[test]
fn neg_g1_generator() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("neg").arg("--g1").write_stdin(G1_GENERATOR);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", NEG_G1_GENERATOR)));
}

#[test]
fn neg_g2_generator() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("neg").arg("--g2").write_stdin(G2_GENERATOR);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", NEG_G2_GENERATOR)));
}

#[test]
fn neg_g1_identity() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("neg").arg("--g1").arg("--point").arg("identity");
    cmd.assert()
        .success()
        .stdout(predicate::eq("0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
}

#[test]
fn neg_g2_identity() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("neg").arg("--g2").arg("--point").arg("identity");
    cmd.assert()
        .success()
        .stdout(predicate::eq("0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
}

#[test]
fn neg_g1_double_neg() {
    let result = Command::cargo_bin("bls12-381-aiken-cli")
        .unwrap()
        .arg("neg")
        .arg("--g1")
        .write_stdin(format!("0x{}", NEG_G1_GENERATOR))
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert_eq!(stdout.trim(), format!("0x{}", G1_GENERATOR));
}

#[test]
fn neg_g1_add_inverse() {
    let neg = Command::cargo_bin("bls12-381-aiken-cli")
        .unwrap()
        .arg("neg")
        .arg("--g1")
        .write_stdin(G1_GENERATOR)
        .output()
        .unwrap();
    let neg_hex = String::from_utf8_lossy(&neg.stdout).trim().to_string();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("add")
        .arg("--g1")
        .arg("--point_right")
        .arg(&neg_hex)
        .write_stdin(G1_GENERATOR);
    cmd.assert()
        .success()
        .stdout(predicate::eq("0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
}

#[test]
fn neg_g2_add_inverse() {
    let neg = Command::cargo_bin("bls12-381-aiken-cli")
        .unwrap()
        .arg("neg")
        .arg("--g2")
        .write_stdin(G2_GENERATOR)
        .output()
        .unwrap();
    let neg_hex = String::from_utf8_lossy(&neg.stdout).trim().to_string();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("add")
        .arg("--g2")
        .arg("--point_right")
        .arg(&neg_hex)
        .write_stdin(G2_GENERATOR);
    cmd.assert()
        .success()
        .stdout(predicate::eq("0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
}

#[test]
fn neg_g1_via_point_flag() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("neg").arg("--g1").arg("--point").arg(G1_GENERATOR);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", NEG_G1_GENERATOR)));
}

#[test]
fn neg_g1_via_generator_special() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("neg").arg("--g1").arg("--point").arg("generator");
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", NEG_G1_GENERATOR)));
}

#[test]
fn neg_g1_from_file() {
    use std::io::Write;

    let mut file = NamedTempFile::new().unwrap();
    write!(file, "{}", G1_GENERATOR).unwrap();

    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("neg").arg("--g1").arg("--point").arg(file.path());
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", NEG_G1_GENERATOR)));
}

#[test]
fn neg_g1_uncompressed_input() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("neg")
        .arg("--g1")
        .write_stdin(G1_GENERATOR_UNCOMPRESSED);
    cmd.assert()
        .success()
        .stdout(predicate::eq(format!("0x{}", NEG_G1_GENERATOR)));
}

#[test]
fn neg_g1_identity_uncompressed() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("neg")
        .arg("--g1")
        .write_stdin(G1_IDENTITY_UNCOMPRESSED);
    cmd.assert()
        .success()
        .stdout(predicate::eq("0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
}

#[test]
fn neg_invalid_point() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("neg")
        .arg("--g1")
        .write_stdin("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid"));
}

#[test]
fn neg_missing_group() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("neg").write_stdin(G1_GENERATOR);
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("--g1"))
        .stderr(predicate::str::contains("--g2"));
}

#[test]
fn neg_wrong_point_length() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("neg").arg("--g1").write_stdin("00"); // too short
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid G1 point length"));
}

#[test]
fn neg_g2_wrong_point_length() {
    let mut cmd = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd.arg("neg").arg("--g2").write_stdin("00"); // too short
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("invalid G2 point length"));
}

#[cfg(test)]
mod property_tests {
    use bls12_381_aiken_cli::*;
    use proptest::prelude::*;

    // Strategy: Generate valid 32-byte private keys
    fn private_key_strategy() -> impl Strategy<Value = Vec<u8>> {
        any::<[u8; 32]>()
            .prop_filter("Valid private key", |bytes| {
                bls12_381_aiken_cli::sk_to_scalar(bytes).is_ok()
            })
            .prop_map(|bytes| bytes.to_vec())
    }

    // Strategy: Generate valid messages (arbitrary byte vectors)
    fn message_strategy() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..1024)
    }

    // Strategy: Generate valid compressed G1 points via sk_to_pk
    fn g1_point_strategy() -> impl Strategy<Value = Vec<u8>> {
        private_key_strategy()
            .prop_filter("valid G1 point", |key| sk_to_pk(key).is_ok())
            .prop_map(|key| sk_to_pk(&key).unwrap())
    }

    // Strategy: Generate valid compressed G2 points via hash_to_group
    fn g2_point_strategy() -> impl Strategy<Value = Vec<u8>> {
        (private_key_strategy(), message_strategy())
            .prop_filter("valid G2 point", |(key, msg)| {
                hash_to_group(key, msg, b"", b"").is_ok()
            })
            .prop_map(|(key, msg)| hash_to_group(&key, &msg, b"", b"").unwrap())
    }

    // Property test: scalar_mul G1 identity * any scalar = identity
    #[test]
    fn scalar_mul_g1_identity_returns_identity() {
        proptest!(|(key in private_key_strategy())| {
            let mut identity = vec![0u8; 48];
            identity[0] = 0xc0;
            let result = scalar_mul(&CurveGroup::G1, &identity, &key);
            prop_assert!(result.is_ok());
            let result = result.unwrap();
            prop_assert_eq!(result[0], 0xc0);
            prop_assert!(result[1..].iter().all(|&b| b == 0));
        });
    }

    // Property test: scalar_mul G2 identity * any scalar = identity
    #[test]
    fn scalar_mul_g2_identity_returns_identity() {
        proptest!(|(key in private_key_strategy())| {
            let mut identity = vec![0u8; 96];
            identity[0] = 0xc0;
            let result = scalar_mul(&CurveGroup::G2, &identity, &key);
            prop_assert!(result.is_ok());
            let result = result.unwrap();
            prop_assert_eq!(result[0], 0xc0);
            prop_assert!(result[1..].iter().all(|&b| b == 0));
        });
    }

    // Property test: group_add G1 identity + identity = identity
    #[test]
    fn group_add_g1_identity_plus_identity() {
        let mut identity = vec![0u8; 48];
        identity[0] = 0xc0;
        let result = group_add(&CurveGroup::G1, &identity, &identity);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result[0], 0xc0);
        assert!(result[1..].iter().all(|&b| b == 0));
    }

    // Property test: group_add G2 identity + identity = identity
    #[test]
    fn group_add_g2_identity_plus_identity() {
        let mut identity = vec![0u8; 96];
        identity[0] = 0xc0;
        let result = group_add(&CurveGroup::G2, &identity, &identity);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result[0], 0xc0);
        assert!(result[1..].iter().all(|&b| b == 0));
    }

    // Property test: compress_point G1 compressed round-trip
    #[test]
    fn compress_g1_compressed_roundtrip() {
        proptest!(|(point in g1_point_strategy())| {
            let result = compress_point(&CurveGroup::G1, &point);
            prop_assert!(result.is_ok());
            let result = result.unwrap();
            prop_assert_eq!(result.len(), 48);
            prop_assert_eq!(result, point);
        });
    }

    // Property test: compress_point G1 identity always returns identity
    #[test]
    fn compress_g1_identity() {
        let mut identity = vec![0u8; 48];
        identity[0] = 0xc0;
        let result = compress_point(&CurveGroup::G1, &identity);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), identity);
    }

    // Property test: compress_point G2 identity always returns identity
    #[test]
    fn compress_g2_identity() {
        let mut identity = vec![0u8; 96];
        identity[0] = 0xc0;
        let result = compress_point(&CurveGroup::G2, &identity);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), identity);
    }

    // Property test: compress_point invalid point returns error
    #[test]
    fn compress_invalid_point() {
        let invalid = vec![0u8; 48];
        let result = compress_point(&CurveGroup::G1, &invalid);
        assert!(result.is_err());
    }

    // Property test: compress_point wrong length returns error
    #[test]
    fn compress_wrong_length() {
        let result = compress_point(&CurveGroup::G1, &[0u8; 10]);
        assert!(result.is_err());
    }

    // Property test: uncompress_point G1 round-trip compress(uncompress(point)) == point
    #[test]
    fn uncompress_g1_roundtrip() {
        proptest!(|(point in g1_point_strategy())| {
            let uncompressed = uncompress_point(&CurveGroup::G1, &point);
            prop_assert!(uncompressed.is_ok());
            let uncompressed = uncompressed.unwrap();
            prop_assert_eq!(uncompressed.len(), 96);
            let recompressed = compress_point(&CurveGroup::G1, &uncompressed);
            prop_assert!(recompressed.is_ok());
            prop_assert_eq!(recompressed.unwrap(), point);
        });
    }

    // Property test: uncompress_point G2 round-trip
    #[test]
    fn uncompress_g2_roundtrip() {
        proptest!(|(point in g2_point_strategy())| {
            let uncompressed = uncompress_point(&CurveGroup::G2, &point);
            prop_assert!(uncompressed.is_ok());
            let uncompressed = uncompressed.unwrap();
            prop_assert_eq!(uncompressed.len(), 192);
            let recompressed = compress_point(&CurveGroup::G2, &uncompressed);
            prop_assert!(recompressed.is_ok());
            prop_assert_eq!(recompressed.unwrap(), point);
        });
    }

    // Property test: uncompress(compress(val)) == val for G1 (reverse round-trip)
    #[test]
    fn uncompress_compress_g1_reverse_roundtrip() {
        proptest!(|(point in g1_point_strategy())| {
            let uncompressed = uncompress_point(&CurveGroup::G1, &point);
            prop_assert!(uncompressed.is_ok());
            let uncompressed = uncompressed.unwrap();
            let compressed = compress_point(&CurveGroup::G1, &uncompressed);
            prop_assert!(compressed.is_ok());
            let compressed = compressed.unwrap();
            let reuncompressed = uncompress_point(&CurveGroup::G1, &compressed);
            prop_assert!(reuncompressed.is_ok());
            prop_assert_eq!(reuncompressed.unwrap(), uncompressed);
        });
    }

    // Property test: uncompress(compress(val)) == val for G2 (reverse round-trip)
    #[test]
    fn uncompress_compress_g2_reverse_roundtrip() {
        proptest!(|(point in g2_point_strategy())| {
            let uncompressed = uncompress_point(&CurveGroup::G2, &point);
            prop_assert!(uncompressed.is_ok());
            let uncompressed = uncompressed.unwrap();
            let compressed = compress_point(&CurveGroup::G2, &uncompressed);
            prop_assert!(compressed.is_ok());
            let compressed = compressed.unwrap();
            let reuncompressed = uncompress_point(&CurveGroup::G2, &compressed);
            prop_assert!(reuncompressed.is_ok());
            prop_assert_eq!(reuncompressed.unwrap(), uncompressed);
        });
    }

    // Property test: uncompress_point G1 identity returns all zeros
    #[test]
    fn uncompress_g1_identity_all_zeros() {
        let mut identity = vec![0u8; 48];
        identity[0] = 0xc0;
        let result = uncompress_point(&CurveGroup::G1, &identity);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 96);
        assert!(result.iter().all(|&b| b == 0));
    }

    // Property test: uncompress_point G2 identity returns all zeros
    #[test]
    fn uncompress_g2_identity_all_zeros() {
        let mut identity = vec![0u8; 96];
        identity[0] = 0xc0;
        let result = uncompress_point(&CurveGroup::G2, &identity);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), 192);
        assert!(result.iter().all(|&b| b == 0));
    }

    // Property test: uncompress_point invalid point returns error
    #[test]
    fn uncompress_invalid_point_returns_error() {
        let invalid = vec![0u8; 48];
        let result = uncompress_point(&CurveGroup::G1, &invalid);
        assert!(result.is_err());
    }

    // Property test: uncompress_point wrong length returns error
    #[test]
    fn uncompress_wrong_length_returns_error() {
        let result = uncompress_point(&CurveGroup::G1, &[0u8; 10]);
        assert!(result.is_err());
    }

    proptest! {
        // Property test for sk_to_scalar
        #[test]
        fn sk_to_scalar_valid_key(key in private_key_strategy()) {
            let result = sk_to_scalar(&key);
            prop_assert!(result.is_ok());
        }

        #[test]
        fn sk_to_scalar_invalid_length(key in proptest::collection::vec(any::<u8>(), 10..31)) {
            let result = sk_to_scalar(&key);
            prop_assert!(result.is_err());
            prop_assert!(result.unwrap_err().contains("must be 32 bytes"));
        }

        // Property test for sk_to_pk
        #[test]
        fn sk_to_pk_valid_key(key in private_key_strategy()) {
            let result = sk_to_pk(&key);
            prop_assert!(result.is_ok());
            let pk = result.unwrap();
            // Public key should be 48 bytes (compressed G1)
            prop_assert_eq!(pk.len(), 48);
        }

        // Property test for hash_to_group (sig)
        #[test]
        fn hash_to_group_valid(msg in message_strategy(), key in private_key_strategy()) {
            let result = hash_to_group(&key, &msg, b"", b"");
            prop_assert!(result.is_ok());
            let sig = result.unwrap();
            // Signature should be 96 bytes (compressed G2)
            prop_assert_eq!(sig.len(), 96);
        }

        // Property test for verify - valid signatures always verify
        #[test]
        fn verify_valid_signature(msg in message_strategy(), key in private_key_strategy()) {
            // Generate public key
            let pk_result = sk_to_pk(&key);
            prop_assume!(pk_result.is_ok());
            let pk = pk_result.unwrap();

            // Generate signature
            let sig_result = hash_to_group(&key, &msg, b"", b"");
            prop_assume!(sig_result.is_ok());
            let sig = sig_result.unwrap();

            // Verify should succeed
            let verify_result = verify(&msg, &sig, &pk, b"", b"");
            prop_assert!(verify_result.is_ok());
            prop_assert!(verify_result.unwrap());
        }

        // Property test: Invalid public key returns error
        #[test]
        fn verify_invalid_pk_returns_error(msg in message_strategy()) {
            // All zeros is not a valid compressed point
            let invalid_pk = vec![0u8; 48];
            let sig = vec![1u8; 96]; // Dummy signature
            let result = verify(&msg, &sig, &invalid_pk, b"", b"");
            // Should return Err because public key is invalid
            prop_assert!(result.is_err());
        }

        // Property test: Invalid signature returns error
        #[test]
        fn verify_invalid_sig_returns_error(msg in message_strategy()) {
            let pk = vec![1u8; 48]; // Dummy public key
            // All zeros is not a valid compressed point
            let invalid_sig = vec![0u8; 96];
            let result = verify(&msg, &invalid_sig, &pk, b"", b"");
            // Should return Err because signature is invalid
            prop_assert!(result.is_err());
        }

        // Property test: wrong message fails verification
        #[test]
        fn verify_wrong_message_fails(msg1 in message_strategy(), msg2 in message_strategy(), key in private_key_strategy()) {
            prop_assume!(msg1 != msg2);
            // Generate public key
            let pk_result = sk_to_pk(&key);
            prop_assume!(pk_result.is_ok());
            let pk = pk_result.unwrap();

            // Sign msg1
            let sig_result = hash_to_group(&key, &msg1, b"", b"");
            prop_assume!(sig_result.is_ok());
            let sig = sig_result.unwrap();

            // Verify with msg2 should fail
            let verify_result = verify(&msg2, &sig, &pk, b"", b"");
            prop_assert!(verify_result.is_ok());
            prop_assert!(!verify_result.unwrap());
        }

        // Property test: scalar_mul G1 with valid inputs always produces 48 bytes
        #[test]
        fn scalar_mul_g1_output_length(point in g1_point_strategy(), key in private_key_strategy()) {
            let result = scalar_mul(&CurveGroup::G1, &point, &key);
            prop_assert!(result.is_ok());
            let result = result.unwrap();
            prop_assert_eq!(result.len(), 48);
        }

        // Property test: scalar_mul G2 produces 96 bytes
        #[test]
        fn scalar_mul_g2_output_length(point in g2_point_strategy(), key in private_key_strategy()) {
            let result = scalar_mul(&CurveGroup::G2, &point, &key);
            prop_assert!(result.is_ok());
            let result = result.unwrap();
            prop_assert_eq!(result.len(), 96);
        }

        // Property test: scalar_mul invalid point returns error
        #[test]
        fn scalar_mul_invalid_point(key in private_key_strategy()) {
            let invalid_point = vec![0u8; 48];
            let result = scalar_mul(&CurveGroup::G1, &invalid_point, &key);
            prop_assert!(result.is_err());
        }

        // Property test: scalar_mul invalid scalar (len != 32) returns error
        #[test]
        fn scalar_mul_invalid_scalar(point in g1_point_strategy()) {
            let invalid_scalar = vec![0u8; 16];
            let result = scalar_mul(&CurveGroup::G1, &point, &invalid_scalar);
            prop_assert!(result.is_err());
        }

        // Property test: group_add G1 identity + point = point
        #[test]
        fn group_add_g1_identity_plus_point(point in g1_point_strategy()) {
            let mut identity = vec![0u8; 48];
            identity[0] = 0xc0;
            let result = group_add(&CurveGroup::G1, &identity, &point);
            prop_assert!(result.is_ok());
            let result = result.unwrap();
            prop_assert_eq!(result, point);
        }

        // Property test: group_add G1 point + identity = point
        #[test]
        fn group_add_g1_point_plus_identity(point in g1_point_strategy()) {
            let mut identity = vec![0u8; 48];
            identity[0] = 0xc0;
            let result = group_add(&CurveGroup::G1, &point, &identity);
            prop_assert!(result.is_ok());
            let result = result.unwrap();
            prop_assert_eq!(result, point);
        }

        // Property test: group_add G2 identity + point = point
        #[test]
        fn group_add_g2_identity_plus_point(point in g2_point_strategy()) {
            let mut identity = vec![0u8; 96];
            identity[0] = 0xc0;
            let result = group_add(&CurveGroup::G2, &identity, &point);
            prop_assert!(result.is_ok());
            let result = result.unwrap();
            prop_assert_eq!(result, point);
        }

        // Property test: group_add G2 point + identity = point
        #[test]
        fn group_add_g2_point_plus_identity(point in g2_point_strategy()) {
            let mut identity = vec![0u8; 96];
            identity[0] = 0xc0;
            let result = group_add(&CurveGroup::G2, &point, &identity);
            prop_assert!(result.is_ok());
            let result = result.unwrap();
            prop_assert_eq!(result, point);
        }

        // Property test: group_add invalid left point returns error
        #[test]
        fn group_add_invalid_left_point(point in g1_point_strategy()) {
            let invalid = vec![0u8; 48];
            let result = group_add(&CurveGroup::G1, &invalid, &point);
            prop_assert!(result.is_err());
        }

        // Property test: group_add invalid right point returns error
        #[test]
        fn group_add_invalid_right_point(point in g1_point_strategy()) {
            let invalid = vec![0u8; 48];
            let result = group_add(&CurveGroup::G1, &point, &invalid);
            prop_assert!(result.is_err());
        }

        // Property test: wrong public key fails verification
        #[test]
        fn verify_wrong_pk_fails(msg in message_strategy(), key1 in private_key_strategy(), key2 in private_key_strategy()) {
            prop_assume!(key1 != key2);
            // Generate public keys
            let pk1_result = sk_to_pk(&key1);
            let pk2_result = sk_to_pk(&key2);
            prop_assume!(pk1_result.is_ok());
            prop_assume!(pk2_result.is_ok());
            let pk1 = pk1_result.unwrap();
            let pk2 = pk2_result.unwrap();
            prop_assume!(pk1 != pk2);

            // Sign with key1
            let sig_result = hash_to_group(&key1, &msg, b"", b"");
            prop_assume!(sig_result.is_ok());
            let sig = sig_result.unwrap();

            // Verify with pk2 should fail
            let verify_result = verify(&msg, &sig, &pk2, b"", b"");
            prop_assert!(verify_result.is_ok());
            prop_assert!(!verify_result.unwrap());
        }
    }
}
