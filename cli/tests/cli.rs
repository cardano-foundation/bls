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

// G1 generator compressed (48 bytes)
const G1_GENERATOR: &str = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

// G2 generator compressed (96 bytes)
const G2_GENERATOR: &str = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

// Scalar value 1 (32 bytes, little-endian encoding)
const SCALAR_ONE: &str = "0100000000000000000000000000000000000000000000000000000000000000";

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
        .stdout(predicate::eq(G1_GENERATOR.to_string()));
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
        .stdout(predicate::eq(G1_GENERATOR.to_string()));
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
        .stdout(predicate::eq(G2_GENERATOR.to_string()));
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
        .stdout(predicate::eq(G2_GENERATOR.to_string()));
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
        .stdout(predicate::eq(G1_IDENTITY.to_string()));
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
        .stdout(predicate::eq(G2_IDENTITY.to_string()));
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

    // Now multiply G1 generator by the same private key scalar
    let mut cmd_mul = Command::cargo_bin("bls12-381-aiken-cli").unwrap();
    cmd_mul
        .arg("mul")
        .arg("--g1")
        .arg("--scalar")
        .arg(private_key)
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
        .arg("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
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
        .stdout(predicate::eq(G1_GENERATOR.to_string()));
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
        .stdout(predicate::eq(G1_GENERATOR.to_string()));
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
        .stdout(predicate::eq(G2_GENERATOR.to_string()));
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
        .stdout(predicate::eq(G2_GENERATOR.to_string()));
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
        .stdout(predicate::eq(G1_IDENTITY.to_string()));
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
        .stdout(predicate::eq(G2_IDENTITY.to_string()));
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
        .stdout(predicate::eq(G1_GENERATOR.to_string()));
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
        .stdout(predicate::eq(G2_GENERATOR.to_string()));
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
