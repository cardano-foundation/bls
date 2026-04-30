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

#[cfg(test)]
mod property_tests {
    use bls12_381_aiken_cli::*;
    use proptest::prelude::*;
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
