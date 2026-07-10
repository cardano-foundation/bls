use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::NamedTempFile;

/// Run a full ceremony → prove → verify round-trip using random keys.
#[test]
fn full_ceremony_prove_verify_roundtrip() {
    let (r1cs, wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();
    let out_file = NamedTempFile::new().unwrap();

    // 1. Ceremony
    let mut cmd_ceremony = Command::cargo_bin("groth16-prover").unwrap();
    cmd_ceremony
        .arg("ceremony")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--proving-key")
        .arg(pk_file.path())
        .arg("--verifying-key")
        .arg(vk_file.path());
    cmd_ceremony
        .assert()
        .success()
        .stderr(predicate::str::contains("Ceremony complete"))
        .stderr(predicate::str::contains("Proving key written to"))
        .stderr(predicate::str::contains("Verifying key written to"));

    // 2. Prove with the generated proving key
    let mut cmd_prove = Command::cargo_bin("groth16-prover").unwrap();
    cmd_prove
        .arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--proving-key")
        .arg(pk_file.path())
        .arg("--out")
        .arg(out_file.path());
    cmd_prove.assert().success();

    // 3. Verify with the generated verifying key
    let pub_path = out_file.path().with_extension("pub");
    let mut cmd_verify = Command::cargo_bin("groth16-prover").unwrap();
    cmd_verify
        .arg("verify")
        .arg("--proof")
        .arg(out_file.path())
        .arg("--public")
        .arg(&pub_path)
        .arg("--verifying-key")
        .arg(vk_file.path());
    cmd_verify
        .assert()
        .success()
        .stdout(predicate::str::contains("Verification result: VALID"));
}

/// Generate a synthetic `.r1cs` file for the 3-gate multiplier circuit.
fn build_synthetic_r1cs() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"r1cs");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    let field_size = 32u32;
    let n_wires = 8u32;
    let n_pub_out = 1u32;
    let n_pub_in = 0u32;
    let n_prv_in = 4u32;
    let n_labels = 8u64;
    let n_constraints = 3u32;

    let mut header = Vec::new();
    header.extend_from_slice(&field_size.to_le_bytes());
    header.extend_from_slice(&[0u8; 32]);
    header.extend_from_slice(&n_wires.to_le_bytes());
    header.extend_from_slice(&n_pub_out.to_le_bytes());
    header.extend_from_slice(&n_pub_in.to_le_bytes());
    header.extend_from_slice(&n_prv_in.to_le_bytes());
    header.extend_from_slice(&n_labels.to_le_bytes());
    header.extend_from_slice(&n_constraints.to_le_bytes());

    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(&header);

    let mut constraints = Vec::new();
    let mut write_vec = |terms: &[(u32, u64)]| {
        constraints.extend_from_slice(&(terms.len() as u32).to_le_bytes());
        for &(w, v) in terms {
            constraints.extend_from_slice(&w.to_le_bytes());
            constraints.push(v as u8);
            constraints.extend_from_slice(&vec![0u8; field_size as usize - 1]);
        }
    };

    // x1*x2 = x5
    write_vec(&[(2, 1)]);
    write_vec(&[(3, 1)]);
    write_vec(&[(6, 1)]);
    // x3*x4 = x6
    write_vec(&[(4, 1)]);
    write_vec(&[(5, 1)]);
    write_vec(&[(7, 1)]);
    // x5*x6 = a
    write_vec(&[(6, 1)]);
    write_vec(&[(7, 1)]);
    write_vec(&[(1, 1)]);

    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(constraints.len() as u64).to_le_bytes());
    out.extend_from_slice(&constraints);
    out
}

/// Generate a synthetic `.wtns` file.
fn build_synthetic_wtns() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"wtns");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    let field_size = 32u32;
    let n_wires = 8u32;
    let mut header = Vec::new();
    header.extend_from_slice(&field_size.to_le_bytes());
    header.extend_from_slice(&[0u8; 32]);
    header.extend_from_slice(&n_wires.to_le_bytes());

    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(&header);

    let witness = vec![1u64, 48, 2, 2, 3, 4, 4, 12];
    let mut data = Vec::new();
    for &v in &witness {
        data.push(v as u8);
        data.extend_from_slice(&vec![0u8; field_size as usize - 1]);
    }

    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&data);
    out
}

/// Create temp files with synthetic artifacts and return their paths.
fn create_test_artifacts() -> (NamedTempFile, NamedTempFile) {
    let r1cs_file = NamedTempFile::new().unwrap();
    fs::write(r1cs_file.path(), build_synthetic_r1cs()).unwrap();

    let wtns_file = NamedTempFile::new().unwrap();
    fs::write(wtns_file.path(), build_synthetic_wtns()).unwrap();

    (r1cs_file, wtns_file)
}

// ------------------------------------------------------------------
// Success cases
// ------------------------------------------------------------------

#[test]
fn prove_default_stdout() {
    let (r1cs, wtns) = create_test_artifacts();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path());

    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            // Should be 384 hex chars = 192 bytes (48 + 96 + 48)
            hex::decode(output.trim()).is_ok() && output.trim().len() == 384
        }))
        .stderr(predicate::str::contains("Loaded circuit: 8 wires, 3 constraints"))
        .stderr(predicate::str::contains("Proof generated successfully."));
}

#[test]
fn prove_to_file() {
    let (r1cs, wtns) = create_test_artifacts();
    let out_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--out")
        .arg(out_file.path());

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Proof written to"))
        .stderr(predicate::str::contains("Public input written to"));

    // Verify files were written
    let proof = fs::read(out_file.path()).unwrap();
    assert_eq!(proof.len(), 192, "proof must be 192 bytes");

    let pub_path = out_file.path().with_extension("pub");
    let public = fs::read(&pub_path).unwrap();
    assert_eq!(public.len(), 48, "public input must be 48 bytes");
}

#[test]
fn prove_dense_engine() {
    let (r1cs, wtns) = create_test_artifacts();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--engine")
        .arg("dense");

    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            hex::decode(output.trim()).is_ok() && output.trim().len() == 384
        }));
}

#[test]
fn prove_naive_prover() {
    let (r1cs, wtns) = create_test_artifacts();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--prover")
        .arg("naive");

    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            hex::decode(output.trim()).is_ok() && output.trim().len() == 384
        }));
}

#[test]
fn prove_dense_naive() {
    let (r1cs, wtns) = create_test_artifacts();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--engine")
        .arg("dense")
        .arg("--prover")
        .arg("naive");

    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            hex::decode(output.trim()).is_ok() && output.trim().len() == 384
        }));
}

#[test]
fn prove_fft_pippenger_explicit() {
    let (r1cs, wtns) = create_test_artifacts();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--engine")
        .arg("fft")
        .arg("--prover")
        .arg("pippenger");

    cmd.assert()
        .success()
        .stdout(predicate::function(|output: &str| {
            hex::decode(output.trim()).is_ok() && output.trim().len() == 384
        }));
}

// ------------------------------------------------------------------
// Parity: all four combinations produce valid proofs
// ------------------------------------------------------------------

#[test]
fn prove_all_combinations_produce_valid_hex() {
    let (r1cs, wtns) = create_test_artifacts();

    for engine in &["dense", "fft"] {
        for prover in &["naive", "pippenger"] {
            let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
            cmd.arg("prove")
                .arg("--circuit")
                .arg(r1cs.path())
                .arg("--witness")
                .arg(wtns.path())
                .arg("--engine")
                .arg(*engine)
                .arg("--prover")
                .arg(*prover);

            let output = cmd.output().unwrap();
            assert!(
                output.status.success(),
                "prove --engine {} --prover {} failed: {}",
                engine,
                prover,
                String::from_utf8_lossy(&output.stderr)
            );

            let stdout = String::from_utf8_lossy(&output.stdout);
            let hex = stdout.trim();
            assert!(
                hex::decode(hex).is_ok() && hex.len() == 384,
                "invalid proof hex for engine={} prover={}",
                engine,
                prover
            );
        }
    }
}

// ------------------------------------------------------------------
// Error cases
// ------------------------------------------------------------------

#[test]
fn prove_missing_circuit() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove").arg("--witness").arg("/tmp/dummy.wtns");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required arguments were not provided"));
}

#[test]
fn prove_missing_witness() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove").arg("--circuit").arg("/tmp/dummy.r1cs");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required arguments were not provided"));
}

#[test]
fn prove_invalid_circuit_file() {
    let bad_r1cs = NamedTempFile::new().unwrap();
    fs::write(bad_r1cs.path(), b"not_a_valid_r1cs_file").unwrap();

    let wtns = NamedTempFile::new().unwrap();
    fs::write(wtns.path(), build_synthetic_wtns()).unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--circuit")
        .arg(bad_r1cs.path())
        .arg("--witness")
        .arg(wtns.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to load circuit"));
}

#[test]
fn prove_invalid_witness_file() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_r1cs()).unwrap();

    let bad_wtns = NamedTempFile::new().unwrap();
    fs::write(bad_wtns.path(), b"not_a_valid_wtns_file").unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(bad_wtns.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to load witness"));
}

// ------------------------------------------------------------------
// Verify command tests
// ------------------------------------------------------------------

#[test]
fn verify_valid_proof() {
    let (r1cs, wtns) = create_test_artifacts();
    let out_file = NamedTempFile::new().unwrap();

    // First, generate a proof
    let mut cmd_prove = Command::cargo_bin("groth16-prover").unwrap();
    cmd_prove
        .arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--out")
        .arg(out_file.path());
    cmd_prove.assert().success();

    // Now verify it
    let pub_path = out_file.path().with_extension("pub");
    let mut cmd_verify = Command::cargo_bin("groth16-prover").unwrap();
    cmd_verify
        .arg("verify")
        .arg("--proof")
        .arg(out_file.path())
        .arg("--public")
        .arg(&pub_path);
    cmd_verify
        .assert()
        .success()
        .stdout(predicate::str::contains("Verification result: VALID"));
}

#[test]
fn verify_all_combinations() {
    let (r1cs, wtns) = create_test_artifacts();

    for engine in &["dense", "fft"] {
        for prover in &["naive", "pippenger"] {
            let out_file = NamedTempFile::new().unwrap();

            // Generate proof with this combination
            let mut cmd_prove = Command::cargo_bin("groth16-prover").unwrap();
            cmd_prove
                .arg("prove")
                .arg("--circuit")
                .arg(r1cs.path())
                .arg("--witness")
                .arg(wtns.path())
                .arg("--engine")
                .arg(*engine)
                .arg("--prover")
                .arg(*prover)
                .arg("--out")
                .arg(out_file.path());
            let prove_output = cmd_prove.output().unwrap();
            assert!(
                prove_output.status.success(),
                "prove failed for engine={} prover={}",
                engine,
                prover
            );

            // Verify it
            let pub_path = out_file.path().with_extension("pub");
            let mut cmd_verify = Command::cargo_bin("groth16-prover").unwrap();
            cmd_verify
                .arg("verify")
                .arg("--proof")
                .arg(out_file.path())
                .arg("--public")
                .arg(&pub_path);
            let verify_output = cmd_verify.output().unwrap();
            assert!(
                verify_output.status.success(),
                "verify failed for engine={} prover={}: {}",
                engine,
                prover,
                String::from_utf8_lossy(&verify_output.stderr)
            );

            let stdout = String::from_utf8_lossy(&verify_output.stdout);
            assert!(
                stdout.contains("VALID"),
                "verify did not report VALID for engine={} prover={}",
                engine,
                prover
            );
        }
    }
}

#[test]
fn verify_missing_proof() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("verify").arg("--public").arg("/tmp/dummy.pub");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required arguments were not provided"));
}

#[test]
fn verify_missing_public() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("verify").arg("--proof").arg("/tmp/dummy.bin");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required arguments were not provided"));
}

#[test]
fn verify_invalid_proof_length() {
    let proof_file = NamedTempFile::new().unwrap();
    fs::write(proof_file.path(), vec![0u8; 100]).unwrap();

    let pub_file = NamedTempFile::new().unwrap();
    fs::write(pub_file.path(), vec![0u8; 48]).unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("verify")
        .arg("--proof")
        .arg(proof_file.path())
        .arg("--public")
        .arg(pub_file.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("proof file must be exactly 192 bytes"));
}

#[test]
fn verify_invalid_public_length() {
    let (r1cs, wtns) = create_test_artifacts();
    let out_file = NamedTempFile::new().unwrap();

    // Generate a valid proof so we have a valid proof file
    let mut cmd_prove = Command::cargo_bin("groth16-prover").unwrap();
    cmd_prove
        .arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--out")
        .arg(out_file.path());
    cmd_prove.assert().success();

    // Provide a public input file that is too short
    let bad_pub = NamedTempFile::new().unwrap();
    fs::write(bad_pub.path(), vec![0u8; 10]).unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("verify")
        .arg("--proof")
        .arg(out_file.path())
        .arg("--public")
        .arg(bad_pub.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("public-input file must be exactly 48 bytes"));
}

#[test]
fn verify_tampered_public_input_fails() {
    let (r1cs, wtns) = create_test_artifacts();
    let out_file = NamedTempFile::new().unwrap();

    // Generate a valid proof
    let mut cmd_prove = Command::cargo_bin("groth16-prover").unwrap();
    cmd_prove
        .arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--out")
        .arg(out_file.path());
    cmd_prove.assert().success();

    // Tamper with the public input file: replace it with the G1 generator
    // (a different valid point that will cause the pairing check to fail)
    let g1_generator: [u8; 48] = [
        0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c,
        0x4f, 0xa9, 0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05,
        0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f,
        0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
    ];
    let pub_path = out_file.path().with_extension("pub");
    fs::write(&pub_path, &g1_generator).unwrap();

    // Verification should fail because the public input commitment does not match
    let mut cmd_verify = Command::cargo_bin("groth16-prover").unwrap();
    cmd_verify
        .arg("verify")
        .arg("--proof")
        .arg(out_file.path())
        .arg("--public")
        .arg(&pub_path);
    cmd_verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("INVALID"));
}
