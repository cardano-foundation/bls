use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::NamedTempFile;

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
