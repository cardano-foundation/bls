use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::NamedTempFile;

use ark_bls12_381::{Fq, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;

// ------------------------------------------------------------------
// Synthetic .ptau generator (self-contained tests)
// ------------------------------------------------------------------

/// Build a minimal valid snarkjs `.ptau` file in memory.
///
/// The file stores uncompressed LEM (Little-Endian Montgomery) points
/// for a fake Powers-of-Tau ceremony with the given `power`.
/// `tau`, `alpha`, and `beta` are fixed to small integers so the
/// resulting points are always valid curve elements.
fn build_synthetic_ptau(power: u32) -> Vec<u8> {
    let max_g2 = 1usize << power;
    let max_g1 = max_g2 * 2 - 1;

    let tau = Fr::from(2u64);
    let alpha = Fr::from(3u64);
    let beta = Fr::from(5u64);

    let mut out = Vec::new();

    // Header
    out.extend_from_slice(b"ptau");
    out.extend_from_slice(&1u32.to_le_bytes()); // version
    out.extend_from_slice(&11u32.to_le_bytes()); // number of sections

    // Helper to write a section: [type][size][data]
    let mut write_section = |stype: u32, data: &[u8]| {
        out.extend_from_slice(&stype.to_le_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(data);
    };

    // Section 1: header
    let mut header = Vec::new();
    header.extend_from_slice(&48u32.to_le_bytes());
    let mut prime = [0u8; 48];
    prime[0] = 0xab;
    prime[1] = 0xff;
    prime[2] = 0xff;
    prime[3] = 0xff;
    header.extend_from_slice(&prime);
    header.extend_from_slice(&power.to_le_bytes());
    header.extend_from_slice(&power.to_le_bytes());
    write_section(1, &header);

    // Helper: write Fq in LEM format
    fn write_fq(buf: &mut Vec<u8>, val: &Fq) {
        let limbs = val.0 .0; // [u64; 6]
        for limb in limbs {
            buf.extend_from_slice(&limb.to_le_bytes());
        }
    }

    // Section 2: tauG1
    let mut sec2 = Vec::new();
    for i in 0..max_g1 {
        let scalar = tau.pow([i as u64]);
        let pt: G1Affine = (G1Affine::generator() * scalar).into_affine();
        write_fq(&mut sec2, &pt.x);
        write_fq(&mut sec2, &pt.y);
    }
    write_section(2, &sec2);

    // Section 3: tauG2
    let mut sec3 = Vec::new();
    for i in 0..max_g2 {
        let scalar = tau.pow([i as u64]);
        let pt: G2Affine = (G2Affine::generator() * scalar).into_affine();
        write_fq(&mut sec3, &pt.x.c0);
        write_fq(&mut sec3, &pt.x.c1);
        write_fq(&mut sec3, &pt.y.c0);
        write_fq(&mut sec3, &pt.y.c1);
    }
    write_section(3, &sec3);

    // Section 4: alphaTauG1
    let mut sec4 = Vec::new();
    for i in 0..max_g2 {
        let scalar = alpha * tau.pow([i as u64]);
        let pt: G1Affine = (G1Affine::generator() * scalar).into_affine();
        write_fq(&mut sec4, &pt.x);
        write_fq(&mut sec4, &pt.y);
    }
    write_section(4, &sec4);

    // Section 5: betaTauG1
    let mut sec5 = Vec::new();
    for i in 0..max_g2 {
        let scalar = beta * tau.pow([i as u64]);
        let pt: G1Affine = (G1Affine::generator() * scalar).into_affine();
        write_fq(&mut sec5, &pt.x);
        write_fq(&mut sec5, &pt.y);
    }
    write_section(5, &sec5);

    // Section 6: betaG2
    let mut sec6 = Vec::new();
    let pt: G2Affine = (G2Affine::generator() * beta).into_affine();
    write_fq(&mut sec6, &pt.x.c0);
    write_fq(&mut sec6, &pt.x.c1);
    write_fq(&mut sec6, &pt.y.c0);
    write_fq(&mut sec6, &pt.y.c1);
    write_section(6, &sec6);

    // Sections 7-11: empty
    for stype in 7..=11 {
        write_section(stype, &[]);
    }

    out
}

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

    // 2. Prove with the generated proving key (legacy scalar path — must opt in with --qap-not-on-fly)
    let mut cmd_prove = Command::cargo_bin("groth16-prover").unwrap();
    cmd_prove
        .arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--proving-key")
        .arg(pk_file.path())
        .arg("--qap-not-on-fly")
        .arg("--out")
        .arg(out_file.path());
    cmd_prove
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Using legacy scalar-based QAP construction",
        ))
        .stderr(predicate::str::contains("Loaded legacy proving key"));

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
        .stderr(predicate::str::contains(
            "Loaded circuit: 8 wires, 3 constraints",
        ))
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

#[test]
fn prove_qap_on_fly_explicit() {
    let (r1cs, wtns) = create_test_artifacts();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--qap-on-fly");

    cmd.assert()
        .success()
        .stderr(predicate::str::contains(
            "Using on-the-fly QAP construction",
        ))
        .stdout(predicate::function(|output: &str| {
            hex::decode(output.trim()).is_ok() && output.trim().len() == 384
        }));
}

#[test]
fn prove_qap_not_on_fly() {
    let (r1cs, wtns) = create_test_artifacts();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--qap-not-on-fly");

    cmd.assert()
        .success()
        .stderr(predicate::str::contains(
            "Using legacy scalar-based QAP construction",
        ))
        .stderr(predicate::str::contains(
            "Warning: no proving key provided; using deterministic test toxic waste",
        ))
        .stdout(predicate::function(|output: &str| {
            hex::decode(output.trim()).is_ok() && output.trim().len() == 384
        }));
}

#[test]
fn prove_qap_on_fly_with_legacy_pk_suggests_not_on_fly() {
    let (r1cs, wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();

    // Legacy ceremony produces a scalar ProvingKey
    let mut cmd_ceremony = Command::cargo_bin("groth16-prover").unwrap();
    cmd_ceremony
        .arg("ceremony")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--proving-key")
        .arg(pk_file.path())
        .arg("--verifying-key")
        .arg(vk_file.path());
    cmd_ceremony.assert().success();

    // Default prove expects a FullProvingKey and should give a helpful error
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--proving-key")
        .arg(pk_file.path());

    cmd.assert().failure().stderr(predicate::str::contains(
        "If your proving key is a legacy scalar-based key, use --qap-not-on-fly.",
    ));
}

#[test]
fn prove_qap_not_on_fly_with_full_pk_suggests_on_fly() {
    let (r1cs, wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();

    // Dev ceremony produces a FullProvingKey
    let mut cmd_ceremony = Command::cargo_bin("groth16-prover").unwrap();
    cmd_ceremony
        .arg("ceremony-dev")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--proving-key")
        .arg(pk_file.path())
        .arg("--verifying-key")
        .arg(vk_file.path());
    cmd_ceremony.assert().success();

    // Legacy path with a FullProvingKey should give a helpful error
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--proving-key")
        .arg(pk_file.path())
        .arg("--qap-not-on-fly");

    cmd.assert().failure().stderr(predicate::str::contains(
        "If your proving key is a FullProvingKey, use --qap-on-fly (or omit the flag).",
    ));
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
    cmd.assert().failure().stderr(predicate::str::contains(
        "required arguments were not provided",
    ));
}

#[test]
fn prove_missing_witness() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove").arg("--circuit").arg("/tmp/dummy.r1cs");
    cmd.assert().failure().stderr(predicate::str::contains(
        "required arguments were not provided",
    ));
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
    cmd.assert().failure().stderr(predicate::str::contains(
        "required arguments were not provided",
    ));
}

#[test]
fn verify_missing_public() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("verify").arg("--proof").arg("/tmp/dummy.bin");
    cmd.assert().failure().stderr(predicate::str::contains(
        "required arguments were not provided",
    ));
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
    cmd.assert().failure().stderr(predicate::str::contains(
        "proof file must be exactly 192 bytes",
    ));
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
    cmd.assert().failure().stderr(predicate::str::contains(
        "public-input file must be exactly 48 bytes",
    ));
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
        0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac,
        0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b,
        0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb,
        0x22, 0xc6, 0xbb,
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

/// Run a full ceremony-dev → prove → verify round-trip using a FullProvingKey.
#[test]
fn full_ceremony_dev_prove_verify_roundtrip() {
    let (r1cs, wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();
    let out_file = NamedTempFile::new().unwrap();

    // 1. Dev ceremony (outputs FullProvingKey)
    let mut cmd_ceremony = Command::cargo_bin("groth16-prover").unwrap();
    cmd_ceremony
        .arg("ceremony-dev")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--proving-key")
        .arg(pk_file.path())
        .arg("--verifying-key")
        .arg(vk_file.path());
    cmd_ceremony
        .assert()
        .success()
        .stderr(predicate::str::contains("Dev ceremony complete"))
        .stderr(predicate::str::contains("Full proving key written to"))
        .stderr(predicate::str::contains("Verifying key written to"));

    // 2. Prove with the FullProvingKey
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
    cmd_prove
        .assert()
        .success()
        .stderr(predicate::str::contains("Loaded FullProvingKey"));

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

// ------------------------------------------------------------------
// Phase-2 ceremony CLI tests
// ------------------------------------------------------------------

#[test]
fn phase2_new_creates_accumulator() {
    let (r1cs, _wtns) = create_test_artifacts();
    let ptau = NamedTempFile::new().unwrap();
    fs::write(ptau.path(), build_synthetic_ptau(4)).unwrap();
    let zkey = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("phase2")
        .arg("new")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--srs")
        .arg(ptau.path())
        .arg("--zkey")
        .arg(zkey.path());

    cmd.assert()
        .success()
        .stderr(predicate::str::contains(
            "Loaded circuit: 8 wires, 3 constraints",
        ))
        .stderr(predicate::str::contains("Accumulator initialized"))
        .stderr(predicate::str::contains("Initial accumulator written to"));

    let zkey_bytes = fs::read(zkey.path()).unwrap();
    assert!(!zkey_bytes.is_empty(), "accumulator should be written");
}

#[test]
fn phase2_contribute_and_verify() {
    let (r1cs, _wtns) = create_test_artifacts();
    let ptau = NamedTempFile::new().unwrap();
    fs::write(ptau.path(), build_synthetic_ptau(4)).unwrap();
    let zkey0 = NamedTempFile::new().unwrap();
    let zkey1 = NamedTempFile::new().unwrap();

    // 1. New
    let mut cmd_new = Command::cargo_bin("groth16-prover").unwrap();
    cmd_new
        .arg("phase2")
        .arg("new")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--srs")
        .arg(ptau.path())
        .arg("--zkey")
        .arg(zkey0.path());
    cmd_new.assert().success();

    // 2. Contribute
    let mut cmd_contrib = Command::cargo_bin("groth16-prover").unwrap();
    cmd_contrib
        .arg("phase2")
        .arg("contribute")
        .arg("--zkey-in")
        .arg(zkey0.path())
        .arg("--zkey-out")
        .arg(zkey1.path())
        .arg("--name")
        .arg("Alice");
    cmd_contrib
        .assert()
        .success()
        .stderr(predicate::str::contains("Contribution applied by 'Alice'."))
        .stderr(predicate::str::contains("Accumulator written to"));

    // 3. Verify
    let mut cmd_verify = Command::cargo_bin("groth16-prover").unwrap();
    cmd_verify
        .arg("phase2")
        .arg("verify")
        .arg("--zkey")
        .arg(zkey1.path());
    cmd_verify
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Accumulator is valid. All 1 contribution(s) passed verification.",
        ));
}

#[test]
fn phase2_full_roundtrip_prove_verify() {
    let (r1cs, wtns) = create_test_artifacts();
    let ptau = NamedTempFile::new().unwrap();
    fs::write(ptau.path(), build_synthetic_ptau(4)).unwrap();
    let zkey0 = NamedTempFile::new().unwrap();
    let zkey1 = NamedTempFile::new().unwrap();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();
    let out_file = NamedTempFile::new().unwrap();

    // 1. New
    let mut cmd_new = Command::cargo_bin("groth16-prover").unwrap();
    cmd_new
        .arg("phase2")
        .arg("new")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--srs")
        .arg(ptau.path())
        .arg("--zkey")
        .arg(zkey0.path());
    cmd_new.assert().success();

    // 2. Contribute
    let mut cmd_contrib = Command::cargo_bin("groth16-prover").unwrap();
    cmd_contrib
        .arg("phase2")
        .arg("contribute")
        .arg("--zkey-in")
        .arg(zkey0.path())
        .arg("--zkey-out")
        .arg(zkey1.path());
    cmd_contrib.assert().success();

    // 3. Finalize
    let mut cmd_final = Command::cargo_bin("groth16-prover").unwrap();
    cmd_final
        .arg("phase2")
        .arg("finalize")
        .arg("--zkey")
        .arg(zkey1.path())
        .arg("--proving-key")
        .arg(pk_file.path())
        .arg("--verifying-key")
        .arg(vk_file.path());
    cmd_final
        .assert()
        .success()
        .stderr(predicate::str::contains("Accumulator finalized"))
        .stderr(predicate::str::contains("Proving key written to"))
        .stderr(predicate::str::contains("Verifying key written to"));

    // 4. Prove
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

    // 5. Verify
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

// ------------------------------------------------------------------
// SMT command tests
// ------------------------------------------------------------------

#[test]
fn smt_insert_and_digest() {
    let state_file = NamedTempFile::new().unwrap();

    // Insert items
    let mut cmd_insert = Command::cargo_bin("groth16-prover").unwrap();
    cmd_insert
        .arg("smt")
        .arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--items")
        .arg("1 100,2 200")
        .arg("--state")
        .arg(state_file.path());
    cmd_insert
        .assert()
        .success()
        .stderr(predicate::str::contains("Inserted items into SMT"))
        .stderr(predicate::str::contains("digest:"));

    // Verify state file was written and contains valid JSON
    let state_text = fs::read_to_string(state_file.path()).unwrap();
    let state_json: serde_json::Value = serde_json::from_str(&state_text).unwrap();
    assert_eq!(state_json["depth"], 2);
    assert!(
        state_json["digest"].as_str().unwrap().len() > 0,
        "digest should be non-empty"
    );

    // Print digest
    let mut cmd_digest = Command::cargo_bin("groth16-prover").unwrap();
    cmd_digest
        .arg("smt")
        .arg("digest")
        .arg("--state")
        .arg(state_file.path());
    cmd_digest
        .assert()
        .success()
        .stdout(predicate::str::contains(
            state_json["digest"].as_str().unwrap(),
        ));
}

#[test]
fn smt_insert_raw_commitments() {
    let state_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("smt")
        .arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--items")
        .arg("10,20,30")
        .arg("--state")
        .arg(state_file.path());

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Inserted items into SMT"));

    let state_text = fs::read_to_string(state_file.path()).unwrap();
    let state_json: serde_json::Value = serde_json::from_str(&state_text).unwrap();
    assert_eq!(state_json["depth"], 2);
    assert!(state_json["digest"].as_str().unwrap().len() > 0);
}

#[test]
fn smt_path_prints_digest() {
    let state_file = NamedTempFile::new().unwrap();

    // First insert so we have a state file
    let mut cmd_insert = Command::cargo_bin("groth16-prover").unwrap();
    cmd_insert
        .arg("smt")
        .arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--items")
        .arg("1 100")
        .arg("--state")
        .arg(state_file.path());
    cmd_insert.assert().success();

    // Now query path
    let mut cmd_path = Command::cargo_bin("groth16-prover").unwrap();
    cmd_path
        .arg("smt")
        .arg("path")
        .arg("--state")
        .arg(state_file.path())
        .arg("--leaf")
        .arg("1");
    cmd_path
        .assert()
        .success()
        .stdout(predicate::str::contains("digest:"));
}

#[test]
fn smt_missing_state_file() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("smt")
        .arg("digest")
        .arg("--state")
        .arg("/nonexistent/path/smt.json");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to read state file"));
}

// ------------------------------------------------------------------
// compute-inputs command tests
// ------------------------------------------------------------------

#[test]
fn compute_inputs_basic() {
    let transcript = NamedTempFile::new().unwrap();
    fs::write(transcript.path(), "1 100\n2 200\n3 300\n").unwrap();
    let out_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("compute-inputs")
        .arg("--depth")
        .arg("2")
        .arg("--transcript")
        .arg(transcript.path())
        .arg("--nullifier")
        .arg("2")
        .arg("--out")
        .arg(out_file.path());

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Witness input written to"))
        .stderr(predicate::str::contains("digest:"))
        .stderr(predicate::str::contains("nullifier:"))
        .stderr(predicate::str::contains("nonce:"))
        .stderr(predicate::str::contains("siblings:"));

    // Verify JSON output
    let json_text = fs::read_to_string(out_file.path()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&json_text).unwrap();
    assert_eq!(json["nullifier"], "2");
    assert_eq!(json["nonce"], "200");
    assert!(json["digest"].as_str().unwrap().len() > 0);
    assert!(json["sibling[0]"].is_string());
    assert!(json["sibling[1]"].is_string());
    assert!(json["direction[0]"].is_string());
    assert!(json["direction[1]"].is_string());
}

#[test]
fn compute_inputs_nullifier_not_found() {
    let transcript = NamedTempFile::new().unwrap();
    fs::write(transcript.path(), "1 100\n2 200\n").unwrap();
    let out_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("compute-inputs")
        .arg("--depth")
        .arg("2")
        .arg("--transcript")
        .arg(transcript.path())
        .arg("--nullifier")
        .arg("99")
        .arg("--out")
        .arg(out_file.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Nullifier not found"));
}

#[test]
fn compute_inputs_with_raw_commitments() {
    let transcript = NamedTempFile::new().unwrap();
    fs::write(transcript.path(), "10\n20\n30\n").unwrap();
    let out_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("compute-inputs")
        .arg("--depth")
        .arg("2")
        .arg("--transcript")
        .arg(transcript.path())
        .arg("--nullifier")
        .arg("10")
        .arg("--out")
        .arg(out_file.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Nullifier not found"));
}

#[test]
fn compute_inputs_missing_transcript() {
    let out_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("compute-inputs")
        .arg("--depth")
        .arg("2")
        .arg("--transcript")
        .arg("/nonexistent/transcript.txt")
        .arg("--nullifier")
        .arg("1")
        .arg("--out")
        .arg(out_file.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to read transcript"));
}
