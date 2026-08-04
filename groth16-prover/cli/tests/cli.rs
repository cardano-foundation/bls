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
        .stderr(predicate::str::contains("Full proving key (uncompressed) written to"))
        .stderr(predicate::str::contains("Verifying key (uncompressed) written to"));

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

/// Run a full ceremony-dev --h-scalar → prove → verify round-trip.
#[test]
fn full_ceremony_dev_h_scalar_prove_verify_roundtrip() {
    let (r1cs, wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();
    let out_file = NamedTempFile::new().unwrap();

    // 1. Dev ceremony with h_scalar compression
    let mut cmd_ceremony = Command::cargo_bin("groth16-prover").unwrap();
    cmd_ceremony
        .arg("ceremony-dev")
        .arg("--h-scalar")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--proving-key")
        .arg(pk_file.path())
        .arg("--verifying-key")
        .arg(vk_file.path());
    cmd_ceremony
        .assert()
        .success()
        .stderr(predicate::str::contains("h_scalar compression (Implementation 7)"))
        .stderr(predicate::str::contains("Full proving key (uncompressed) written to"))
        .stderr(predicate::str::contains("Verifying key (uncompressed) written to"));

    // 2. Prove with the h_scalar FullProvingKey
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
        .stderr(predicate::str::contains("Inserted"))
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
        .stderr(predicate::str::contains("Inserted"));

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
        .arg("42")
        .arg("--state")
        .arg(state_file.path());
    cmd_insert.assert().success();

    // Now query path for the inserted leaf
    let mut cmd_path = Command::cargo_bin("groth16-prover").unwrap();
    cmd_path
        .arg("smt")
        .arg("path")
        .arg("--state")
        .arg(state_file.path())
        .arg("--leaf")
        .arg("42");
    cmd_path
        .assert()
        .success()
        .stdout(predicate::str::contains("digest:"))
        .stdout(predicate::str::contains("level 0:"));
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

#[test]
fn smt_verify_valid_path() {
    let state_file = NamedTempFile::new().unwrap();

    // Insert raw commitments
    let mut cmd_insert = Command::cargo_bin("groth16-prover").unwrap();
    cmd_insert
        .arg("smt")
        .arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--items")
        .arg("10,20")
        .arg("--state")
        .arg(state_file.path());
    cmd_insert.assert().success();

    // Verify path for a known commitment
    let mut cmd_verify = Command::cargo_bin("groth16-prover").unwrap();
    cmd_verify
        .arg("smt")
        .arg("verify")
        .arg("--state")
        .arg(state_file.path())
        .arg("--leaf")
        .arg("10");
    cmd_verify
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));
}

#[test]
fn smt_verify_invalid_path() {
    let state_file = NamedTempFile::new().unwrap();

    let mut cmd_insert = Command::cargo_bin("groth16-prover").unwrap();
    cmd_insert
        .arg("smt")
        .arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--items")
        .arg("10,20")
        .arg("--state")
        .arg(state_file.path());
    cmd_insert.assert().success();

    // Verify path for a leaf NOT in the tree
    let mut cmd_verify = Command::cargo_bin("groth16-prover").unwrap();
    cmd_verify
        .arg("smt")
        .arg("verify")
        .arg("--state")
        .arg(state_file.path())
        .arg("--leaf")
        .arg("999");
    cmd_verify
        .assert()
        .success()
        .stdout(predicate::str::contains("INVALID"))
        .stdout(predicate::str::contains("not found in tree"));
}

#[test]
fn smt_export_creates_input_json() {
    let state_file = NamedTempFile::new().unwrap();
    let input_file = NamedTempFile::new().unwrap();

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
    cmd_insert.assert().success();

    let mut cmd_export = Command::cargo_bin("groth16-prover").unwrap();
    cmd_export
        .arg("smt")
        .arg("export")
        .arg("--state")
        .arg(state_file.path())
        .arg("--nullifier")
        .arg("1")
        .arg("--out")
        .arg(input_file.path());
    cmd_export
        .assert()
        .success()
        .stderr(predicate::str::contains("Witness input written to"));

    let input_text = fs::read_to_string(input_file.path()).unwrap();
    let input_json: serde_json::Value = serde_json::from_str(&input_text).unwrap();
    assert!(input_json["digest"].as_str().unwrap().len() > 0);
    assert_eq!(input_json["nullifier"], "1");
    assert!(input_json["nonce"].as_str().unwrap().len() > 0);
}

#[test]
fn smt_insert_from_transcript_file() {
    let state_file = NamedTempFile::new().unwrap();
    let transcript_file = NamedTempFile::new().unwrap();

    fs::write(
        transcript_file.path(),
        "1 100\n2 200\n3 300\n",
    ).unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("smt")
        .arg("insert")
        .arg("--depth")
        .arg("2")
        .arg("--transcript")
        .arg(transcript_file.path())
        .arg("--state")
        .arg(state_file.path());

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Inserted 3 item(s) into SMT"));

    let state_text = fs::read_to_string(state_file.path()).unwrap();
    let state_json: serde_json::Value = serde_json::from_str(&state_text).unwrap();
    assert_eq!(state_json["depth"], 2);
    assert!(state_json["digest"].as_str().unwrap().len() > 0);
    assert_eq!(state_json["items"].as_array().unwrap().len(), 3);
}

// ------------------------------------------------------------------
// Sparse mode CLI tests (Implementation 6)
// ------------------------------------------------------------------

#[test]
fn ceremony_dev_sparse() {
    let (r1cs, _wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("ceremony-dev")
        .arg("--sparse")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--proving-key")
        .arg(pk_file.path())
        .arg("--verifying-key")
        .arg(vk_file.path());

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Loaded circuit (sparse)"))
        .stderr(predicate::str::contains("Dev ceremony complete"))
        .stderr(predicate::str::contains("Full proving key (uncompressed) written to"))
        .stderr(predicate::str::contains("Verifying key (uncompressed) written to"));
}

#[test]
fn prove_sparse_stdout() {
    let (r1cs, wtns) = create_test_artifacts();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--sparse")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path());

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Loaded circuit (sparse)"))
        .stderr(predicate::str::contains(
            "Using sparse on-the-fly QAP construction",
        ))
        .stderr(predicate::str::contains(
            "Proof generated successfully (sparse path)",
        ))
        .stdout(predicate::function(|output: &str| {
            hex::decode(output.trim()).is_ok() && output.trim().len() == 384
        }));
}

#[test]
fn prove_sparse_to_file() {
    let (r1cs, wtns) = create_test_artifacts();
    let out_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--sparse")
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

    let proof = fs::read(out_file.path()).unwrap();
    assert_eq!(proof.len(), 192, "proof must be 192 bytes");

    let pub_path = out_file.path().with_extension("pub");
    let public = fs::read(&pub_path).unwrap();
    assert_eq!(public.len(), 48, "public input must be 48 bytes");
}

#[test]
fn prove_sparse_naive() {
    let (r1cs, wtns) = create_test_artifacts();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--sparse")
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
fn prove_sparse_rejects_qap_not_on_fly() {
    let (r1cs, wtns) = create_test_artifacts();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove")
        .arg("--sparse")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--witness")
        .arg(wtns.path())
        .arg("--qap-not-on-fly");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains(
            "--qap-not-on-fly is incompatible with --sparse",
        ));
}

/// Full sparse roundtrip: ceremony-dev --sparse → prove --sparse → verify
#[test]
fn full_sparse_roundtrip() {
    let (r1cs, wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();
    let out_file = NamedTempFile::new().unwrap();

    // 1. Sparse dev ceremony
    let mut cmd_ceremony = Command::cargo_bin("groth16-prover").unwrap();
    cmd_ceremony
        .arg("ceremony-dev")
        .arg("--sparse")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--proving-key")
        .arg(pk_file.path())
        .arg("--verifying-key")
        .arg(vk_file.path());
    cmd_ceremony
        .assert()
        .success()
        .stderr(predicate::str::contains("Dev ceremony complete"));

    // 2. Sparse prove with generated PK
    let mut cmd_prove = Command::cargo_bin("groth16-prover").unwrap();
    cmd_prove
        .arg("prove")
        .arg("--sparse")
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

    // 3. Verify
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

// ------------------------------------------------------------------
// AnonymousAirdrop end-to-end test
// ------------------------------------------------------------------

fn airdrop_input_json_accepted() -> String {
    // Carol: nullifier=3, nonce=300, score=120, minScore=100
    // SMT built from credentials (1,100,85), (2,200,42), (3,300,120)
    r#"{
  "digest": "11532464310312174561046533224304711315458591992375104258711270731788815721034",
  "minScore": "100",
  "nullifier": "3",
  "nonce": "300",
  "score": "120",
  "sibling": ["0", "47252287271164011656207288696370005352642778257683443251406641354340159993877"],
  "direction": ["0", "1"]
}"#.to_string()
}

fn airdrop_input_json_rejected() -> String {
    // Bob: nullifier=2, nonce=200, score=42, minScore=100
    r#"{
  "digest": "11532464310312174561046533224304711315458591992375104258711270731788815721034",
  "minScore": "100",
  "nullifier": "2",
  "nonce": "200",
  "score": "42",
  "sibling": ["35160131748704873718595568135151760221085503677314381633708407820008083539060", "17658844911186938366405770927670297620261209849670034280597915862109464511349"],
  "direction": ["1", "0"]
}"#.to_string()
}

/// Full pipeline for the AnonymousAirdrop circuit:
///   generate input.json → snarkjs witness → ceremony-dev → prove → verify
///
/// Skips if snarkjs or compiled circom artifacts are not present.
#[test]
fn anonymous_airdrop_e2e_accepted() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent().unwrap();
    let airdrop_dir = repo_root.join("circom/AnonymousAirdrop");
    let r1cs = airdrop_dir.join("anonymous_airdrop_depth2.r1cs");
    let wasm = airdrop_dir.join("anonymous_airdrop_depth2_js/anonymous_airdrop_depth2.wasm");

    if !r1cs.exists() || !wasm.exists() {
        eprintln!("AnonymousAirdrop compiled artifacts missing; skipping e2e test");
        return;
    }

    if std::process::Command::new("snarkjs").arg("--version").output().is_err() {
        eprintln!("snarkjs not installed; skipping e2e test");
        return;
    }

    let input_file = NamedTempFile::new().unwrap();
    fs::write(input_file.path(), airdrop_input_json_accepted()).unwrap();

    let wtns_file = NamedTempFile::new().unwrap();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();
    let proof_file = NamedTempFile::new().unwrap();

    // 1. Generate witness with snarkjs
    let mut snarkjs = std::process::Command::new("snarkjs");
    snarkjs
        .arg("wtns")
        .arg("calculate")
        .arg(&wasm)
        .arg(input_file.path())
        .arg(wtns_file.path());
    let out = snarkjs.output().expect("snarkjs failed");
    assert!(
        out.status.success(),
        "snarkjs witness generation failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // 2. Dev ceremony
    let mut cmd_ceremony = Command::cargo_bin("groth16-prover").unwrap();
    cmd_ceremony
        .arg("ceremony-dev")
        .arg("--circuit")
        .arg(&r1cs)
        .arg("--proving-key")
        .arg(pk_file.path())
        .arg("--verifying-key")
        .arg(vk_file.path());
    cmd_ceremony.assert().success();

    // 3. Prove
    let mut cmd_prove = Command::cargo_bin("groth16-prover").unwrap();
    cmd_prove
        .arg("prove")
        .arg("--circuit")
        .arg(&r1cs)
        .arg("--witness")
        .arg(wtns_file.path())
        .arg("--proving-key")
        .arg(pk_file.path())
        .arg("--out")
        .arg(proof_file.path());
    cmd_prove.assert().success();

    // 4. Verify
    let pub_file = proof_file.path().with_extension("pub");
    let mut cmd_verify = Command::cargo_bin("groth16-prover").unwrap();
    cmd_verify
        .arg("verify")
        .arg("--proof")
        .arg(proof_file.path())
        .arg("--public")
        .arg(&pub_file)
        .arg("--verifying-key")
        .arg(vk_file.path());
    cmd_verify
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"));
}

/// Rejected case: score < minScore should fail at witness generation.
#[test]
fn anonymous_airdrop_e2e_rejected() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir.parent().unwrap();
    let airdrop_dir = repo_root.join("circom/AnonymousAirdrop");
    let wasm = airdrop_dir.join("anonymous_airdrop_depth2_js/anonymous_airdrop_depth2.wasm");

    if !wasm.exists() {
        eprintln!("AnonymousAirdrop WASM artifact missing; skipping rejected e2e test");
        return;
    }

    if std::process::Command::new("snarkjs").arg("--version").output().is_err() {
        eprintln!("snarkjs not installed; skipping rejected e2e test");
        return;
    }

    let input_file = NamedTempFile::new().unwrap();
    fs::write(input_file.path(), airdrop_input_json_rejected()).unwrap();

    let wtns_file = NamedTempFile::new().unwrap();

    let mut snarkjs = std::process::Command::new("snarkjs");
    snarkjs
        .arg("wtns")
        .arg("calculate")
        .arg(&wasm)
        .arg(input_file.path())
        .arg(wtns_file.path());
    let out = snarkjs.output().expect("snarkjs failed");

    // Witness generation must fail because score (42) < minScore (100)
    assert!(
        !out.status.success(),
        "Expected witness generation to fail for rejected input, but it succeeded"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Assert Failed") || stderr.contains("Error"),
        "Expected assertion error, got: {}", stderr
    );
}

// ------------------------------------------------------------------
// Nova / Implementation 8 — CardanoKeyOwnership step-chain tests
//
// Implementation 8 splits the monolithic Ed25519 key-ownership proof into a
// chain of `BitElementMulAny` steps (one scalar-mul bit per step).  The step
// circuit `cardano_ed25519_ownership_nova.circom` has `n_pub_in == n_pub_out
// == 24` (the IVC state = (dblIn[4][3], addIn[4][3])), which `nova` enforces.
//
// The committed monolithic circuits (`cardano_ed25519_ownership.r1cs`,
// `cardano_key_ownership.r1cs`) must be *rejected* by `nova params` because
// their public-input width does not equal their public-output width.  The
// step-circuit tests (compile the .circom with
// `circom --prime bls12381 --r1cs --wasm`) skip when the compiled artifacts
// are not present, mirroring the AnonymousAirdrop e2e tests.
// ------------------------------------------------------------------

fn cardano_key_ownership_dir() -> std::path::PathBuf {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .unwrap()
        .join("circom/CardanoKeyOwnership")
}

/// True if the user compiled the Nova step circuit (r1cs + wasm).
fn nova_step_artifacts_present() -> bool {
    let dir = cardano_key_ownership_dir();
    dir.join("cardano_ed25519_ownership_nova.r1cs").exists()
        && dir
            .join("cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm")
            .exists()
}

fn snarkjs_available() -> bool {
    std::process::Command::new("snarkjs")
        .arg("--version")
        .output()
        .is_ok()
}

/// Curve25519 base point G in extended coordinates, base-2^85 limbs
/// (from `cardano_ed25519_ownership.circom`).
const ED25519_BASE_POINT_G: [[&str; 3]; 4] = [
    [
        "6836562328990639286768922",
        "21231440843933962135602345",
        "10097852978535018773096760",
    ],
    [
        "7737125245533626718119512",
        "23211375736600880154358579",
        "30948500982134506872478105",
    ],
    ["1", "0", "0"],
    [
        "20943500354259764865654179",
        "24722277920680796426601402",
        "31289658119428895172835987",
    ],
];

/// Edwards identity in extended coordinates (X=0, Y=1, Z=1, T=0).
const EDWARDS_IDENTITY: [[&str; 3]; 4] = [
    ["0", "0", "0"],
    ["1", "0", "0"],
    ["1", "0", "0"],
    ["0", "0", "0"],
];

/// Build one step's input JSON from the current (dblIn, addIn) state.
fn step_input_json(dbl: &[[String; 3]; 4], add: &[[String; 3]; 4], sel: &str) -> String {
    let mut fields = serde_json::Map::new();
    for (i, row) in dbl.iter().enumerate() {
        for (j, v) in row.iter().enumerate() {
            fields.insert(
                format!("dbl_in_{i}_{j}"),
                serde_json::Value::String(v.clone()),
            );
        }
    }
    for (i, row) in add.iter().enumerate() {
        for (j, v) in row.iter().enumerate() {
            fields.insert(
                format!("add_in_{i}_{j}"),
                serde_json::Value::String(v.clone()),
            );
        }
    }
    fields.insert("sel".into(), serde_json::Value::String(sel.into()));
    serde_json::Value::Object(fields).to_string()
}

/// Extract a [4][3] block (12 values) starting at witness index `base`.
fn extract_witness_state(w: &[serde_json::Value], base: usize) -> [[String; 3]; 4] {
    std::array::from_fn(|i| {
        std::array::from_fn(|j| w[base + 3 * i + j].as_str().unwrap().to_string())
    })
}

/// Generate `count` chained step witnesses with snarkjs into `dir`.
///
/// The state starts at (dblIn = G, addIn = identity) and each step's public
/// outputs (witness indices 1..25) feed the next step's public inputs, so the
/// `state_in[i+1] == state_out[i]` chain invariant holds by construction.
fn generate_nova_step_witnesses(
    dir: &std::path::Path,
    wasm: &std::path::Path,
    count: usize,
) -> Result<(), String> {
    let mut dbl = ED25519_BASE_POINT_G.map(|r| r.map(String::from));
    let mut add = EDWARDS_IDENTITY.map(|r| r.map(String::from));

    for i in 0..count {
        let input_path = dir.join(format!("input_{i}.json"));
        let wtns_path = dir.join(format!("step_{i:04}.wtns"));
        let json_path = dir.join(format!("step_{i:04}.json"));

        fs::write(&input_path, step_input_json(&dbl, &add, "1"))
            .map_err(|e| format!("failed to write {}: {e}", input_path.display()))?;

        let status = std::process::Command::new("snarkjs")
            .arg("wtns")
            .arg("calculate")
            .arg(wasm)
            .arg(&input_path)
            .arg(&wtns_path)
            .status()
            .map_err(|e| format!("snarkjs failed to start: {e}"))?;
        if !status.success() {
            return Err(format!(
                "snarkjs wtns calculate failed for step {i} ({} != 0)",
                status.code().unwrap_or(-1)
            ));
        }

        let status = std::process::Command::new("snarkjs")
            .arg("wtns")
            .arg("export")
            .arg("json")
            .arg(&wtns_path)
            .arg(&json_path)
            .status()
            .map_err(|e| format!("snarkjs failed to start: {e}"))?;
        if !status.success() {
            return Err(format!(
                "snarkjs wtns export json failed for step {i} ({} != 0)",
                status.code().unwrap_or(-1)
            ));
        }

        let w: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&json_path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let w = w.as_array().ok_or("witness JSON is not an array")?;
        if w.len() < 25 {
            return Err(format!(
                "witness JSON has {} elements, expected >= 25",
                w.len()
            ));
        }
        // Public outputs (24) live at indices 1..25: [dblOut, addOut].
        dbl = extract_witness_state(w, 1);
        add = extract_witness_state(w, 13);
    }
    Ok(())
}

/// `nova params` must reject the monolithic Ed25519 ownership circuit:
/// its 256-bit public input `A` is not an IVC state.
#[test]
fn nova_params_rejects_monolithic_ed25519_ownership() {
    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership.r1cs");
    assert!(
        circuit.exists(),
        "missing committed fixture {}",
        circuit.display()
    );

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("nova").arg("params").arg("--circuit").arg(&circuit);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid step circuit"))
        .stderr(predicate::str::contains("n_pub_in (256) != n_pub_out (1)"));
}

/// Same invariant for the JubJub ownership circuit (public in = 2, public out = 0).
#[test]
fn nova_params_rejects_jubjub_ownership() {
    let circuit = cardano_key_ownership_dir().join("cardano_key_ownership.r1cs");
    assert!(
        circuit.exists(),
        "missing committed fixture {}",
        circuit.display()
    );

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("nova").arg("params").arg("--circuit").arg(&circuit);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid step circuit"))
        .stderr(predicate::str::contains("n_pub_in (2) != n_pub_out (0)"));
}

/// The synthetic multiplier circuit (1 pub out, 0 pub in) is not a step circuit.
#[test]
fn nova_params_rejects_non_step_circuit() {
    let r1cs = NamedTempFile::new().unwrap();
    fs::write(r1cs.path(), build_synthetic_r1cs()).unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("nova")
        .arg("params")
        .arg("--circuit")
        .arg(r1cs.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid step circuit"))
        .stderr(predicate::str::contains("n_pub_in (0) != n_pub_out (1)"));
}

#[test]
fn nova_params_missing_circuit() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("nova")
        .arg("params")
        .arg("--circuit")
        .arg("/tmp/does-not-exist-nova.r1cs");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to load circuit"));
}

#[test]
fn nova_params_invalid_circuit() {
    let bad_r1cs = NamedTempFile::new().unwrap();
    fs::write(bad_r1cs.path(), b"not_a_valid_r1cs_file").unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("nova")
        .arg("params")
        .arg("--circuit")
        .arg(bad_r1cs.path());

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to load circuit"));
}

/// `nova params` on the compiled step circuit reports the IVC state shape:
/// 24 public inputs = 24 public outputs, 1 private `sel` bit.
#[test]
fn nova_params_accepts_cardano_ed25519_ownership_step() {
    if !nova_step_artifacts_present() {
        eprintln!("Nova step circuit artifacts missing; skipping params test");
        return;
    }

    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership_nova.r1cs");

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("nova").arg("params").arg("--circuit").arg(&circuit);

    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "nova params failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let desc: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(desc["n_pub_out"], 24);
    assert_eq!(desc["n_pub_in"], 24);
    assert_eq!(desc["n_prv_in"], 1);
    assert!(desc["n_constraints"].as_u64().unwrap() > 0);
}

/// Run `nova ceremony` + `nova fold` over a chained witness directory and
/// return the (pk, vk, ivc) temp files.
fn nova_ceremony_and_fold(
    circuit: &std::path::Path,
    steps_dir: &std::path::Path,
) -> (NamedTempFile, NamedTempFile, NamedTempFile) {
    let pk = NamedTempFile::new().unwrap();
    let vk = NamedTempFile::new().unwrap();

    let mut ceremony = Command::cargo_bin("groth16-prover").unwrap();
    ceremony
        .arg("nova")
        .arg("ceremony")
        .arg("--circuit")
        .arg(circuit)
        .arg("--proving-key")
        .arg(pk.path())
        .arg("--verifying-key")
        .arg(vk.path());
    ceremony.assert().success();

    let ivc = NamedTempFile::new().unwrap();
    let mut fold = Command::cargo_bin("groth16-prover").unwrap();
    fold.arg("nova")
        .arg("fold")
        .arg("--circuit")
        .arg(circuit)
        .arg("--proving-key")
        .arg(pk.path())
        .arg("--steps")
        .arg(steps_dir)
        .arg("--out")
        .arg(ivc.path());
    fold.assert().success();

    (pk, vk, ivc)
}

/// Full Implementation 8 flow on CardanoKeyOwnership:
/// ceremony → fold → verify over a 3-step Ed25519 scalar-mul chain.
#[test]
fn cardano_ed25519_ownership_nova_fold_verify_e2e() {
    if !nova_step_artifacts_present() {
        eprintln!("Nova step circuit artifacts missing; skipping e2e test");
        return;
    }
    if !snarkjs_available() {
        eprintln!("snarkjs not installed; skipping e2e test");
        return;
    }

    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership_nova.r1cs");
    let wasm = cardano_key_ownership_dir()
        .join("cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm");

    let steps_dir = tempfile::tempdir().unwrap();
    generate_nova_step_witnesses(steps_dir.path(), &wasm, 3).unwrap();

    let (_pk, vk, ivc) = nova_ceremony_and_fold(&circuit, steps_dir.path());

    let mut verify = Command::cargo_bin("groth16-prover").unwrap();
    verify
        .arg("nova")
        .arg("verify")
        .arg("--ivc")
        .arg(ivc.path())
        .arg("--verifying-key")
        .arg(vk.path());
    verify
        .assert()
        .success()
        .stderr(predicate::str::contains("Verified 3 steps"));
}

/// `nova fold` isolates the exact step whose `state_in` breaks the chain:
/// step 1 must be reported when step_0001.wtns does not follow step_0000.wtns.
#[test]
fn cardano_ed25519_ownership_nova_fold_rejects_broken_chain() {
    if !nova_step_artifacts_present() {
        eprintln!("Nova step circuit artifacts missing; skipping broken-chain test");
        return;
    }
    if !snarkjs_available() {
        eprintln!("snarkjs not installed; skipping broken-chain test");
        return;
    }

    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership_nova.r1cs");
    let wasm = cardano_key_ownership_dir()
        .join("cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm");

    // Generate 3 consecutive witnesses, then drop step 1 from the chain.
    let full_dir = tempfile::tempdir().unwrap();
    generate_nova_step_witnesses(full_dir.path(), &wasm, 3).unwrap();

    let broken_dir = tempfile::tempdir().unwrap();
    fs::copy(
        full_dir.path().join("step_0000.wtns"),
        broken_dir.path().join("step_0000.wtns"),
    )
    .unwrap();
    fs::copy(
        full_dir.path().join("step_0002.wtns"),
        broken_dir.path().join("step_0001.wtns"),
    )
    .unwrap();

    let (_pk, _vk, _ivc) = {
        let pk = NamedTempFile::new().unwrap();
        let vk = NamedTempFile::new().unwrap();
        let mut ceremony = Command::cargo_bin("groth16-prover").unwrap();
        ceremony
            .arg("nova")
            .arg("ceremony")
            .arg("--circuit")
            .arg(&circuit)
            .arg("--proving-key")
            .arg(pk.path())
            .arg("--verifying-key")
            .arg(vk.path());
        ceremony.assert().success();

        let ivc = NamedTempFile::new().unwrap();
        let mut fold = Command::cargo_bin("groth16-prover").unwrap();
        fold.arg("nova")
            .arg("fold")
            .arg("--circuit")
            .arg(&circuit)
            .arg("--proving-key")
            .arg(pk.path())
            .arg("--steps")
            .arg(broken_dir.path())
            .arg("--out")
            .arg(ivc.path());
        fold.assert()
            .failure()
            .stderr(predicate::str::contains(
                "state_in does not chain to previous state_out",
            ))
            .stderr(predicate::str::contains("step_0001.wtns"));
        (pk, vk, ivc)
    };
}

/// Tampering with any part of the IVC bundle is detected at verify time:
/// a modified final transcript fails the deterministic BLAKE2b512 re-derivation.
#[test]
fn cardano_ed25519_ownership_nova_verify_rejects_tampered_bundle() {
    if !nova_step_artifacts_present() {
        eprintln!("Nova step circuit artifacts missing; skipping tamper test");
        return;
    }
    if !snarkjs_available() {
        eprintln!("snarkjs not installed; skipping tamper test");
        return;
    }

    let circuit = cardano_key_ownership_dir().join("cardano_ed25519_ownership_nova.r1cs");
    let wasm = cardano_key_ownership_dir()
        .join("cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm");

    let steps_dir = tempfile::tempdir().unwrap();
    generate_nova_step_witnesses(steps_dir.path(), &wasm, 3).unwrap();

    let (_pk, vk, ivc) = nova_ceremony_and_fold(&circuit, steps_dir.path());

    // Corrupt the final transcript digest in the bundle.
    let mut bundle: serde_json::Value =
        serde_json::from_slice(&fs::read(ivc.path()).unwrap()).unwrap();
    bundle["transcript_final"] = serde_json::Value::String("0".repeat(128));
    fs::write(ivc.path(), serde_json::to_vec_pretty(&bundle).unwrap()).unwrap();

    let mut verify = Command::cargo_bin("groth16-prover").unwrap();
    verify
        .arg("nova")
        .arg("verify")
        .arg("--ivc")
        .arg(ivc.path())
        .arg("--verifying-key")
        .arg(vk.path());
    verify
        .assert()
        .failure()
        .stderr(predicate::str::contains("final transcript mismatch"));
}

// ------------------------------------------------------------------
// export-vk command tests
// ------------------------------------------------------------------

/// `export-vk` produces valid Aiken source from a binary verifying key.
#[test]
fn export_vk_produces_aiken_source() {
    let (r1cs, wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();
    let out_file = NamedTempFile::new().unwrap();

    // Generate a VK via ceremony-dev
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

    // Export to a file
    let mut cmd_export = Command::cargo_bin("groth16-prover").unwrap();
    cmd_export
        .arg("export-vk")
        .arg("--verifying-key")
        .arg(vk_file.path())
        .arg("--out")
        .arg(out_file.path());
    cmd_export
        .assert()
        .success()
        .stderr(predicate::str::contains("Aiken verification key source written to"));

    // Verify the output is valid Aiken source
    let aiken_src = fs::read_to_string(out_file.path()).unwrap();
    assert!(aiken_src.contains("pub fn verification_key()"));
    assert!(aiken_src.contains("VerificationKey {"));
    assert!(aiken_src.contains("alpha_g1:"));
    assert!(aiken_src.contains("beta_g2:"));
    assert!(aiken_src.contains("gamma_g2:"));
    assert!(aiken_src.contains("delta_g2:"));
    assert!(aiken_src.contains("ic:"));
    assert!(aiken_src.contains("n_public:"));
}

/// `export-vk` prints Aiken source to stdout when `--out` is omitted.
#[test]
fn export_vk_prints_to_stdout() {
    let (r1cs, _wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();

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

    let mut cmd_export = Command::cargo_bin("groth16-prover").unwrap();
    cmd_export
        .arg("export-vk")
        .arg("--verifying-key")
        .arg(vk_file.path());
    cmd_export
        .assert()
        .success()
        .stdout(predicate::str::contains("pub fn verification_key()"))
        .stdout(predicate::str::contains("VerificationKey {"));
}

/// `export-vk` fails when the verifying key file does not exist.
#[test]
fn export_vk_missing_file() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("export-vk")
        .arg("--verifying-key")
        .arg("/nonexistent/does-not-exist.vk");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to read verifying key"));
}

/// `export-vk` fails when the file is not a valid verifying key.
#[test]
fn export_vk_invalid_file() {
    let bad_vk = NamedTempFile::new().unwrap();
    fs::write(bad_vk.path(), b"not_a_valid_vk_file").unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("export-vk")
        .arg("--verifying-key")
        .arg(bad_vk.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to deserialize verifying key"));
}

// ------------------------------------------------------------------
// --help output tests
// ------------------------------------------------------------------

/// Top-level `--help` prints the usage summary.
#[test]
fn help_top_level() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage: groth16-prover <COMMAND>"))
        .stdout(predicate::str::contains("Commands:"))
        .stdout(predicate::str::contains("ceremony"))
        .stdout(predicate::str::contains("ceremony-dev"))
        .stdout(predicate::str::contains("prove"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("export-vk"))
        .stdout(predicate::str::contains("compute-inputs"))
        .stdout(predicate::str::contains("smt"))
        .stdout(predicate::str::contains("phase2"))
        .stdout(predicate::str::contains("nova"));
}

/// `smt --help` lists all SMT subcommands.
#[test]
fn help_smt() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("smt").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("insert"))
        .stdout(predicate::str::contains("digest"))
        .stdout(predicate::str::contains("path"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("export"));
}

/// `smt insert --help` shows the --depth, --items, --transcript, and --state options.
#[test]
fn help_smt_insert() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("smt").arg("insert").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--depth"))
        .stdout(predicate::str::contains("--items"))
        .stdout(predicate::str::contains("--transcript"))
        .stdout(predicate::str::contains("--state"))
        .stdout(predicate::str::contains("Merkle tree depth (number of levels)"))
        .stdout(predicate::str::contains("Comma-separated list of items to insert"));
}

/// `phase2 --help` lists all Phase-2 subcommands.
#[test]
fn help_phase2() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("phase2").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("new"))
        .stdout(predicate::str::contains("contribute"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("finalize"));
}

/// `phase2 new --help` shows the --circuit, --srs, and --zkey options.
#[test]
fn help_phase2_new() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("phase2").arg("new").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--circuit"))
        .stdout(predicate::str::contains("--srs"))
        .stdout(predicate::str::contains("--zkey"))
        .stdout(predicate::str::contains("Path to the `.r1cs` circuit file"))
        .stdout(predicate::str::contains("Path to the Phase-1 `.ptau` SRS file"));
}

/// `nova --help` lists all Nova subcommands.
#[test]
fn help_nova() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("nova").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("params"))
        .stdout(predicate::str::contains("ceremony"))
        .stdout(predicate::str::contains("fold"))
        .stdout(predicate::str::contains("verify"));
}

/// `nova ceremony --help` shows the --h-scalar option.
#[test]
fn help_nova_ceremony() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("nova").arg("ceremony").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--h-scalar"))
        .stdout(predicate::str::contains("h-query scalar compression"))
        .stdout(predicate::str::contains("Use h-query scalar compression (Implementation 7)"));
}

/// `ceremony-dev --help` shows the --sparse and --h-scalar options.
#[test]
fn help_ceremony_dev() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("ceremony-dev").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--sparse"))
        .stdout(predicate::str::contains("--h-scalar"))
        .stdout(predicate::str::contains("sparse constraint representation"))
        .stdout(predicate::str::contains("h-query scalar compression"));
}

/// `prove --help` shows the --sparse, --engine, and --prover options.
#[test]
fn help_prove() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("prove").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--sparse"))
        .stdout(predicate::str::contains("--engine"))
        .stdout(predicate::str::contains("--prover"))
        .stdout(predicate::str::contains("dense"))
        .stdout(predicate::str::contains("fft"))
        .stdout(predicate::str::contains("naive"))
        .stdout(predicate::str::contains("pippenger"));
}

/// `verify --help` shows the expected options.
#[test]
fn help_verify() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("verify").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--proof"))
        .stdout(predicate::str::contains("--public"))
        .stdout(predicate::str::contains("--verifying-key"));
}

/// `export-vk --help` shows the expected options.
#[test]
fn help_export_vk() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("export-vk").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--verifying-key"))
        .stdout(predicate::str::contains("--out"));
}

/// `compute-inputs --help` shows the expected options.
#[test]
fn help_compute_inputs() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("compute-inputs").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--depth"))
        .stdout(predicate::str::contains("--transcript"))
        .stdout(predicate::str::contains("--nullifier"))
        .stdout(predicate::str::contains("--out"));
}

// ------------------------------------------------------------------
// Error cases for new commands
// ------------------------------------------------------------------

/// `export-vk` fails with a helpful error when no `--verifying-key` is provided.
#[test]
fn export_vk_missing_verifying_key() {
    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("export-vk");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required arguments were not provided"));
}

/// `phase2 new` fails when the circuit file does not exist.
#[test]
fn phase2_new_missing_circuit() {
    let ptau = NamedTempFile::new().unwrap();
    fs::write(ptau.path(), build_synthetic_ptau(4)).unwrap();
    let zkey = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("phase2")
        .arg("new")
        .arg("--circuit")
        .arg("/nonexistent/circuit.r1cs")
        .arg("--srs")
        .arg(ptau.path())
        .arg("--zkey")
        .arg(zkey.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to load circuit"));
}

/// `phase2 new` fails when the SRS file does not exist.
#[test]
fn phase2_new_missing_srs() {
    let (r1cs, _wtns) = create_test_artifacts();
    let zkey = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("phase2")
        .arg("new")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--srs")
        .arg("/nonexistent/universal.ptau")
        .arg("--zkey")
        .arg(zkey.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to open .ptau"));
}

/// `nova ceremony` fails when the circuit file does not exist.
#[test]
fn nova_ceremony_missing_circuit() {
    let pk = NamedTempFile::new().unwrap();
    let vk = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("nova")
        .arg("ceremony")
        .arg("--circuit")
        .arg("/nonexistent/step_circuit.r1cs")
        .arg("--proving-key")
        .arg(pk.path())
        .arg("--verifying-key")
        .arg(vk.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to load circuit"));
}

/// `nova fold` fails early when the circuit is not a valid step circuit
/// (n_pub_in != n_pub_out), before even trying to load the proving key.
#[test]
fn nova_fold_rejects_non_step_circuit() {
    let (r1cs, _wtns) = create_test_artifacts();
    let steps_dir = tempfile::tempdir().unwrap();
    let ivc = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("nova")
        .arg("fold")
        .arg("--circuit")
        .arg(r1cs.path())
        .arg("--proving-key")
        .arg("/nonexistent/step.pk")
        .arg("--steps")
        .arg(steps_dir.path())
        .arg("--out")
        .arg(ivc.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not a valid step circuit"));
}

/// `nova verify` fails when the IVC bundle file does not exist.
#[test]
fn nova_verify_missing_ivc() {
    let vk = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("groth16-prover").unwrap();
    cmd.arg("nova")
        .arg("verify")
        .arg("--ivc")
        .arg("/nonexistent/bundle.ivc.json")
        .arg("--verifying-key")
        .arg(vk.path());
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("failed to read IVC bundle"));
}
