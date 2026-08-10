use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::NamedTempFile;

use ark_bls12_381::{Fq, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;

// ------------------------------------------------------------------
// Synthetic .r1cs / .wtns generators (self-contained tests)
// ------------------------------------------------------------------

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
// Key-generation helpers (mirror the `trusted-setup` CLI output)
// ------------------------------------------------------------------
//
// The ceremony / ceremony-dev commands live in the standalone
// `trusted-setup` CLI. These helpers reproduce their file output through
// the shared library so the groth16 CLI tests stay self-contained.

use ark_serialize::CanonicalSerialize;
use groth16_prover::ceremony::single_party_ceremony_full;
use groth16_prover::circom_adapter::CircomCircuit;
use groth16_prover::engine::FftQapEngine;

/// Run a legacy `ceremony` and write the `.pk` / `.vk` files, matching the
/// `trusted-setup ceremony` CLI output (compressed `ProvingKey`).
fn write_legacy_ceremony_files(
    r1cs: &std::path::Path,
    pk_file: &std::path::Path,
    vk_file: &std::path::Path,
) {
    let circuit = CircomCircuit::from_r1cs(r1cs.to_str().unwrap()).unwrap();
    let n_public = 1 + circuit.n_pub_out as usize + circuit.n_pub_in as usize;
    let engine = FftQapEngine::new();
    let mut rng = rand::thread_rng();
    let (pk, vk) = groth16_prover::ceremony::ceremony(
        &engine,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        n_public,
        &mut rng,
    );
    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes).unwrap();
    fs::write(pk_file, &pk_bytes).unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes).unwrap();
    fs::write(vk_file, &vk_bytes).unwrap();
}

/// Run a `ceremony-dev` and write the `.pk` / `.vk` files, matching the
/// `trusted-setup ceremony-dev` CLI output (uncompressed `FullProvingKey`).
fn write_ceremony_dev_files(
    r1cs: &std::path::Path,
    pk_file: &std::path::Path,
    vk_file: &std::path::Path,
) {
    let circuit = CircomCircuit::from_r1cs(r1cs.to_str().unwrap()).unwrap();
    let n_public = 1 + circuit.n_pub_out as usize + circuit.n_pub_in as usize;
    let engine = FftQapEngine::new();
    let mut rng = rand::thread_rng();
    let (full_pk, vk) = single_party_ceremony_full(
        &engine,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        n_public,
        &mut rng,
        false,
    );
    let mut pk_bytes = Vec::new();
    full_pk.serialize_uncompressed(&mut pk_bytes).unwrap();
    fs::write(pk_file, &pk_bytes).unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes).unwrap();
    fs::write(vk_file, &vk_bytes).unwrap();
}

// ------------------------------------------------------------------
// Success cases
// ------------------------------------------------------------------

#[test]
fn prove_default_stdout() {
    let (r1cs, wtns) = create_test_artifacts();

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    // Legacy ceremony produces a scalar ProvingKey (via the shared library,
    // mirroring `trusted-setup ceremony` output)
    write_legacy_ceremony_files(r1cs.path(), pk_file.path(), vk_file.path());

    // Default prove expects a FullProvingKey and should give a helpful error
    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    // Dev ceremony produces a FullProvingKey (via the shared library,
    // mirroring `trusted-setup ceremony-dev` output)
    write_ceremony_dev_files(r1cs.path(), pk_file.path(), vk_file.path());

    // Legacy path with a FullProvingKey should give a helpful error
    let mut cmd = Command::cargo_bin("groth16").unwrap();
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
            let mut cmd = Command::cargo_bin("groth16").unwrap();
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
    let mut cmd = Command::cargo_bin("groth16").unwrap();
    cmd.arg("prove").arg("--witness").arg("/tmp/dummy.wtns");
    cmd.assert().failure().stderr(predicate::str::contains(
        "required arguments were not provided",
    ));
}

#[test]
fn prove_missing_witness() {
    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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
    let mut cmd_prove = Command::cargo_bin("groth16").unwrap();
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
    let mut cmd_verify = Command::cargo_bin("groth16").unwrap();
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
            let mut cmd_prove = Command::cargo_bin("groth16").unwrap();
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
            let mut cmd_verify = Command::cargo_bin("groth16").unwrap();
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
    let mut cmd = Command::cargo_bin("groth16").unwrap();
    cmd.arg("verify").arg("--public").arg("/tmp/dummy.pub");
    cmd.assert().failure().stderr(predicate::str::contains(
        "required arguments were not provided",
    ));
}

#[test]
fn verify_missing_public() {
    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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
    let mut cmd_prove = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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
    let mut cmd_prove = Command::cargo_bin("groth16").unwrap();
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
    let mut cmd_verify = Command::cargo_bin("groth16").unwrap();
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

// ------------------------------------------------------------------
// Sparse mode CLI tests (Implementation 6)
// ------------------------------------------------------------------

#[test]
fn prove_sparse_stdout() {
    let (r1cs, wtns) = create_test_artifacts();

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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
    let repo_root = manifest_dir.parent().unwrap().parent().unwrap();
    let airdrop_dir = repo_root.join("groth16-prover/circom/AnonymousAirdrop");
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

    // 2. Dev ceremony (via the shared library, mirroring `trusted-setup ceremony-dev`)
    write_ceremony_dev_files(&r1cs, pk_file.path(), vk_file.path());

    // 3. Prove
    let mut cmd_prove = Command::cargo_bin("groth16").unwrap();
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
    let mut cmd_verify = Command::cargo_bin("groth16").unwrap();
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
    let repo_root = manifest_dir.parent().unwrap().parent().unwrap();
    let airdrop_dir = repo_root.join("groth16-prover/circom/AnonymousAirdrop");
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
// export-vk command tests
// ------------------------------------------------------------------

/// `export-vk` produces valid Aiken source from a binary verifying key.
#[test]
fn export_vk_produces_aiken_source() {
    let (r1cs, wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();
    let out_file = NamedTempFile::new().unwrap();

    // Generate a VK via ceremony-dev (via the shared library, mirroring the
    // `trusted-setup ceremony-dev` output)
    write_ceremony_dev_files(r1cs.path(), pk_file.path(), vk_file.path());

    // Export to a file
    let mut cmd_export = Command::cargo_bin("groth16").unwrap();
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

    // Generate a VK via ceremony-dev (via the shared library)
    write_ceremony_dev_files(r1cs.path(), pk_file.path(), vk_file.path());

    let mut cmd_export = Command::cargo_bin("groth16").unwrap();
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
    let mut cmd = Command::cargo_bin("groth16").unwrap();
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

    let mut cmd = Command::cargo_bin("groth16").unwrap();
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
    let mut cmd = Command::cargo_bin("groth16").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage: groth16 <COMMAND>"))
        .stdout(predicate::str::contains("Commands:"))
        .stdout(predicate::str::contains("prove"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("export-vk"));
}

/// `prove --help` shows the --sparse, --engine, and --prover options.
#[test]
fn help_prove() {
    let mut cmd = Command::cargo_bin("groth16").unwrap();
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
    let mut cmd = Command::cargo_bin("groth16").unwrap();
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
    let mut cmd = Command::cargo_bin("groth16").unwrap();
    cmd.arg("export-vk").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--verifying-key"))
        .stdout(predicate::str::contains("--out"));
}

// ------------------------------------------------------------------
// Error cases for new commands
// ------------------------------------------------------------------

/// `export-vk` fails with a helpful error when no `--verifying-key` is provided.
#[test]
fn export_vk_missing_verifying_key() {
    let mut cmd = Command::cargo_bin("groth16").unwrap();
    cmd.arg("export-vk");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("required arguments were not provided"));
}

// ------------------------------------------------------------------
// Randomized R1CS fixture library-level tests
// ------------------------------------------------------------------

/// Randomized R1CS circuits produce valid proofs (library-level test).
#[test]
fn random_circuit_library_roundtrip() {
    use groth16_prover::prover::Prover;

    let mut rng = rand::thread_rng();
    let circuit = groth16_prover::r1cs::random_r1cs_circuit(&mut rng, 3);
    let r1cs_bytes = groth16_prover::circom_adapter::r1cs_to_bytes(&circuit);
    let wtns_bytes = groth16_prover::circom_adapter::wtns_to_bytes(&circuit.witness);

    // Verify the binary format can be parsed back
    let mut parsed_circuit = groth16_prover::circom_adapter::CircomCircuit::from_bytes(&r1cs_bytes)
        .expect("random R1CS bytes should parse");
    parsed_circuit.load_witness_from_bytes(&wtns_bytes, 32)
        .expect("random WTNS bytes should parse");

    // Prove and verify
    let engine = groth16_prover::engine::FftQapEngine::new();
    let tw = groth16_prover::ceremony::ToxicWaste::deterministic();
    let n_public = circuit.n_public;

    let (pk, vk) = groth16_prover::ceremony::single_party_ceremony_full_from_tw(
        &engine, &circuit.l, &circuit.r, &circuit.o,
        n_public, tw, false,
    );

    let prover = groth16_prover::prover::PippengerProver::new();
    let (proof, public_input) = prover.prove_with_full_pk(
        &engine, &pk,
        &circuit.l, &circuit.r, &circuit.o,
        &circuit.witness,
    );

    assert!(
        groth16_prover::prover::verify_proof(&proof, &public_input, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2),
        "proof must be valid for random 3-constraint circuit"
    );
}
