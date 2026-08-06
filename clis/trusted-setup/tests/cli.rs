//! CLI integration tests for the `trusted-setup` binary.
//!
//! The ceremony / ceremony-dev / phase2 commands produce `.pk` / `.vk` /
//! `.zkey` artifacts that are consumed by the `groth16-prover` CLI.  The
//! prove/verify steps below are exercised through the `trusted_setup`
//! library (same code path) so these tests stay self-contained within this
//! crate.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::NamedTempFile;

use ark_bls12_381::{Fq, Fr, G1Affine, G2Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::Field;
use ark_serialize::CanonicalDeserialize;

use trusted_setup::ceremony::{FullProvingKey, ProvingKey, VerifyingKey};
use trusted_setup::circom_adapter::{CircomCircuit, SparseCircomCircuit};
use trusted_setup::engine::FftQapEngine;
use trusted_setup::prover::{verify_proof, PippengerProver, Prover};

// ------------------------------------------------------------------
// Synthetic artifacts (self-contained tests)
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
// Key-loading helpers (same logic as the groth16-prover CLI's util.rs)
// ------------------------------------------------------------------

fn load_full_pk(path: &std::path::Path) -> FullProvingKey {
    let bytes = fs::read(path).unwrap();
    if let Ok(pk) = FullProvingKey::deserialize_uncompressed_unchecked(&bytes[..]) {
        return pk;
    }
    FullProvingKey::deserialize_compressed(&bytes[..]).unwrap()
}

fn load_vk(path: &std::path::Path) -> VerifyingKey {
    let bytes = fs::read(path).unwrap();
    if let Ok(vk) = VerifyingKey::deserialize_uncompressed_unchecked(&bytes[..]) {
        return vk;
    }
    VerifyingKey::deserialize_compressed(&bytes[..]).unwrap()
}

fn load_legacy_pk(path: &std::path::Path) -> ProvingKey {
    let bytes = fs::read(path).unwrap();
    ProvingKey::deserialize_compressed(&bytes[..]).unwrap()
}

// ------------------------------------------------------------------
// Library-level prove/verify helpers (same code path as the CLI)
// ------------------------------------------------------------------

/// Prove + verify a dense FullProvingKey artifact against the circuit files.
fn prove_and_verify_full_pk(pk_file: &std::path::Path, vk_file: &std::path::Path, r1cs: &std::path::Path, wtns: &std::path::Path) {
    let pk = load_full_pk(pk_file);
    let vk = load_vk(vk_file);
    let mut circuit = CircomCircuit::from_bytes(&fs::read(r1cs).unwrap()).unwrap();
    circuit
        .load_witness_from_bytes(&fs::read(wtns).unwrap(), 32)
        .unwrap();

    let engine = FftQapEngine::new();
    let (proof, public_input) = PippengerProver::new().prove_with_full_pk(
        &engine, &pk, &circuit.l, &circuit.r, &circuit.o, &circuit.witness,
    );

    assert!(
        verify_proof(&proof, &public_input, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2),
        "proof must verify against the ceremony verifying key"
    );
}

/// Prove + verify a sparse FullProvingKey artifact (Implementation 6).
fn prove_and_verify_full_pk_sparse(pk_file: &std::path::Path, vk_file: &std::path::Path, r1cs: &std::path::Path, wtns: &std::path::Path) {
    let pk = load_full_pk(pk_file);
    let vk = load_vk(vk_file);
    let mut circuit = SparseCircomCircuit::from_r1cs(r1cs.to_str().unwrap()).unwrap();
    circuit.load_witness(wtns.to_str().unwrap()).unwrap();

    let engine = FftQapEngine::new();
    let (proof, public_input) = PippengerProver::new().prove_with_full_pk_sparse(
        &engine,
        &pk,
        circuit.n_constraints as usize,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        &circuit.witness,
    );

    assert!(
        verify_proof(&proof, &public_input, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2),
        "sparse proof must verify against the ceremony verifying key"
    );
}

/// Prove + verify a legacy scalar `ProvingKey` artifact.
fn prove_and_verify_legacy_pk(pk_file: &std::path::Path, vk_file: &std::path::Path, r1cs: &std::path::Path, wtns: &std::path::Path) {
    let pk = load_legacy_pk(pk_file);
    let vk = load_vk(vk_file);
    let mut circuit = CircomCircuit::from_bytes(&fs::read(r1cs).unwrap()).unwrap();
    circuit
        .load_witness_from_bytes(&fs::read(wtns).unwrap(), 32)
        .unwrap();

    let engine = FftQapEngine::new();
    let (proof, public_input) = PippengerProver::new().prove(
        &engine,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        &circuit.witness,
        pk.toxic_waste.tau,
        pk.toxic_waste.alpha,
        pk.toxic_waste.beta,
        pk.toxic_waste.gamma,
        pk.toxic_waste.delta,
    );

    assert!(
        verify_proof(&proof, &public_input, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2),
        "legacy proof must verify against the ceremony verifying key"
    );
}

// ------------------------------------------------------------------
// Legacy `ceremony` CLI tests
// ------------------------------------------------------------------

/// Run a full legacy ceremony → prove → verify round-trip.
#[test]
fn full_ceremony_prove_verify_roundtrip() {
    let (r1cs, wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();

    // 1. Ceremony
    let mut cmd_ceremony = Command::cargo_bin("trusted-setup").unwrap();
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

    // 2. Prove + verify via the library (same code path as the CLI)
    prove_and_verify_legacy_pk(pk_file.path(), vk_file.path(), r1cs.path(), wtns.path());
}

// ------------------------------------------------------------------
// `ceremony-dev` CLI tests
// ------------------------------------------------------------------

/// Run a full ceremony-dev → prove → verify round-trip using a FullProvingKey.
#[test]
fn full_ceremony_dev_prove_verify_roundtrip() {
    let (r1cs, wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();

    // 1. Dev ceremony (outputs FullProvingKey)
    let mut cmd_ceremony = Command::cargo_bin("trusted-setup").unwrap();
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

    // 2. Prove + verify via the library
    prove_and_verify_full_pk(pk_file.path(), vk_file.path(), r1cs.path(), wtns.path());
}

/// Run a full ceremony-dev --h-scalar → prove → verify round-trip.
#[test]
fn full_ceremony_dev_h_scalar_prove_verify_roundtrip() {
    let (r1cs, wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();

    // 1. Dev ceremony with h_scalar compression
    let mut cmd_ceremony = Command::cargo_bin("trusted-setup").unwrap();
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

    // 2. Prove + verify via the library
    prove_and_verify_full_pk(pk_file.path(), vk_file.path(), r1cs.path(), wtns.path());
}

/// `ceremony-dev --sparse` produces a usable FullProvingKey.
#[test]
fn ceremony_dev_sparse() {
    let (r1cs, _wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("trusted-setup").unwrap();
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

/// Full sparse roundtrip: ceremony-dev --sparse → prove --sparse → verify.
#[test]
fn full_sparse_roundtrip() {
    let (r1cs, wtns) = create_test_artifacts();
    let pk_file = NamedTempFile::new().unwrap();
    let vk_file = NamedTempFile::new().unwrap();

    // 1. Sparse dev ceremony
    let mut cmd_ceremony = Command::cargo_bin("trusted-setup").unwrap();
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

    // 2. Sparse prove + verify via the library
    prove_and_verify_full_pk_sparse(pk_file.path(), vk_file.path(), r1cs.path(), wtns.path());
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

    let mut cmd = Command::cargo_bin("trusted-setup").unwrap();
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
    let mut cmd_new = Command::cargo_bin("trusted-setup").unwrap();
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
    let mut cmd_contrib = Command::cargo_bin("trusted-setup").unwrap();
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
    let mut cmd_verify = Command::cargo_bin("trusted-setup").unwrap();
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

    // 1. New
    let mut cmd_new = Command::cargo_bin("trusted-setup").unwrap();
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
    let mut cmd_contrib = Command::cargo_bin("trusted-setup").unwrap();
    cmd_contrib
        .arg("phase2")
        .arg("contribute")
        .arg("--zkey-in")
        .arg(zkey0.path())
        .arg("--zkey-out")
        .arg(zkey1.path());
    cmd_contrib.assert().success();

    // 3. Finalize
    let mut cmd_final = Command::cargo_bin("trusted-setup").unwrap();
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

    // 4. Prove + verify via the library
    prove_and_verify_full_pk(pk_file.path(), vk_file.path(), r1cs.path(), wtns.path());
}

// ------------------------------------------------------------------
// Error cases
// ------------------------------------------------------------------

/// `phase2 new` fails when the circuit file does not exist.
#[test]
fn phase2_new_missing_circuit() {
    let ptau = NamedTempFile::new().unwrap();
    fs::write(ptau.path(), build_synthetic_ptau(4)).unwrap();
    let zkey = NamedTempFile::new().unwrap();

    let mut cmd = Command::cargo_bin("trusted-setup").unwrap();
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

    let mut cmd = Command::cargo_bin("trusted-setup").unwrap();
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

// ------------------------------------------------------------------
// --help output tests
// ------------------------------------------------------------------

/// Top-level `--help` prints the usage summary.
#[test]
fn help_top_level() {
    let mut cmd = Command::cargo_bin("trusted-setup").unwrap();
    cmd.arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Usage: trusted-setup <COMMAND>"))
        .stdout(predicate::str::contains("Commands:"))
        .stdout(predicate::str::contains("ceremony"))
        .stdout(predicate::str::contains("ceremony-dev"))
        .stdout(predicate::str::contains("phase2"));
}

/// `phase2 --help` lists all Phase-2 subcommands.
#[test]
fn help_phase2() {
    let mut cmd = Command::cargo_bin("trusted-setup").unwrap();
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
    let mut cmd = Command::cargo_bin("trusted-setup").unwrap();
    cmd.arg("phase2").arg("new").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--circuit"))
        .stdout(predicate::str::contains("--srs"))
        .stdout(predicate::str::contains("--zkey"))
        .stdout(predicate::str::contains("Path to the `.r1cs` circuit file"))
        .stdout(predicate::str::contains("Path to the Phase-1 `.ptau` SRS file"));
}

/// `ceremony-dev --help` shows the --sparse and --h-scalar options.
#[test]
fn help_ceremony_dev() {
    let mut cmd = Command::cargo_bin("trusted-setup").unwrap();
    cmd.arg("ceremony-dev").arg("--help");
    cmd.assert()
        .success()
        .stdout(predicate::str::contains("--sparse"))
        .stdout(predicate::str::contains("--h-scalar"))
        .stdout(predicate::str::contains("sparse constraint representation"))
        .stdout(predicate::str::contains("h-query scalar compression"));
}
