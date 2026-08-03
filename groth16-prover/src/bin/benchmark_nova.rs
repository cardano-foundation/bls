//! Nova step-chain benchmark (Implementation 8).
//!
//! Measures the three cryptographic phases of the `nova` IVC flow for a
//! compiled step circuit and a directory of step witnesses:
//!
//!   1. ceremony — single-party trusted setup for the step circuit
//!   2. fold     — per-step Groth16 proof (+ state-chain check), averaged
//!   3. verify   — Groth16 pairing check over every step proof
//!
//! The transcript hashing of `nova fold` (BLAKE2b512 over states + proofs)
//! is deliberately excluded: it is microseconds per step, negligible next to
//! the per-step proof.  The proving/verifying keys are kept in memory (no
//! `.pk` / `.vk` disk I/O), matching what `nova fold` measures as `steps`.
//!
//! Usage:
//!   cargo run --release --bin benchmark_nova -- --circuit step.r1cs --steps DIR [--limit N]

use ark_bls12_381::Fr;
use groth16_prover::ceremony::{
    single_party_ceremony_full_from_tw_sparse, verify_with_vk, ToxicWaste,
};
use groth16_prover::circom_adapter::SparseCircomCircuit;
use groth16_prover::engine::FftQapEngine;
use groth16_prover::prover::{PippengerProver, Proof, Prover, PublicInput};
use std::fs;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 || args[1] != "--circuit" || args[3] != "--steps" {
        eprintln!(
            "usage: benchmark_nova --circuit <step.r1cs> --steps <witness-dir> [--limit N]"
        );
        std::process::exit(2);
    }
    let circuit_path = &args[2];
    let steps_dir = &args[4];
    let limit = args
        .windows(2)
        .find(|w| w[0] == "--limit")
        .map(|w| {
            w[1].parse::<usize>()
                .expect("--limit must be a positive integer")
        });

    let mut circuit = SparseCircomCircuit::from_r1cs(circuit_path)
        .unwrap_or_else(|e| panic!("failed to load circuit {circuit_path}: {e}"));
    if circuit.n_pub_in != circuit.n_pub_out {
        panic!(
            "not a step circuit: n_pub_in ({}) != n_pub_out ({})",
            circuit.n_pub_in, circuit.n_pub_out
        );
    }

    let mut wtns: Vec<std::path::PathBuf> = fs::read_dir(steps_dir)
        .expect("failed to read steps dir")
        .map(|e| e.expect("steps dir entry").path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("wtns"))
        .collect();
    wtns.sort();
    if let Some(n) = limit {
        wtns.truncate(n);
    }
    assert!(!wtns.is_empty(), "no .wtns files in steps dir");

    let n_steps = wtns.len();
    let n_public = 1 + circuit.n_pub_out as usize + circuit.n_pub_in as usize;
    let n_constraints = circuit.n_constraints as usize;
    let n_pub_out = circuit.n_pub_out as usize;
    let n_pub_in = circuit.n_pub_in as usize;

    println!(
        "step circuit: {} wires, {} constraints, pub {} out + {} in, private {}",
        circuit.n_wires,
        circuit.n_constraints,
        circuit.n_pub_out,
        circuit.n_pub_in,
        circuit.n_prv_in
    );
    println!("step witnesses: {n_steps} (from {steps_dir})");

    let engine = FftQapEngine::new();
    let prover = PippengerProver::new();

    // 1. Ceremony — single-party trusted setup for the step circuit.
    let mut rng = rand::thread_rng();
    let t = Instant::now();
    let (full_pk, vk) = single_party_ceremony_full_from_tw_sparse(
        &engine,
        n_constraints,
        circuit.n_wires as usize,
        n_public,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        ToxicWaste::random(&mut rng),
        false,
    );
    let ceremony_s = t.elapsed().as_secs_f64();
    println!("ceremony: {ceremony_s:.3} s (single-party, h_scalar off)");

    // 2. Fold — per-step proof + state-chain check (state_in[i] == state_out[i-1]).
    let mut proofs: Vec<(Proof, PublicInput)> = Vec::with_capacity(n_steps);
    let mut prev_out: Option<Vec<Fr>> = None;
    let t = Instant::now();
    for (i, p) in wtns.iter().enumerate() {
        circuit
            .load_witness(p.to_str().expect("witness path is not valid UTF-8"))
            .unwrap_or_else(|e| panic!("failed to load witness {}: {e}", p.display()));
        let w = &circuit.witness;
        let in_fr = &w[1 + n_pub_out..1 + n_pub_out + n_pub_in];
        let out_fr = &w[1..1 + n_pub_out];
        if let Some(prev) = &prev_out {
            assert_eq!(
                in_fr,
                prev.as_slice(),
                "step {i}: state_in does not chain to previous state_out"
            );
        }
        let (proof, public) = prover.prove_with_full_pk_sparse(
            &engine,
            &full_pk,
            n_constraints,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            w,
        );
        proofs.push((proof, public));
        prev_out = Some(out_fr.to_vec());
    }
    let fold_s = t.elapsed().as_secs_f64();
    println!(
        "fold: {fold_s:.3} s total, {:.1} ms/step over {n_steps} steps",
        fold_s * 1000.0 / n_steps as f64
    );

    // 3. Verify — pairing check over every step proof.
    let t = Instant::now();
    for (proof, public) in &proofs {
        assert!(
            verify_with_vk(proof, public, &vk),
            "a step proof failed the Groth16 pairing check"
        );
    }
    let verify_s = t.elapsed().as_secs_f64();
    println!(
        "verify: {verify_s:.3} s total, {:.2} ms/step over {n_steps} steps",
        verify_s * 1000.0 / n_steps as f64
    );
    println!("all {n_steps} step proofs verified OK");
}
