//! `benchmark_poseidon_merkle` — benchmark proof generation for the PoseidonMerkle depth-2 circuit.
//!
//! Loads the real `circom/PoseidonMerkle/poseidon_merkle_depth2.r1cs` +
//! `witness.wtns` artifacts from disk, then times all five Circom prover paths:
//!
//!   4b. Circom + FftQapEngine   + NaiveProver      (scalar path)
//!   4c. Circom + FftQapEngine   + PippengerProver  (scalar path)
//!   5a. Circom + FftQapEngine   + NaiveProver      + FullProvingKey
//!   5b. Circom + FftQapEngine   + PippengerProver  + FullProvingKey
//!
//! Note: `DenseQapEngine` is hard-coded for the 3-gate toy circuit, so the
//! dense Circom path (4a) is not included for this 1,911-constraint circuit.
//!
//! The FullProvingKey is generated once (group elements only, no scalars) and
//! reused across the timed iterations.

use ark_bls12_381::Fr;
use groth16_prover::{
    ceremony::{single_party_ceremony_full_from_tw, ToxicWaste},
    circom_adapter::CircomCircuit,
    engine::FftQapEngine,
    prover::{NaiveProver, PippengerProver, Prover},
};
use std::time::Instant;

fn main() {
    println!("=== Benchmark: PoseidonMerkle depth-2 circuit ===\n");

    // Load real Circom circuit artifacts.
    let mut circuit =
        CircomCircuit::from_r1cs("circom/PoseidonMerkle/poseidon_merkle_depth2.r1cs").unwrap();
    circuit
        .load_witness("circom/PoseidonMerkle/witness.wtns")
        .unwrap();

    println!(
        "Loaded circuit: {} wires, {} constraints (public: {} out + {} in, private: {})\n",
        circuit.n_wires,
        circuit.n_constraints,
        circuit.n_pub_out,
        circuit.n_pub_in,
        circuit.n_prv_in
    );

    // Deterministic toxic waste (same values as the hard-coded toy example).
    let tw = ToxicWaste {
        tau: Fr::from(3u64),
        alpha: Fr::from(5u64),
        beta: Fr::from(7u64),
        gamma: Fr::from(11u64),
        delta: Fr::from(13u64),
    };

    // Public variables = constant wire + public inputs (digest).
    let n_public = 1 + circuit.n_pub_out as usize + circuit.n_pub_in as usize;

    let fft = FftQapEngine::new();

    let naive = NaiveProver::new();
    let pippenger = PippengerProver::new();

    // Generate the group-element-only FullProvingKey once.
    let (full_pk, _vk) = single_party_ceremony_full_from_tw(
        &fft,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        n_public,
        tw.clone(),
    );
    println!("FullProvingKey generated (group elements only, no scalars)\n");

    // Warm-up: one proof for each path so caches / allocators are hot.
    let _ = naive.prove(
        &fft,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        &circuit.witness,
        tw.tau,
        tw.alpha,
        tw.beta,
        tw.gamma,
        tw.delta,
    );
    let _ = pippenger.prove(
        &fft,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        &circuit.witness,
        tw.tau,
        tw.alpha,
        tw.beta,
        tw.gamma,
        tw.delta,
    );
    let _ = naive.prove_with_full_pk(
        &fft,
        &full_pk,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        &circuit.witness,
    );
    let _ = pippenger.prove_with_full_pk(
        &fft,
        &full_pk,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        &circuit.witness,
    );

    // Iteration counts tuned per path so the total run stays reasonable.
    let it_4b = 3u64;
    let it_4c = 3u64;
    let it_5a = 10u64;
    let it_5b = 10u64;

    // --- 4b: Circom + FFT + Naive ---
    let start = Instant::now();
    for _ in 0..it_4b {
        let _ = naive.prove(
            &fft,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            &circuit.witness,
            tw.tau,
            tw.alpha,
            tw.beta,
            tw.gamma,
            tw.delta,
        );
    }
    let t4b = start.elapsed();

    // --- 4c: Circom + FFT + Pippenger ---
    let start = Instant::now();
    for _ in 0..it_4c {
        let _ = pippenger.prove(
            &fft,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            &circuit.witness,
            tw.tau,
            tw.alpha,
            tw.beta,
            tw.gamma,
            tw.delta,
        );
    }
    let t4c = start.elapsed();

    // --- 5a: Circom + FFT + Naive + FullProvingKey ---
    let start = Instant::now();
    for _ in 0..it_5a {
        let _ = naive.prove_with_full_pk(
            &fft,
            &full_pk,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            &circuit.witness,
        );
    }
    let t5a = start.elapsed();

    // --- 5b: Circom + FFT + Pippenger + FullProvingKey ---
    let start = Instant::now();
    for _ in 0..it_5b {
        let _ = pippenger.prove_with_full_pk(
            &fft,
            &full_pk,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            &circuit.witness,
        );
    }
    let t5b = start.elapsed();

    println!(
        "| Implementation | Engine | Prover | Full PK | Iterations | Total time | Per-proof |"
    );
    println!(
        "|----------------|--------|--------|---------|------------|------------|-----------|"
    );
    println!(
        "| 4b (Circom FFT)   | FftQapEngine   | NaiveProver | no | {} | {:?} | {:?} |",
        it_4b,
        t4b,
        t4b / it_4b as u32
    );
    println!(
        "| 4c (Circom Pipp)  | FftQapEngine   | PippengerProver | no | {} | {:?} | {:?} |",
        it_4c,
        t4c,
        t4c / it_4c as u32
    );
    println!(
        "| 5a (Circom Full PK) | FftQapEngine   | NaiveProver | yes | {} | {:?} | {:?} |",
        it_5a,
        t5a,
        t5a / it_5a as u32
    );
    println!(
        "| 5b (Circom Full PK Pipp) | FftQapEngine   | PippengerProver | yes | {} | {:?} | {:?} |",
        it_5b,
        t5b,
        t5b / it_5b as u32
    );

    let per_4b = t4b / it_4b.max(1) as u32;
    let per_4c = t4c / it_4c.max(1) as u32;
    let per_5a = t5a / it_5a.max(1) as u32;
    let per_5b = t5b / it_5b.max(1) as u32;

    println!("\nSpeedup relative to 4b (Circom FFT + Naive):");
    println!(
        "  4c (FFT + Pippenger): {:.2}×",
        ratio(per_4b, per_4c)
    );
    println!(
        "  5a (Full PK + Naive):  {:.2}×",
        ratio(per_4b, per_5a)
    );
    println!(
        "  5b (Full PK + Pippenger): {:.2}×",
        ratio(per_4b, per_5b)
    );

    println!("\n✅ PoseidonMerkle benchmarks complete.");
}

fn ratio(a: std::time::Duration, b: std::time::Duration) -> f64 {
    if b.as_nanos() == 0 {
        return f64::INFINITY;
    }
    a.as_nanos() as f64 / b.as_nanos() as f64
}
