//! `benchmark_privacy` — benchmark proof generation for the Spend(depth) circuit.
//!
//! Loads the real `circom/Privacy/spend_depth2.r1cs` + `witness.wtns` artifacts
//! from disk, generates a `FullProvingKey` once, then times proof production
//! using the fast group-element-only path.

use ark_bls12_381::Fr;
use groth16_prover::{
    ceremony::single_party_ceremony_full_from_tw,
    circom_adapter::CircomCircuit,
    engine::FftQapEngine,
    prover::{NaiveProver, PippengerProver, Prover},
};
use std::time::Instant;

fn main() {
    println!("=== Benchmark: Privacy circuit (Spend depth-2) ===\n");

    // Load real Circom circuit
    let mut circuit = CircomCircuit::from_r1cs("circom/Privacy/spend_depth2.r1cs").unwrap();
    circuit.load_witness("circom/Privacy/witness.wtns").unwrap();

    println!(
        "Loaded circuit: {} wires, {} constraints\n",
        circuit.n_wires, circuit.n_constraints
    );

    // Generate FullProvingKey once (same as `ceremony-dev` CLI)
    let engine = FftQapEngine::new();
    let n_public = 1; // constant wire only
    let (full_pk, _vk) = single_party_ceremony_full_from_tw(
        &engine,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        n_public,
        groth16_prover::ceremony::ToxicWaste {
            tau: Fr::from(3u64),
            alpha: Fr::from(5u64),
            beta: Fr::from(7u64),
            gamma: Fr::from(11u64),
            delta: Fr::from(13u64),
        },
    );
    println!("FullProvingKey generated (group elements only, no scalars)\n");

    let iterations = 1u64;

    let naive = NaiveProver::new();
    let pippenger = PippengerProver::new();

    // Warm-up
    for _ in 0..1 {
        let _ = naive.prove_with_full_pk(&engine, &full_pk, &circuit.l, &circuit.r, &circuit.o, &circuit.witness);
        let _ = pippenger.prove_with_full_pk(&engine, &full_pk, &circuit.l, &circuit.r, &circuit.o, &circuit.witness);
    }

    // --- FFT + Naive (legacy scalar path, for comparison) ---
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = naive.prove(&engine, &circuit.l, &circuit.r, &circuit.o, &circuit.witness,
            Fr::from(3u64), Fr::from(5u64), Fr::from(7u64), Fr::from(11u64), Fr::from(13u64));
    }
    let t_legacy = start.elapsed();

    // --- FFT + Naive (FullProvingKey) ---
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = naive.prove_with_full_pk(&engine, &full_pk, &circuit.l, &circuit.r, &circuit.o, &circuit.witness);
    }
    let t_fft_naive = start.elapsed();

    // --- FFT + Pippenger (FullProvingKey) ---
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = pippenger.prove_with_full_pk(&engine, &full_pk, &circuit.l, &circuit.r, &circuit.o, &circuit.witness);
    }
    let t_fft_pippenger = start.elapsed();

    println!("Iterations: {}\n", iterations);
    println!("| Path             | Engine         | Prover          | Total time | Per-proof |");
    println!("|------------------|----------------|-----------------|------------|-----------|");
    println!(
        "| Legacy (scalars) | FftQapEngine   | NaiveProver     | {:?} | {:?} |",
        t_legacy,
        t_legacy / iterations as u32
    );
    println!(
        "| FullProvingKey   | FftQapEngine   | NaiveProver     | {:?} | {:?} |",
        t_fft_naive,
        t_fft_naive / iterations as u32
    );
    println!(
        "| FullProvingKey   | FftQapEngine   | PippengerProver | {:?} | {:?} |",
        t_fft_pippenger,
        t_fft_pippenger / iterations as u32
    );

    println!("\n✅ Privacy circuit benchmarks complete.");
}
