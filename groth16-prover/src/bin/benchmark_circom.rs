//! `benchmark_circom` — benchmark Implementation 4 (Circom adapter).
//!
//! Loads the synthetic `.r1cs` / `.wtns` data through the Circom parser,
//! builds a `QapEngine` from the parsed matrices, and times proof
//! production.  The benchmark is otherwise identical to
//! `benchmark_provers.rs` so the numbers are directly comparable.

use ark_bls12_381::Fr;
use groth16_prover::{
    circom_adapter::CircomCircuit,
    engine::{DenseQapEngine, FftQapEngine},
    prover::{NaiveProver, PippengerProver, Prover},
};
use std::time::Instant;

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

fn main() {
    println!("=== Benchmark: Circom adapter (Implementation 4) ===\n");

    // Load Circom circuit (parse once, outside the benchmark loop)
    let mut circuit = CircomCircuit::from_bytes(&build_synthetic_r1cs()).unwrap();
    circuit
        .load_witness_from_bytes(&build_synthetic_wtns(), 32)
        .unwrap();

    let l_ref: Vec<&[u64]> = circuit.l.iter().map(|v| v.as_slice()).collect();
    let r_ref: Vec<&[u64]> = circuit.r.iter().map(|v| v.as_slice()).collect();
    let o_ref: Vec<&[u64]> = circuit.o.iter().map(|v| v.as_slice()).collect();

    let witness_fr: Vec<Fr> = circuit.witness.iter().map(|&v| Fr::from(v)).collect();
    let tau = Fr::from(3u64);
    let alpha = Fr::from(5u64);
    let beta = Fr::from(7u64);
    let gamma = Fr::from(11u64);
    let delta = Fr::from(13u64);

    let iterations = 100u64;

    // Warm-up
    let naive = NaiveProver::new();
    let pippenger = PippengerProver::new();
    let dense = DenseQapEngine::new();
    let fft = FftQapEngine::new();

    for _ in 0..100 {
        let _ = naive.prove(&dense, &l_ref, &r_ref, &o_ref, &witness_fr, tau, alpha, beta, gamma, delta);
        let _ = naive.prove(&fft, &l_ref, &r_ref, &o_ref, &witness_fr, tau, alpha, beta, gamma, delta);
        let _ = pippenger.prove(&fft, &l_ref, &r_ref, &o_ref, &witness_fr, tau, alpha, beta, gamma, delta);
    }

    // --- Implementation 4a: Circom + Dense + Naive ---
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = naive.prove(&dense, &l_ref, &r_ref, &o_ref, &witness_fr, tau, alpha, beta, gamma, delta);
    }
    let t4a = start.elapsed();

    // --- Implementation 4b: Circom + FFT + Naive ---
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = naive.prove(&fft, &l_ref, &r_ref, &o_ref, &witness_fr, tau, alpha, beta, gamma, delta);
    }
    let t4b = start.elapsed();

    // --- Implementation 4c: Circom + FFT + Pippenger ---
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = pippenger.prove(&fft, &l_ref, &r_ref, &o_ref, &witness_fr, tau, alpha, beta, gamma, delta);
    }
    let t4c = start.elapsed();

    println!("Iterations: {}\n", iterations);
    println!("| Implementation | Engine         | Prover          | Total time | Per-proof |");
    println!("|----------------|----------------|-----------------|------------|-----------|");
    println!(
        "| 4a (Circom dense) | DenseQapEngine | NaiveProver    | {:?} | {:?} |",
        t4a,
        t4a / iterations as u32
    );
    println!(
        "| 4b (Circom FFT)   | FftQapEngine   | NaiveProver    | {:?} | {:?} |",
        t4b,
        t4b / iterations as u32
    );
    println!(
        "| 4c (Circom Pipp)  | FftQapEngine   | PippengerProver| {:?} | {:?} |",
        t4c,
        t4c / iterations as u32
    );

    println!("\n✅ Circom adapter benchmarks complete.");
}
