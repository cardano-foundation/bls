use ark_bls12_381::Fr;
use groth16_prover::engine::{DenseQapEngine, FftQapEngine};
use groth16_prover::prover::{NaiveProver, PippengerProver, Prover};
use groth16_prover::r1cs::{L, O, R, WITNESS};
use std::time::Instant;

fn main() {
    println!("=== Benchmark: Proof production time ===\n");

    let witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();
    let tau = Fr::from(3u64);
    let alpha = Fr::from(5u64);
    let beta = Fr::from(7u64);
    let gamma = Fr::from(11u64);
    let delta = Fr::from(13u64);

    let iterations = 10000u64;

    // Warm-up
    let naive = NaiveProver::new();
    let pippenger = PippengerProver::new();
    let dense = DenseQapEngine::new();
    let fft = FftQapEngine::new();

    for _ in 0..100 {
        let _ = naive.prove(&dense, &L, &R, &O, &witness, tau, alpha, beta, gamma, delta);
        let _ = naive.prove(&fft, &L, &R, &O, &witness, tau, alpha, beta, gamma, delta);
        let _ = pippenger.prove(&fft, &L, &R, &O, &witness, tau, alpha, beta, gamma, delta);
    }

    // --- Implementation 1: Dense + Naive ---
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = naive.prove(&dense, &L, &R, &O, &witness, tau, alpha, beta, gamma, delta);
    }
    let t1 = start.elapsed();

    // --- Implementation 2: FFT + Naive ---
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = naive.prove(&fft, &L, &R, &O, &witness, tau, alpha, beta, gamma, delta);
    }
    let t2 = start.elapsed();

    // --- Implementation 3: FFT + Pippenger ---
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = pippenger.prove(&fft, &L, &R, &O, &witness, tau, alpha, beta, gamma, delta);
    }
    let t3 = start.elapsed();

    println!("Iterations: {}\n", iterations);
    println!("| Implementation | Engine | Prover | Total time | Per-proof |");
    println!("|----------------|--------|--------|------------|-----------|");
    println!(
        "| 1 (dense)      | DenseQapEngine | NaiveProver    | {:?} | {:?} |",
        t1,
        t1 / iterations as u32
    );
    println!(
        "| 2 (FFT)        | FftQapEngine   | NaiveProver    | {:?} | {:?} |",
        t2,
        t2 / iterations as u32
    );
    println!(
        "| 3 (Pippenger)  | FftQapEngine   | PippengerProver| {:?} | {:?} |",
        t3,
        t3 / iterations as u32
    );

    // Speedup ratios
    let r_dense = t1.as_nanos() as f64;
    let r_fft_naive = t2.as_nanos() as f64;
    let r_fft_pip = t3.as_nanos() as f64;

    println!("\nSpeedup relative to Implementation 1 (dense + naive):");
    println!("  Implementation 2 (FFT + naive):     {:.2}×", r_dense / r_fft_naive);
    println!("  Implementation 3 (FFT + Pippenger): {:.2}×", r_dense / r_fft_pip);

    println!("\nSpeedup relative to Implementation 2 (FFT + naive):");
    println!("  Implementation 3 (FFT + Pippenger): {:.2}×", r_fft_naive / r_fft_pip);
}
