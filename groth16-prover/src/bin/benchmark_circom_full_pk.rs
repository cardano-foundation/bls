//! `benchmark_circom_full_pk` — benchmark Implementation 5 (Circom adapter + FullProvingKey + on-the-fly QAP construction).
//!
//! Loads the synthetic `.r1cs` / `.wtns` data through the Circom parser,
//! generates a `FullProvingKey` once, then times proof production using the
//! group-element-only path.  The prover builds the witness polynomials `l(x)`,
//! `r(x)`, `o(x)` on-the-fly via variable-by-variable IFFT instead of
//! materialising the full `n_vars × domain_size` QAP matrix, which is the
//! key memory optimisation added in Implementation 5.

use groth16_prover::{
    ceremony::{single_party_ceremony_full_from_tw, ToxicWaste},
    circom_adapter::CircomCircuit,
    engine::FftQapEngine,
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
    println!("=== Benchmark: Circom adapter + FullProvingKey (Implementation 5) ===\n");

    // Load Circom circuit (parse once, outside the benchmark loop)
    let mut circuit = CircomCircuit::from_bytes(&build_synthetic_r1cs()).unwrap();
    circuit
        .load_witness_from_bytes(&build_synthetic_wtns(), 32)
        .unwrap();

    println!(
        "Loaded circuit: {} wires, {} constraints\n",
        circuit.n_wires, circuit.n_constraints
    );

    // Generate FullProvingKey once (group elements only, no scalars)
    let engine = FftQapEngine::new();
    let n_public = 1; // constant wire only
    let tw = ToxicWaste::deterministic();
    let (full_pk, _vk) = single_party_ceremony_full_from_tw(
        &engine, &circuit.l, &circuit.r, &circuit.o, n_public, tw,
    );
    println!("FullProvingKey generated (group elements only, no scalars)\n");

    let iterations = 100u64;

    let naive = NaiveProver::new();
    let pippenger = PippengerProver::new();

    // Warm-up
    for _ in 0..100 {
        let _ = naive.prove_with_full_pk(
            &engine,
            &full_pk,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            &circuit.witness,
        );
        let _ = pippenger.prove_with_full_pk(
            &engine,
            &full_pk,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            &circuit.witness,
        );
    }

    // --- Implementation 5a: Circom + FFT + Naive + FullProvingKey ---
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = naive.prove_with_full_pk(
            &engine,
            &full_pk,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            &circuit.witness,
        );
    }
    let t5a = start.elapsed();

    // --- Implementation 5b: Circom + FFT + Pippenger + FullProvingKey ---
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = pippenger.prove_with_full_pk(
            &engine,
            &full_pk,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            &circuit.witness,
        );
    }
    let t5b = start.elapsed();

    println!("Iterations: {}\n", iterations);
    println!(
        "| Implementation | Engine         | Prover          | Full PK? | Total time | Per-proof |"
    );
    println!(
        "|----------------|----------------|-----------------|----------|------------|-----------|"
    );
    println!(
        "| 5a (Circom FFT Naive)  | FftQapEngine | NaiveProver    | yes      | {:?} | {:?} |",
        t5a,
        t5a / iterations as u32
    );
    println!(
        "| 5b (Circom FFT Pipp)   | FftQapEngine | PippengerProver| yes      | {:?} | {:?} |",
        t5b,
        t5b / iterations as u32
    );

    println!("\n✅ Implementation 5 benchmarks complete.");
}
