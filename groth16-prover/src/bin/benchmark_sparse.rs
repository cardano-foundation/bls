//! `benchmark_sparse` — benchmark Implementation 6 (sparse-matrix prover).
//!
//! Compares the dense path (Implementation 5) against the sparse path
//! (Implementation 6) on the same circuits.  Both paths use FFT QAP engine +
//! Pippenger MSM + FullProvingKey.  The only difference is whether the `.r1cs`
//! is expanded into dense matrices or kept in sparse triplet form.
//!
//! Circuits tested:
//!   1. Synthetic toy multiplier (3 constraints, 8 wires) — many iterations
//!   2. PoseidonMerkle depth-2 (1,911 constraints, 1,914 wires) — real circuit
//!   3. EdDSAJubJub test_pbk_only — real circuit

use groth16_prover::{
    ceremony::{single_party_ceremony_full_from_tw, single_party_ceremony_full_from_tw_sparse, ToxicWaste},
    circom_adapter::{CircomCircuit, SparseCircomCircuit},
    engine::FftQapEngine,
    prover::{NaiveProver, PippengerProver, Prover},
};
use std::time::Instant;

// ------------------------------------------------------------------
// Synthetic toy circuit generators (same as benchmark_circom_full_pk.rs)
// ------------------------------------------------------------------

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

    write_vec(&[(2, 1)]);
    write_vec(&[(3, 1)]);
    write_vec(&[(6, 1)]);
    write_vec(&[(4, 1)]);
    write_vec(&[(5, 1)]);
    write_vec(&[(7, 1)]);
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

// ------------------------------------------------------------------
// Benchmark helpers
// ------------------------------------------------------------------

fn ratio(a: std::time::Duration, b: std::time::Duration) -> f64 {
    if b.as_nanos() == 0 {
        return f64::INFINITY;
    }
    a.as_nanos() as f64 / b.as_nanos() as f64
}

fn bench_toy() {
    println!("\n=== 1. Toy multiplier (3 constraints, 8 wires) ===\n");

    // Dense load
    let mut dense = CircomCircuit::from_bytes(&build_synthetic_r1cs()).unwrap();
    dense.load_witness_from_bytes(&build_synthetic_wtns(), 32).unwrap();

    // Sparse load
    let mut sparse = SparseCircomCircuit::from_bytes(&build_synthetic_r1cs()).unwrap();
    sparse.load_witness_from_bytes(&build_synthetic_wtns(), 32).unwrap();

    println!("Dense memory (approx): {} bytes", dense.l.len() * dense.l[0].len() * 32 * 3);
    let sparse_entries: usize = sparse.l.iter().map(|v| v.len()).sum::<usize>()
        + sparse.r.iter().map(|v| v.len()).sum::<usize>()
        + sparse.o.iter().map(|v| v.len()).sum::<usize>();
    println!("Sparse entries: {} ({} bytes)", sparse_entries, sparse_entries * 40); // (u32, Fr) ≈ 40 bytes

    let engine = FftQapEngine::new();
    let tw = ToxicWaste::deterministic();
    let n_public = 1;

    // Dense FullProvingKey
    let (pk_dense, _vk_dense) = single_party_ceremony_full_from_tw(
        &engine, &dense.l, &dense.r, &dense.o, n_public, tw.clone(),
    );

    // Sparse FullProvingKey
    let (pk_sparse, _vk_sparse) = single_party_ceremony_full_from_tw_sparse(
        &engine,
        dense.n_constraints as usize,
        dense.n_wires as usize,
        n_public,
        &sparse.l,
        &sparse.r,
        &sparse.o,
        tw.clone(),
    );

    // Verify keys match (parity check)
    assert_eq!(pk_dense.a_query, pk_sparse.a_query, "PK mismatch");
    assert_eq!(pk_dense.c_query, pk_sparse.c_query, "PK mismatch");

    let naive = NaiveProver::new();
    let pippenger = PippengerProver::new();

    let iterations = 500u64;

    // Warm-up
    for _ in 0..100 {
        let _ = naive.prove_with_full_pk(&engine, &pk_dense, &dense.l, &dense.r, &dense.o, &dense.witness);
        let _ = naive.prove_with_full_pk_sparse(&engine, &pk_sparse, dense.n_constraints as usize, &sparse.l, &sparse.r, &sparse.o, &sparse.witness);
    }

    // Dense + Naive
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = naive.prove_with_full_pk(&engine, &pk_dense, &dense.l, &dense.r, &dense.o, &dense.witness);
    }
    let t_dense_naive = start.elapsed();

    // Sparse + Naive
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = naive.prove_with_full_pk_sparse(&engine, &pk_sparse, dense.n_constraints as usize, &sparse.l, &sparse.r, &sparse.o, &sparse.witness);
    }
    let t_sparse_naive = start.elapsed();

    // Dense + Pippenger
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = pippenger.prove_with_full_pk(&engine, &pk_dense, &dense.l, &dense.r, &dense.o, &dense.witness);
    }
    let t_dense_pipp = start.elapsed();

    // Sparse + Pippenger
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = pippenger.prove_with_full_pk_sparse(&engine, &pk_sparse, dense.n_constraints as usize, &sparse.l, &sparse.r, &sparse.o, &sparse.witness);
    }
    let t_sparse_pipp = start.elapsed();

    println!("| Path | Dense / Sparse | Prover | Iterations | Total | Per-proof |");
    println!("|------|----------------|--------|------------|-------|-----------|");
    println!("| 5a (dense) | dense | Naive | {} | {:?} | {:?} |", iterations, t_dense_naive, t_dense_naive / iterations as u32);
    println!("| 6a (sparse)| sparse| Naive | {} | {:?} | {:?} |", iterations, t_sparse_naive, t_sparse_naive / iterations as u32);
    println!("| 5b (dense) | dense | Pippenger | {} | {:?} | {:?} |", iterations, t_dense_pipp, t_dense_pipp / iterations as u32);
    println!("| 6b (sparse)| sparse| Pippenger | {} | {:?} | {:?} |", iterations, t_sparse_pipp, t_sparse_pipp / iterations as u32);

    let per_dense_naive = t_dense_naive / iterations as u32;
    let per_sparse_naive = t_sparse_naive / iterations as u32;
    let per_dense_pipp = t_dense_pipp / iterations as u32;
    let per_sparse_pipp = t_sparse_pipp / iterations as u32;

    println!("\nSparse vs Dense speedup (same prover):");
    println!("  Naive:  {:.2}×", ratio(per_dense_naive, per_sparse_naive));
    println!("  Pippenger: {:.2}×", ratio(per_dense_pipp, per_sparse_pipp));
}

fn bench_real_circuit(name: &str, r1cs_path: &str, wtns_path: &str) {
    println!("\n=== {} ===\n", name);

    let mut dense = match CircomCircuit::from_r1cs(r1cs_path) {
        Ok(c) => c,
        Err(e) => { println!("⚠️  Failed to load {}: {}", r1cs_path, e); return; }
    };
    if let Err(e) = dense.load_witness(wtns_path) {
        println!("⚠️  Failed to load witness {}: {}", wtns_path, e); return;
    }

    let mut sparse = match SparseCircomCircuit::from_r1cs(r1cs_path) {
        Ok(c) => c,
        Err(e) => { println!("⚠️  Failed to load sparse {}: {}", r1cs_path, e); return; }
    };
    if let Err(e) = sparse.load_witness(wtns_path) {
        println!("⚠️  Failed to load sparse witness {}: {}", wtns_path, e); return;
    }

    let n_constraints = dense.n_constraints as usize;
    let n_wires = dense.n_wires as usize;
    let n_public = 1 + dense.n_pub_out as usize + dense.n_pub_in as usize;

    let dense_mem = dense.l.len() * dense.l[0].len() * 32 * 3;
    let sparse_entries: usize = sparse.l.iter().map(|v| v.len()).sum::<usize>()
        + sparse.r.iter().map(|v| v.len()).sum::<usize>()
        + sparse.o.iter().map(|v| v.len()).sum::<usize>();
    let sparse_mem = sparse_entries * 40;

    println!("Circuit: {} wires, {} constraints, {} public", n_wires, n_constraints, n_public);
    println!("Dense memory:  {} bytes ({:.1} MiB)", dense_mem, dense_mem as f64 / (1024.0 * 1024.0));
    println!("Sparse memory: {} bytes ({:.1} MiB) — {:.1}× smaller",
        sparse_mem, sparse_mem as f64 / (1024.0 * 1024.0),
        dense_mem as f64 / sparse_mem as f64);

    let engine = FftQapEngine::new();
    let tw = ToxicWaste::deterministic();

    let (pk_dense, _vk_dense) = single_party_ceremony_full_from_tw(
        &engine, &dense.l, &dense.r, &dense.o, n_public, tw.clone(),
    );
    let (pk_sparse, _vk_sparse) = single_party_ceremony_full_from_tw_sparse(
        &engine, n_constraints, n_wires, n_public,
        &sparse.l, &sparse.r, &sparse.o, tw.clone(),
    );

    assert_eq!(pk_dense.a_query, pk_sparse.a_query, "PK mismatch on real circuit");

    let pippenger = PippengerProver::new();

    // Warm-up
    let _ = pippenger.prove_with_full_pk(&engine, &pk_dense, &dense.l, &dense.r, &dense.o, &dense.witness);
    let _ = pippenger.prove_with_full_pk_sparse(&engine, &pk_sparse, n_constraints, &sparse.l, &sparse.r, &sparse.o, &sparse.witness);

    // Adaptive iteration count: fewer iterations for larger circuits
    let iterations = if n_constraints > 3000 { 1u64 } else { 10u64 };

    // Dense
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = pippenger.prove_with_full_pk(&engine, &pk_dense, &dense.l, &dense.r, &dense.o, &dense.witness);
    }
    let t_dense = start.elapsed();

    // Sparse
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = pippenger.prove_with_full_pk_sparse(&engine, &pk_sparse, n_constraints, &sparse.l, &sparse.r, &sparse.o, &sparse.witness);
    }
    let t_sparse = start.elapsed();

    println!("| Path | Prover | Iterations | Total | Per-proof |");
    println!("|------|--------|------------|-------|-----------|");
    println!("| 5b (dense Full PK) | Pippenger | {} | {:?} | {:?} |",
        iterations, t_dense, t_dense / iterations as u32);
    println!("| 6b (sparse Full PK)| Pippenger | {} | {:?} | {:?} |",
        iterations, t_sparse, t_sparse / iterations as u32);

    let per_dense = t_dense / iterations as u32;
    let per_sparse = t_sparse / iterations as u32;
    println!("\nSparse vs Dense speedup: {:.2}×", ratio(per_dense, per_sparse));
}

fn main() {
    println!("=== Benchmark: Sparse-matrix prover (Implementation 6) ===");
    println!("Comparing dense path (Impl 5) vs sparse path (Impl 6).");
    println!("Both use FFT engine + Pippenger MSM + FullProvingKey.");

    // 1. Toy circuit
    bench_toy();

    // 2. PoseidonMerkle depth-2
    if std::path::Path::new("circom/PoseidonMerkle/poseidon_merkle_depth2.r1cs").exists() {
        bench_real_circuit(
            "PoseidonMerkle depth-2",
            "circom/PoseidonMerkle/poseidon_merkle_depth2.r1cs",
            "circom/PoseidonMerkle/witness.wtns",
        );
    } else {
        println!("\n⚠️  PoseidonMerkle circuit not found, skipping.");
    }

    // 3. EdDSAJubJub test
    if std::path::Path::new("circom/EdDSAJubJub/test_pbk_only.r1cs").exists() {
        bench_real_circuit(
            "EdDSAJubJub test_pbk_only",
            "circom/EdDSAJubJub/test_pbk_only.r1cs",
            "circom/EdDSAJubJub/test_pbk_witness.wtns",
        );
    } else {
        println!("\n⚠️  EdDSAJubJub circuit not found, skipping.");
    }

    println!("\n✅ Sparse benchmark complete.");
}
