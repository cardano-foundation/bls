//! Nova benchmarks — Implementation 8 (step-chain) and Implementation 9
//! (NIFS folding + single compression proof) for a compiled step circuit and
//! a directory of chained step witnesses.
//!
//! Implementation 8 (default) measures the three phases of the `nova` IVC
//! step-chain:
//!
//!   1. ceremony — single-party trusted setup for the step circuit
//!   2. fold     — per-step Groth16 proof (+ state-chain check), averaged
//!   3. verify   — Groth16 pairing check over every step proof
//!
//! Implementation 9 (`--nifs`) measures the constant-size path:
//!
//!   1. nifs fold          — per-step Relaxed-R1CS NIFS fold (two O(step)-sized
//!                           MSMs), averaged
//!   2. compression ceremony — single-party trusted setup on the compression
//!                           circuit (≈ 2·n_constraints constraints)
//!   3. compress           — one Groth16 proof over the final relaxed instance
//!   4. verify             — one pairing check + recomputed com(Z)/com(E)/V MSMs
//!
//! Both modes keep the keys/witnesses in memory (no `.pk`/`.vk`/`.wtns` disk
//! I/O beyond the initial read) and exclude transcript hashing — it is
//! microseconds per step, negligible next to the MSMs.  Usage:
//!
//!   cargo run --release --bin benchmark_nova -- --circuit step.r1cs --steps DIR [--limit N]
//!   cargo run --release --bin benchmark_nova -- --nifs --circuit step.r1cs --steps DIR [--limit N]

use ark_bls12_381::{Fr, G1Affine};
use ark_ec::AffineRepr;
use ark_ff::Zero;
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2b512, Digest};
use groth16_prover::ceremony::{
    single_party_ceremony_full_from_tw_sparse, verify_with_vk, ToxicWaste,
};
use groth16_prover::circom_adapter::SparseCircomCircuit;
use groth16_prover::engine::FftQapEngine;
use groth16_prover::prover::{PippengerProver, Proof, Prover, PublicInput};
use nova_prover::nifs;
use nova_prover::{
    prove_compression, verify_compression, fr_to_string, NifsBundle, NifsFinalInstance,
    NifsFoldOutput, NIFS_PARAMS_SEED, NIFS_TRANSCRIPT_PREFIX,
};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let nifs_mode = args.iter().any(|a| a == "--nifs");
    let circuit_path = args
        .windows(2)
        .find(|w| w[0] == "--circuit")
        .map(|w| w[1].clone());
    let steps_dir = args
        .windows(2)
        .find(|w| w[0] == "--steps")
        .map(|w| w[1].clone());
    let (Some(circuit_path), Some(steps_dir)) = (circuit_path, steps_dir) else {
        eprintln!(
            "usage: benchmark_nova [--nifs] --circuit <step.r1cs> --steps <witness-dir> [--limit N]"
        );
        std::process::exit(2);
    };
    let limit = args
        .windows(2)
        .find(|w| w[0] == "--limit")
        .map(|w| {
            w[1].parse::<usize>()
                .expect("--limit must be a positive integer")
        });

    let mut circuit = SparseCircomCircuit::from_r1cs(&circuit_path)
        .unwrap_or_else(|e| panic!("failed to load circuit {circuit_path}: {e}"));
    if circuit.n_pub_in != circuit.n_pub_out {
        panic!(
            "not a step circuit: n_pub_in ({}) != n_pub_out ({})",
            circuit.n_pub_in, circuit.n_pub_out
        );
    }

    let mut wtns: Vec<PathBuf> = fs::read_dir(&steps_dir)
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

    if nifs_mode {
        benchmark_nifs(&engine, &mut circuit, &wtns);
    } else {
        benchmark_step_chain(&engine, &prover, &mut circuit, &wtns, n_public, n_constraints);
    }
}

/// Implementation 8: one Groth16 proof per step + per-step pairing verify.
fn benchmark_step_chain(
    engine: &FftQapEngine,
    prover: &PippengerProver,
    circuit: &mut SparseCircomCircuit,
    wtns: &[PathBuf],
    n_public: usize,
    n_constraints: usize,
) {
    let n_steps = wtns.len();
    let n_pub_out = circuit.n_pub_out as usize;
    let n_pub_in = circuit.n_pub_in as usize;

    // 1. Ceremony — single-party trusted setup for the step circuit.
    let mut rng = rand::thread_rng();
    let t = Instant::now();
    let (full_pk, vk) = single_party_ceremony_full_from_tw_sparse(
        engine,
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
            engine,
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

    // Bundle: N per-step Groth16 proofs (compressed A 48 + B 96 + C 48 bytes).
    let proof_bytes = n_steps * 192;
    println!(
        "bundle: {n_steps} Groth16 proofs = {proof_bytes} B ({:.1} KiB), O(N)",
        proof_bytes as f64 / 1024.0
    );
    println!("all {n_steps} step proofs verified OK");
}

/// Implementation 9: NIFS fold → compression ceremony → one compression proof
/// → O(1) verify.
fn benchmark_nifs(
    engine: &FftQapEngine,
    circuit: &mut SparseCircomCircuit,
    wtns: &[PathBuf],
) {
    let n_steps = wtns.len();
    let n_wires = circuit.n_wires as usize;

    // 1. NIFS fold — in-memory, per-step Relaxed-R1CS folding (state-chain
    //    check + microsecond transcript included; MSM-dominated).
    let t = Instant::now();
    let folded = nifs_fold(circuit, wtns);
    let fold_s = t.elapsed().as_secs_f64();
    println!(
        "nifs fold: {fold_s:.3} s total, {:.3} ms/step over {n_steps} steps (2 O(step)-sized MSMs)",
        fold_s * 1000.0 / n_steps as f64
    );

    // 2. Compression ceremony — single-party trusted setup on the compression
    //    circuit (≈ 2·n_constraints constraints, one per relaxed-equation
    //    product plus the t_i = u·(CZ)_i bindings).
    let cc = nova_prover::compression::CompressionCircuit::new(
        &circuit.l,
        &circuit.r,
        &circuit.o,
        n_wires,
    );
    let mut rng = rand::thread_rng();
    let t = Instant::now();
    let (full_pk, vk) = single_party_ceremony_full_from_tw_sparse(
        engine,
        cc.l.len(),
        cc.n_wires_total,
        cc.n_public,
        &cc.l,
        &cc.r,
        &cc.o,
        ToxicWaste::random(&mut rng),
        false,
    );
    let ceremony_s = t.elapsed().as_secs_f64();
    println!(
        "compression ceremony: {ceremony_s:.3} s (single-party, h_scalar off, {} constraints, {} wires)",
        cc.l.len(),
        cc.n_wires_total
    );

    // 3. Compress — one Groth16 proof over the final relaxed instance (O(1)).
    let t = Instant::now();
    let cproof = prove_compression(circuit, &folded, &full_pk)
        .unwrap_or_else(|e| panic!("failed to build the compression proof: {e}"));
    let compress_s = t.elapsed().as_secs_f64();
    println!(
        "compress: {:.3} s (one Groth16 proof over the final relaxed instance)",
        compress_s
    );

    // 4. Verify — one pairing check + recomputed com(Z)/com(E) and V MSMs.
    let t = Instant::now();
    verify_compression(&folded.bundle, &cproof, &vk)
        .unwrap_or_else(|e| panic!("compression verification failed: {e}"));
    let verify_s = t.elapsed().as_secs_f64();
    println!("verify: {verify_s:.4} s (one pairing + com(Z)/com(E)/V MSMs, O(1))");

    // Bundle size: O(N) (Impl 8) vs constant-in-N (Impl 9).
    let n_pub_out = circuit.n_pub_out as usize;
    let state_bytes = n_steps * n_pub_out * 48;
    let step_proof_bytes = n_steps * 192;
    let impl8_bytes = step_proof_bytes + state_bytes;
    let bundle_json = serde_json::to_string(&folded.bundle)
        .expect("NIFS bundle serialization should not fail");
    let proof_json = serde_json::to_string(&cproof)
        .expect("compression proof serialization should not fail");
    println!(
        "bundle (Impl 8): {n_steps} proofs × 192 B + {n_steps} × {state_bytes} B state = {impl8_bytes} B ({:.1} KiB), grows O(N)",
        impl8_bytes as f64 / 1024.0
    );
    println!(
        "bundle (Impl 9): final instance {} B (O(1)) + compression proof {} B = {} B ({:.1} KiB), constant in N (proof reveals the folded Z/E, so its constant is O(step size))",
        bundle_json.len(),
        proof_json.len(),
        bundle_json.len() + proof_json.len(),
        (bundle_json.len() + proof_json.len()) as f64 / 1024.0
    );
    println!("compression proof verified OK");
}

/// Fold every step witness into one Relaxed-R1CS running instance, exactly as
/// `nova fold --nifs` does (same transparent Pedersen params, FOLD_PREFIX
/// challenge, and NIFS_TRANSCRIPT_PREFIX chain), but fully in memory.
fn nifs_fold(circuit: &mut SparseCircomCircuit, wtns: &[PathBuf]) -> NifsFoldOutput {
    let n_pub_out = circuit.n_pub_out as usize;
    let n_pub_in = circuit.n_pub_in as usize;
    let n_wires = circuit.n_wires as usize;
    let n_constraints = circuit.n_constraints as usize;

    let params = nifs::PedersenParams::from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints);
    let zero_e = vec![Fr::zero(); n_constraints];

    let mut acc_hash: Option<Vec<u8>> = None;
    let mut prev_out: Option<Vec<String>> = None;
    let mut initial_state: Vec<String> = Vec::new();
    let mut acc_u: Option<nifs::RelaxedR1csInstance> = None;
    let mut acc_w: Option<nifs::RelaxedR1csWitness> = None;

    for p in wtns {
        circuit
            .load_witness(p.to_str().expect("witness path is not valid UTF-8"))
            .unwrap_or_else(|e| panic!("failed to load witness {}: {e}", p.display()));
        let w = &circuit.witness;

        let out_fr = &w[1..1 + n_pub_out];
        let in_fr = &w[1 + n_pub_out..1 + n_pub_out + n_pub_in];
        let state_in: Vec<String> = in_fr.iter().map(fr_to_string).collect();
        let state_out: Vec<String> = out_fr.iter().map(fr_to_string).collect();
        if let Some(prev) = &prev_out {
            assert_eq!(&state_in, prev, "state_in does not chain to previous state_out");
        } else {
            initial_state = state_in.clone();
            acc_hash = Some(transcript_nifs_init(in_fr));
        }

        let x = w[1..1 + n_pub_out + n_pub_in].to_vec();
        let step_u = nifs::RelaxedR1csInstance {
            x,
            u: Fr::from(1u64),
            w_commit: nifs::commit(&params.basis_w, w),
            e_commit: G1Affine::zero(),
        };
        let step_w = nifs::RelaxedR1csWitness {
            w: w.to_vec(),
            e: zero_e.clone(),
        };

        match acc_u.take() {
            None => {
                acc_u = Some(step_u);
                acc_w = Some(step_w);
            }
            Some(u_acc) => {
                let w_acc = acc_w.take().expect("running witness must exist");
                let acc = acc_hash.as_ref().expect("transcript initialized");
                let challenge = nifs::fold_challenge(acc, &u_acc, &step_u);
                let (u3, w3) = nifs::fold(
                    &params,
                    &circuit.l,
                    &circuit.r,
                    &circuit.o,
                    &u_acc,
                    &w_acc,
                    &step_u,
                    &step_w,
                    challenge,
                );
                acc_u = Some(u3);
                acc_w = Some(w3);
            }
        }

        acc_hash = Some(transcript_nifs_step(
            acc_hash.as_ref().expect("transcript initialized"),
            acc_u.as_ref().expect("running instance"),
        ));
        prev_out = Some(state_out);
    }

    let final_u = acc_u.expect("no step witnesses folded");
    let final_w = acc_w.expect("final witness present");
    let transcript_final = hex::encode(acc_hash.expect("transcript finalized"));

    let bundle = NifsBundle {
        circuit: String::new(),
        n_wires: circuit.n_wires,
        n_constraints: circuit.n_constraints,
        n_pub_out: circuit.n_pub_out,
        n_pub_in: circuit.n_pub_in,
        initial_state,
        n_steps: wtns.len(),
        final_instance: NifsFinalInstance {
            x: final_u.x.iter().map(fr_to_string).collect(),
            u: fr_to_string(&final_u.u),
            w_commit: g1_hex(&final_u.w_commit),
            e_commit: g1_hex(&final_u.e_commit),
        },
        transcript_final,
    };

    NifsFoldOutput {
        bundle,
        final_instance: final_u,
        final_witness: final_w,
    }
}

/// `H(NIFS_TRANSCRIPT_PREFIX ‖ initial_state)`, matching `nova fold --nifs`.
fn transcript_nifs_init(initial_state: &[Fr]) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(frs_bytes(initial_state));
    h.finalize().to_vec()
}

/// `H(NIFS_TRANSCRIPT_PREFIX ‖ acc ‖ instance_bytes)`, matching `nova fold --nifs`.
fn transcript_nifs_step(acc: &[u8], u: &nifs::RelaxedR1csInstance) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(acc);
    h.update(nifs::instance_to_bytes(u).expect("serialize instance"));
    h.finalize().to_vec()
}

fn frs_bytes(frs: &[Fr]) -> Vec<u8> {
    let mut buf = Vec::new();
    for f in frs {
        f.serialize_compressed(&mut buf).expect("Fr serialize");
    }
    buf
}

fn g1_hex(p: &G1Affine) -> String {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).expect("G1 serialize");
    hex::encode(buf)
}
