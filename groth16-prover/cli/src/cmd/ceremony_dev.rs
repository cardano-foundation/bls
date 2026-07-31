//! Dev ceremony subcommand — single-party trusted setup that outputs a FullProvingKey.
//!
//! This is the **insecure, dev-only** path.  It generates random toxic waste
//! locally, computes all group elements from it, and writes a `FullProvingKey`
//! that contains **no scalars**.  The resulting `.pk` file is in the same
//! binary format as what a production Phase-2 MPC would produce, so the
//! downstream `prove` / `verify` code is agnostic.
//!
//! For production deployments use the `phase2` multi-party ceremony instead.

use ark_serialize::CanonicalSerialize;
use clap::Parser;
use groth16_prover::ceremony::{single_party_ceremony_full, single_party_ceremony_full_from_tw_sparse};
use groth16_prover::circom_adapter::{CircomCircuit, SparseCircomCircuit};
use groth16_prover::engine::FftQapEngine;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// Arguments for the `ceremony-dev` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the `.r1cs` circuit file
    #[arg(long, value_name = "FILE")]
    circuit: PathBuf,

    /// Output path for the proving key (.pk extension recommended)
    #[arg(long, value_name = "FILE")]
    proving_key: PathBuf,

    /// Output path for the verification key (.vk extension recommended)
    #[arg(long, value_name = "FILE")]
    verifying_key: PathBuf,

    /// Use sparse constraint representation (Implementation 6).
    /// Avoids expanding the `.r1cs` into dense matrices, saving memory
    /// for large circuits (e.g. Blake2b-224, Ed25519).
    #[arg(long)]
    sparse: bool,

    /// Use h-query scalar compression (Implementation 7).
    /// Stores a single scalar `delta_inv * T(tau)` instead of the full
    /// `h_query` G1 vector, cutting PK size and eliminating the h MSM.
    #[arg(long)]
    h_scalar: bool,
}

/// Run the dev ceremony command
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    // ------------------------------------------------------------------
    // 1. Load circuit
    // ------------------------------------------------------------------
    let (full_pk, vk) = if args.sparse {
        let circuit = SparseCircomCircuit::from_r1cs(
            args.circuit
                .to_str()
                .ok_or("circuit path is not valid UTF-8")?,
        )
        .map_err(|e| format!("failed to load circuit: {e}"))?;

        eprintln!(
            "Loaded circuit (sparse): {} wires, {} constraints (public: {} out + {} in, private: {})",
            circuit.n_wires,
            circuit.n_constraints,
            circuit.n_pub_out,
            circuit.n_pub_in,
            circuit.n_prv_in
        );

        let n_public = 1 + circuit.n_pub_out as usize + circuit.n_pub_in as usize;
        let mut rng = rand::thread_rng();
        let engine = FftQapEngine::new();
        let tw = groth16_prover::ceremony::ToxicWaste::random(&mut rng);

        let (full_pk, vk) = single_party_ceremony_full_from_tw_sparse(
            &engine,
            circuit.n_constraints as usize,
            circuit.n_wires as usize,
            n_public,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            tw,
            args.h_scalar,
        );
        (full_pk, vk)
    } else {
        let circuit = CircomCircuit::from_r1cs(
            args.circuit
                .to_str()
                .ok_or("circuit path is not valid UTF-8")?,
        )
        .map_err(|e| format!("failed to load circuit: {e}"))?;

        eprintln!(
            "Loaded circuit: {} wires, {} constraints (public: {} out + {} in, private: {})",
            circuit.n_wires,
            circuit.n_constraints,
            circuit.n_pub_out,
            circuit.n_pub_in,
            circuit.n_prv_in
        );

        let n_public = 1 + circuit.n_pub_out as usize + circuit.n_pub_in as usize;
        let mut rng = rand::thread_rng();
        let engine = FftQapEngine::new();
        let (full_pk, vk) = single_party_ceremony_full(&engine, &circuit.l, &circuit.r, &circuit.o, n_public, &mut rng, args.h_scalar);
        (full_pk, vk)
    };

    if args.h_scalar {
        eprintln!("Dev ceremony complete. Full proving key generated with h_scalar compression (Implementation 7).");
    } else {
        eprintln!("Dev ceremony complete. Full proving key generated (group elements only, no scalars).");
    }
    eprintln!("  Proving key:  {}  ({} bytes compressed / {} bytes uncompressed)", args.proving_key.display(), {
        let mut buf = Vec::new();
        full_pk.serialize_compressed(&mut buf).unwrap();
        buf.len()
    }, {
        let mut buf = Vec::new();
        full_pk.serialize_uncompressed(&mut buf).unwrap();
        buf.len()
    });
    eprintln!("  Verifying key: {}  ({} bytes)", args.verifying_key.display(), {
        let mut buf = Vec::new();
        vk.serialize_compressed(&mut buf).unwrap();
        buf.len()
    });

    // ------------------------------------------------------------------
    // 5. Serialize keys
    // ------------------------------------------------------------------
    // Proving key is written UNCOMPRESSED for large circuits (Ed25519, Blake2b-224).
    // Compressed deserialization requires decompression (square roots) for every
    // curve point, which takes 10+ minutes for 20M+ points. Uncompressed is
    // raw bytes and deserializes in < 30 seconds.
    let mut pk_bytes = Vec::new();
    full_pk.serialize_uncompressed(&mut pk_bytes)
        .map_err(|e| format!("failed to serialize proving key: {e:?}"))?;
    fs::write(&args.proving_key, &pk_bytes)
        .map_err(|e| format!("failed to write proving key: {e}"))?;
    eprintln!("Full proving key (uncompressed) written to {}", args.proving_key.display());

    // Verifying key is also written UNCOMPRESSED for large circuits.
    // The VK contains ic points for every variable (1M+ for large circuits).
    // Compressed deserialization requires square-root decompression for each point,
    // which dominates verification time.
    let mut vk_bytes = Vec::new();
    vk.serialize_uncompressed(&mut vk_bytes)
        .map_err(|e| format!("failed to serialize verifying key: {e:?}"))?;
    fs::write(&args.verifying_key, &vk_bytes)
        .map_err(|e| format!("failed to write verifying key: {e}"))?;
    eprintln!("Verifying key (uncompressed) written to {}", args.verifying_key.display());

    Ok(())
}
