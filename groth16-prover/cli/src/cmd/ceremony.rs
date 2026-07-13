//! Ceremony subcommand — run a trusted-setup ceremony for a circuit.
//!
//! Generates random toxic waste and produces a proving key + verification key.

use ark_serialize::CanonicalSerialize;
use clap::Parser;
use groth16_prover::ceremony::ceremony;
use groth16_prover::circom_adapter::CircomCircuit;
use groth16_prover::engine::FftQapEngine;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// Arguments for the `ceremony` subcommand
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
}

/// Run the ceremony command
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    // ------------------------------------------------------------------
    // 1. Load circuit
    // ------------------------------------------------------------------
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

    // ------------------------------------------------------------------
    // 2. Determine number of public variables
    // ------------------------------------------------------------------
    // In Circom, the constant wire (always 1) is implicit, followed by
    // public outputs, then public inputs, then private inputs.
    // Our convention: n_public = 1 (constant) + n_pub_out + n_pub_in
    let n_public = 1 + circuit.n_pub_out as usize + circuit.n_pub_in as usize;

    // ------------------------------------------------------------------
    // 3. Run ceremony
    // ------------------------------------------------------------------
    let mut rng = rand::thread_rng();
    let engine = FftQapEngine::new();
    let (pk, vk) = ceremony(&engine, &circuit.l, &circuit.r, &circuit.o, n_public, &mut rng);

    eprintln!("Ceremony complete. Toxic waste generated and discarded from memory.");
    eprintln!("  Proving key:  {}  ({} bytes)", args.proving_key.display(), {
        let mut buf = Vec::new();
        pk.serialize_compressed(&mut buf).unwrap();
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
    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes)
        .map_err(|e| format!("failed to serialize proving key: {e:?}"))?;
    fs::write(&args.proving_key, &pk_bytes)
        .map_err(|e| format!("failed to write proving key: {e}"))?;
    eprintln!("Proving key written to {}", args.proving_key.display());

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| format!("failed to serialize verifying key: {e:?}"))?;
    fs::write(&args.verifying_key, &vk_bytes)
        .map_err(|e| format!("failed to write verifying key: {e}"))?;
    eprintln!("Verifying key written to {}", args.verifying_key.display());

    Ok(())
}
