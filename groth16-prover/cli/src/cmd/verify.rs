//! Verify subcommand — load a proof + public input and run the Groth16 pairing check.

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::Group;
use ark_serialize::CanonicalDeserialize;
use clap::Parser;
use groth16_prover::prover::{verify_proof, Proof, PublicInput};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// Arguments for the `verify` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the proof file (raw binary, 192 bytes)
    #[arg(long, value_name = "FILE")]
    proof: PathBuf,

    /// Path to the public-input file (raw binary, 48 bytes)
    #[arg(long, value_name = "FILE")]
    public: PathBuf,
}

/// Run the verify command
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    // ------------------------------------------------------------------
    // 1. Load proof
    // ------------------------------------------------------------------
    let proof_bytes = fs::read(&args.proof)
        .map_err(|e| format!("failed to read proof file: {e}"))?;

    if proof_bytes.len() != 192 {
        return Err(format!(
            "proof file must be exactly 192 bytes (got {})",
            proof_bytes.len()
        )
        .into());
    }

    let a = G1Affine::deserialize_compressed(&proof_bytes[0..48])
        .map_err(|e| format!("failed to deserialize proof.A: {e:?}"))?;
    let b = G2Affine::deserialize_compressed(&proof_bytes[48..144])
        .map_err(|e| format!("failed to deserialize proof.B: {e:?}"))?;
    let c = G1Affine::deserialize_compressed(&proof_bytes[144..192])
        .map_err(|e| format!("failed to deserialize proof.C: {e:?}"))?;

    let proof = Proof { a, b, c };

    // ------------------------------------------------------------------
    // 2. Load public input
    // ------------------------------------------------------------------
    let public_bytes = fs::read(&args.public)
        .map_err(|e| format!("failed to read public-input file: {e}"))?;

    if public_bytes.len() != 48 {
        return Err(format!(
            "public-input file must be exactly 48 bytes (got {})",
            public_bytes.len()
        )
        .into());
    }

    let v = G1Affine::deserialize_compressed(&public_bytes[..])
        .map_err(|e| format!("failed to deserialize public input V: {e:?}"))?;

    let public_input = PublicInput { v };

    // ------------------------------------------------------------------
    // 3. Build verification key from hard-coded toxic waste
    //
    // NOTE: In a production deployment the verification key would be
    // loaded from a file (generated during the trusted-setup ceremony).
    // Here we use the same deterministic test values as the prover so
    // that CLI-generated proofs can be verified end-to-end without
    // requiring a separate VK file.
    // ------------------------------------------------------------------
    let alpha = Fr::from(5u64);
    let beta = Fr::from(7u64);
    let gamma = Fr::from(11u64);
    let delta = Fr::from(13u64);

    let alpha_g1 = G1Affine::from(G1Projective::generator() * alpha);
    let beta_g2 = G2Affine::from(G2Projective::generator() * beta);
    let gamma_g2 = G2Affine::from(G2Projective::generator() * gamma);
    let delta_g2 = G2Affine::from(G2Projective::generator() * delta);

    // ------------------------------------------------------------------
    // 4. Pairing check
    // ------------------------------------------------------------------
    let valid = verify_proof(&proof, &public_input, &alpha_g1, &beta_g2, &gamma_g2, &delta_g2);

    if valid {
        println!("Verification result: VALID");
        Ok(())
    } else {
        Err("Verification result: INVALID — pairing equation does not hold".into())
    }
}
