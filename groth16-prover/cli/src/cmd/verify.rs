//! Verify subcommand — load a proof + public input and run the Groth16 pairing check.

use ark_bls12_381::{G1Affine, G2Affine};
use ark_serialize::CanonicalDeserialize;
use clap::Parser;
use groth16_prover::ceremony::VerifyingKey;
use groth16_prover::prover::{Proof, PublicInput, verify_proof};
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

    /// Path to the verifying key file (from the ceremony step).
    /// If omitted, the deterministic test values are used (dev only).
    #[arg(long, value_name = "FILE")]
    verifying_key: Option<PathBuf>,
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
    // 3. Load verifying key (or fall back to deterministic test values)
    // ------------------------------------------------------------------
    let vk = if let Some(vk_path) = &args.verifying_key {
        let vk_bytes = fs::read(vk_path)
            .map_err(|e| format!("failed to read verifying key: {e}"))?;
        let vk = VerifyingKey::deserialize_compressed(&vk_bytes[..])
            .map_err(|e| format!("failed to deserialize verifying key: {e:?}"))?;
        eprintln!("Loaded verifying key from {}", vk_path.display());
        vk
    } else {
        eprintln!("Warning: no verifying key provided; using deterministic test toxic waste (dev only)");
        // Reconstruct the hard-coded VK from deterministic scalars
        use ark_bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Fr};
        use ark_ec::Group;
        let alpha = Fr::from(5u64);
        let beta = Fr::from(7u64);
        let gamma = Fr::from(11u64);
        let delta = Fr::from(13u64);
        VerifyingKey {
            alpha_g1: G1Affine::from(G1Projective::generator() * alpha),
            beta_g2: G2Affine::from(G2Projective::generator() * beta),
            gamma_g2: G2Affine::from(G2Projective::generator() * gamma),
            delta_g2: G2Affine::from(G2Projective::generator() * delta),
            ic: Vec::new(), // empty — verify_proof only uses the four fixed points when no VK is loaded
            n_public: 2,
        }
    };

    // ------------------------------------------------------------------
    // 4. Pairing check
    // ------------------------------------------------------------------
    let valid = verify_proof(&proof, &public_input, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2);

    if valid {
        println!("Verification result: VALID");
        Ok(())
    } else {
        Err("Verification result: INVALID — pairing equation does not hold".into())
    }
}
