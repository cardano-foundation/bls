//! Verify-batch subcommand — check many Groth16 proofs with a single
//! multi-pairing product (Impl 11).

use ark_bls12_381::{G1Affine, G2Affine};
use ark_serialize::CanonicalDeserialize;
use clap::Parser;
use groth16_prover::ceremony::VerifyingKey;
use groth16_prover::prover::{PreparedVerifyingKey, Proof, PublicInput, verify_batch};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// Arguments for the `verify-batch` subcommand.
///
/// Proof and public-input lists are paired positionally: `--proof` entries
/// align with `--public` entries in the order given.
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to a proof file (raw binary, 192 bytes). May be repeated; the
    /// i-th `--proof` pairs with the i-th `--public`.
    #[arg(long, value_name = "FILE", required = true)]
    proof: Vec<PathBuf>,

    /// Path to a public-input file (raw binary, 48 bytes). May be repeated.
    #[arg(long, value_name = "FILE", required = true)]
    public: Vec<PathBuf>,

    /// Path to the verifying key file (from the ceremony step).
    /// If omitted, the deterministic test values are used (dev only).
    #[arg(long, value_name = "FILE")]
    verifying_key: Option<PathBuf>,
}

/// Run the verify-batch command.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    if args.proof.is_empty() {
        return Err("verify-batch: at least one --proof/--public pair is required".into());
    }
    if args.proof.len() != args.public.len() {
        return Err(format!(
            "verify-batch: {} proof(s) but {} public-input file(s); each proof needs its own public input",
            args.proof.len(),
            args.public.len()
        )
        .into());
    }

    // ------------------------------------------------------------------
    // 1. Load verifying key (once) — the fixed CRS points are prepared a
    //    single time and reused across every proof in the batch.
    // ------------------------------------------------------------------
    let vk = if let Some(vk_path) = &args.verifying_key {
        let vk = crate::util::load_vk(vk_path)
            .map_err(|e| format!("failed to load verifying key: {e}"))?;
        eprintln!("Loaded verifying key from {}", vk_path.display());
        vk
    } else {
        eprintln!("Warning: no verifying key provided; using deterministic test toxic waste (dev only)");
        use ark_bls12_381::{Fr, G1Projective, G2Projective};
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
            ic: Vec::new(),
            n_public: 2,
        }
    };
    let pvk = PreparedVerifyingKey::from_vk(&vk);

    // ------------------------------------------------------------------
    // 2. Load all proofs + public inputs
    // ------------------------------------------------------------------
    let mut proofs = Vec::with_capacity(args.proof.len());
    let mut public_inputs = Vec::with_capacity(args.public.len());

    for (i, (pf, pubf)) in args.proof.iter().zip(args.public.iter()).enumerate() {
        let proof_bytes = fs::read(pf)
            .map_err(|e| format!("failed to read proof file {}: {e}", pf.display()))?;
        if proof_bytes.len() != 192 {
            return Err(format!(
                "proof file {} must be exactly 192 bytes (got {})",
                pf.display(),
                proof_bytes.len()
            )
            .into());
        }
        let a = G1Affine::deserialize_compressed(&proof_bytes[0..48])
            .map_err(|e| format!("failed to deserialize proof {i} A: {e:?}"))?;
        let b = G2Affine::deserialize_compressed(&proof_bytes[48..144])
            .map_err(|e| format!("failed to deserialize proof {i} B: {e:?}"))?;
        let c = G1Affine::deserialize_compressed(&proof_bytes[144..192])
            .map_err(|e| format!("failed to deserialize proof {i} C: {e:?}"))?;

        let public_bytes = fs::read(pubf)
            .map_err(|e| format!("failed to read public-input file {}: {e}", pubf.display()))?;
        if public_bytes.len() != 48 {
            return Err(format!(
                "public-input file {} must be exactly 48 bytes (got {})",
                pubf.display(),
                public_bytes.len()
            )
            .into());
        }
        let v = G1Affine::deserialize_compressed(&public_bytes[..])
            .map_err(|e| format!("failed to deserialize public input {i} V: {e:?}"))?;

        proofs.push(Proof { a, b, c });
        public_inputs.push(PublicInput { v });
    }

    // ------------------------------------------------------------------
    // 3. Single multi-pairing product for the whole batch
    // ------------------------------------------------------------------
    let valid = verify_batch(&proofs, &public_inputs, &pvk);

    if valid {
        println!("Verification result: VALID ({} proofs, one multi-pairing product)", proofs.len());
        Ok(())
    } else {
        Err(format!(
            "Verification result: INVALID — the batch of {} proofs does not satisfy the folded pairing equation",
            proofs.len()
        )
        .into())
    }
}