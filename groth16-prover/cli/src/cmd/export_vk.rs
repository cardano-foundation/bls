//! Export verifying-key subcommand — read a binary `.vk` and emit Aiken source.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::Parser;
use groth16_prover::ceremony::VerifyingKey;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// Arguments for the `export-vk` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the binary verifying key file (from ceremony)
    #[arg(long, value_name = "FILE")]
    verifying_key: PathBuf,

    /// Output path for the generated Aiken source file.
    /// If omitted, prints to stdout.
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

/// Run the export-vk command
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    // ------------------------------------------------------------------
    // 1. Load VK
    // ------------------------------------------------------------------
    let vk_bytes = fs::read(&args.verifying_key)
        .map_err(|e| format!("failed to read verifying key: {e}"))?;

    let vk = VerifyingKey::deserialize_compressed(&vk_bytes[..])
        .map_err(|e| format!("failed to deserialize verifying key: {e:?}"))?;

    // ------------------------------------------------------------------
    // 2. Serialize each point individually to compressed bytes
    // ------------------------------------------------------------------
    let alpha_hex = point_to_hex(&vk.alpha_g1);
    let beta_hex = point_to_hex(&vk.beta_g2);
    let gamma_hex = point_to_hex(&vk.gamma_g2);
    let delta_hex = point_to_hex(&vk.delta_g2);

    // Only export the first n_public ic entries — these are the only ones
    // the on-chain verifier needs (the rest belong to the proving key).
    let ic_public = &vk.ic[..vk.n_public];
    let mut ic_lines = Vec::with_capacity(ic_public.len());
    for (i, pt) in ic_public.iter().enumerate() {
        let hex = point_to_hex(pt);
        ic_lines.push(format!("    // ic[{i}]\n    #\"{hex}\","));
    }

    // ------------------------------------------------------------------
    // 3. Build Aiken source
    // ------------------------------------------------------------------
    let aiken_src = format!(
        "// Auto-generated from {}\n\
         // Circuit: {} public variables (incl. constant wire)\n\
         pub fn verification_key() -> groth16/verifier.VerificationKey {{\n\
           VerificationKey {{\n\
             alpha_g1: #\"{alpha_hex}\",\n\
             beta_g2:  #\"{beta_hex}\",\n\
             gamma_g2: #\"{gamma_hex}\",\n\
             delta_g2: #\"{delta_hex}\",\n\
             ic: [\n\
               {}\n\
             ],\n\
             n_public: {},\n\
           }}\n\
         }}\n",
        args.verifying_key.display(),
        vk.n_public,
        ic_lines.join("\n"),
        vk.n_public,
    );

    // ------------------------------------------------------------------
    // 4. Output
    // ------------------------------------------------------------------
    if let Some(out_path) = args.out {
        fs::write(&out_path, &aiken_src)
            .map_err(|e| format!("failed to write Aiken source: {e}"))?;
        eprintln!("Aiken verification key source written to {}", out_path.display());
    } else {
        println!("{}", aiken_src);
    }

    Ok(())
}

/// Serialize a single curve point to its compressed hex representation.
fn point_to_hex<P: CanonicalSerialize>(pt: &P) -> String {
    let mut buf = Vec::new();
    pt.serialize_compressed(&mut buf).expect("serialization must succeed");
    hex::encode(&buf)
}
