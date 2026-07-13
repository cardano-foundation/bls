//! Compute witness inputs for the Spend(depth) circuit.
//!
//! Reads a transcript file (nullifier nonce pairs, one per line) and
//! produces a JSON file with the private Merkle-path data needed by the
//! Circom witness generator.
//!
//! Example:
//!
//!   $ groth16-prover compute-inputs \
//!       --depth 2 \
//!       --transcript transcript.txt \
//!       --nullifier 2 \
//!       --out input.json

use clap::Parser;
use groth16_prover::privacy_inputs::{compute_spend_inputs, parse_transcript_lines};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// Arguments for the `compute-inputs` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Merkle tree depth
    #[arg(long, value_name = "N")]
    depth: usize,

    /// Path to the transcript file
    #[arg(long, value_name = "FILE")]
    transcript: PathBuf,

    /// Target nullifier to prove membership for
    #[arg(long, value_name = "VALUE")]
    nullifier: String,

    /// Output path for the JSON witness input
    #[arg(long, value_name = "FILE", default_value = "input.json")]
    out: PathBuf,
}

/// Run the compute-inputs command
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    // Read transcript
    let transcript_text = fs::read_to_string(&args.transcript)
        .map_err(|e| format!("failed to read transcript: {e}"))?;
    let lines: Vec<String> = transcript_text
        .lines()
        .map(|s| s.to_string())
        .collect();

    let transcript = parse_transcript_lines(&lines)
        .map_err(|e| format!("failed to parse transcript: {e}"))?;

    // Compute inputs
    let inputs = compute_spend_inputs(args.depth, &transcript, &args.nullifier)
        .map_err(|e| format!("failed to compute inputs: {e}"))?;

    // Build JSON map
    let mut json_map = serde_json::Map::new();
    for (key, value) in inputs.to_json_map() {
        json_map.insert(key, serde_json::Value::String(value));
    }
    let json = serde_json::to_string_pretty(&json_map)
        .map_err(|e| format!("failed to serialize JSON: {e}"))?;

    fs::write(&args.out, json)
        .map_err(|e| format!("failed to write output: {e}"))?;

    eprintln!("Witness input written to {}", args.out.display());
    eprintln!("  digest:      {}", inputs.digest);
    eprintln!("  nullifier:   {}", inputs.nullifier);
    eprintln!("  nonce:       {}", inputs.nonce);
    eprintln!("  siblings:    {}", inputs.siblings.len());

    Ok(())
}
