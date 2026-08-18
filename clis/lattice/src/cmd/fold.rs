//! `fold` subcommand — fold step witnesses into a relaxed instance (Lova folding).

use clap::Parser;
use lattice::run_fold_lova;
use lattice_prover::params::LovaParams;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// Arguments for the `fold` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Number of steps to fold
    #[arg(long, default_value_t = 8)]
    pub steps: usize,

    /// Commitment matrix rows (m parameter)
    #[arg(long, default_value_t = 256)]
    pub m: usize,

    /// Witness vector dimension (n parameter)
    #[arg(long, default_value_t = 128)]
    pub n: usize,

    /// Number of folding rounds
    #[arg(long, default_value_t = 32)]
    pub rounds: usize,

    /// Output path for the folded state JSON (optional).
    /// If omitted, prints a summary to stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

/// Run the `fold` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let params = LovaParams {
        m: args.m,
        n: args.n,
        witness_chunk_size: args.n / 4,
        decompose_base: 2,
        decompose_digits: 64,
        witness_norm_bound: 1 << 31,
        error_norm_bound: 1 << 31,
        num_rounds: args.rounds,
    };

    eprintln!(
        "Lova fold: m={}, n={}, steps={}, decompose_base=2, decompose_digits=64",
        params.m, params.n, args.steps,
    );

    let result = run_fold_lova(&params, args.steps)?;

    if let Some(out_path) = &args.out {
        let json = serde_json::to_string_pretty(&format!(
            "Lova fold: {} steps, {:.2} ms fold, {:.2} ms verify, {} bytes proof",
            result.steps, result.total_fold_ms, result.total_verify_ms, result.proof_size_bytes
        ))
        .unwrap_or_default();
        fs::write(out_path, &json)
            .map_err(|e| format!("failed to write to {}: {e}", out_path.display()))?;
        eprintln!("Fold result written to {}", out_path.display());
    }

    // Print per-step summary
    for step_result in &result.fold_steps {
        eprintln!(
            "  step {:3}: u={} witness_norm={} error_norm={} elapsed={:.2} ms",
            step_result.step,
            step_result.u,
            step_result.witness_norm,
            step_result.error_norm,
            step_result.elapsed_ms
        );
    }

    eprintln!();
    eprintln!(
        "Fold complete: {} steps in {:.2} ms (avg {:.2} ms/step)",
        result.steps,
        result.total_fold_ms,
        result.total_fold_ms / result.steps as f64,
    );
    eprintln!(
        "Verify total: {:.2} ms (avg {:.2} ms/step)",
        result.total_verify_ms,
        result.total_verify_ms / result.steps as f64,
    );
    eprintln!(
        "Proof size: {} bytes ({:.1} KiB)",
        result.proof_size_bytes,
        result.proof_size_bytes as f64 / 1024.0
    );

    Ok(())
}
