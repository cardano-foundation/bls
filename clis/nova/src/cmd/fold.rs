//! `fold` subcommand — fold step witnesses into an IVC bundle + transcript.

use clap::Parser;
use nova_prover::run_fold;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// Arguments for the `fold` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the step circuit `.r1cs` file
    #[arg(long, value_name = "FILE")]
    pub circuit: PathBuf,

    /// Path to the step proving key (from `nova ceremony`)
    #[arg(long, value_name = "FILE")]
    pub proving_key: PathBuf,

    /// Directory containing the step witness files
    /// (`step_0000.wtns`, `step_0001.wtns`, …).  Files are
    /// processed in sorted order.
    #[arg(long, value_name = "DIR")]
    pub steps: PathBuf,

    /// Output path for the IVC bundle JSON
    /// (`.ivc.json` extension recommended).
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

/// Run the `fold` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let bundle = run_fold(&args.circuit, &args.proving_key, &args.steps)?;

    let json = serde_json::to_string_pretty(&bundle)
        .map_err(|e| format!("failed to serialize IVC bundle: {e}"))?;
    fs::write(&args.out, &json)
        .map_err(|e| format!("failed to write IVC bundle to {}: {e}", args.out.display()))?;
    eprintln!("IVC bundle written to {}", args.out.display());
    Ok(())
}
