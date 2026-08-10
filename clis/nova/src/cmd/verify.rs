//! `verify` subcommand — verify a folded IVC bundle.

use clap::Parser;
use nova_prover::run_verify;
use std::error::Error;
use std::path::PathBuf;

/// Arguments for the `verify` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the IVC bundle produced by `nova fold`
    #[arg(long, value_name = "FILE")]
    pub ivc: PathBuf,

    /// Path to the step verifying key (from `nova ceremony`)
    #[arg(long, value_name = "FILE")]
    pub verifying_key: PathBuf,
}

/// Run the `verify` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let out = run_verify(&args.ivc, &args.verifying_key)?;

    eprintln!(
        "Verified {} steps: {} pairings OK, state chain OK, transcript OK",
        out.steps, out.steps
    );
    eprintln!("Final transcript: {}", out.transcript_final);
    Ok(())
}
