//! `ceremony` subcommand — single-party trusted setup for a step circuit.

use clap::Parser;
use nova_prover::run_ceremony;
use std::error::Error;
use std::path::PathBuf;

/// Arguments for the `ceremony` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the step circuit `.r1cs` file
    #[arg(long, value_name = "FILE")]
    pub circuit: PathBuf,

    /// Output path for the proving key (`.pk` extension recommended)
    #[arg(long, value_name = "FILE")]
    pub proving_key: PathBuf,

    /// Output path for the verifying key (`.vk` extension recommended)
    #[arg(long, value_name = "FILE")]
    pub verifying_key: PathBuf,

    /// Use h-query scalar compression (Implementation 7).
    /// Stores a single scalar `delta_inv * T(tau)` instead of the full
    /// `h_query` G1 vector, cutting PK size and eliminating the h MSM.
    #[arg(long)]
    pub h_scalar: bool,
}

/// Run the `ceremony` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    run_ceremony(
        &args.circuit,
        &args.proving_key,
        &args.verifying_key,
        args.h_scalar,
    )?;
    Ok(())
}
