//! `compress` subcommand — Groth16-compress the final NIFS instance.

use clap::Parser;
use nova_prover::run_compress;
use std::error::Error;
use std::path::PathBuf;

/// Arguments for the `compress` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the step circuit `.r1cs` file
    #[arg(long, value_name = "FILE")]
    pub circuit: PathBuf,

    /// Directory containing the step witness files
    /// (`step_0000.wtns`, `step_0001.wtns`, …).  The fold is re-run
    /// deterministically to recover the private final witness.
    #[arg(long, value_name = "DIR")]
    pub steps: PathBuf,

    /// Path to the compression proving key (from
    /// `trusted-setup ceremony-dev --sparse` on the compression `.r1cs`
    /// emitted by `fold --nifs --compression-r1cs`)
    #[arg(long, value_name = "FILE")]
    pub proving_key: PathBuf,

    /// Output path for the compression proof JSON
    /// (`.proof.json` extension recommended)
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,
}

/// Run the `compress` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    run_compress(&args.circuit, &args.steps, &args.proving_key, &args.out)?;
    Ok(())
}
