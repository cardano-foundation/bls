//! `compress` subcommand — compress a NIFS bundle into one proof.
//!
//! With `--sumcheck` (Implementation 10), produces a transparent sumcheck proof.
//! Without it (Implementation 9), produces a Groth16 compression proof.

use clap::Parser;
use nova_prover::{run_compress, run_compress_sumcheck};
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
    /// emitted by `fold --nifs --compression-r1cs`).
    /// Not required with `--sumcheck` (transparent sumcheck needs no setup).
    #[arg(long, value_name = "FILE", required_unless_present = "sumcheck")]
    pub proving_key: Option<PathBuf>,

    /// Output path for the compression proof JSON
    /// (`.proof.json` extension recommended)
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,

    /// Use sumcheck compression (Implementation 10) instead of Groth16.
    /// No trusted setup needed — the sumcheck proof is transparent and
    /// produces O(log N) proof size.
    #[arg(long)]
    pub sumcheck: bool,
}

/// Run the `compress` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    if args.sumcheck {
        run_compress_sumcheck(&args.circuit, &args.steps, &args.out)?;
    } else {
        run_compress(
            &args.circuit,
            &args.steps,
            args.proving_key
                .as_deref()
                .expect("clap requires --proving-key unless --sumcheck"),
            &args.out,
        )?;
    }
    Ok(())
}
