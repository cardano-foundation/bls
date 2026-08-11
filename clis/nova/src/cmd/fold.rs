//! `fold` subcommand — fold step witnesses into an IVC bundle + transcript.

use clap::Parser;
use nova_prover::run_fold;
use nova_prover::run_fold_nifs;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// Arguments for the `fold` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the step circuit `.r1cs` file
    #[arg(long, value_name = "FILE")]
    pub circuit: PathBuf,

    /// Path to the step proving key (from `nova ceremony`).
    /// Not required with `--nifs` — folding is transparent.
    #[arg(long, value_name = "FILE", required_unless_present = "nifs")]
    pub proving_key: Option<PathBuf>,

    /// Directory containing the step witness files
    /// (`step_0000.wtns`, `step_0001.wtns`, …).  Files are
    /// processed in sorted order.
    #[arg(long, value_name = "DIR")]
    pub steps: PathBuf,

    /// Output path for the IVC bundle JSON
    /// (`.ivc.json` extension recommended).
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,

    /// Use NIFS folding (Implementation 9): fold the step instances into one
    /// Relaxed-R1CS instance instead of producing one Groth16 proof per step.
    /// Folding is linear-time and needs no proving key.
    #[arg(long)]
    pub nifs: bool,
}

/// Run the `fold` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    if args.nifs {
        let out = run_fold_nifs(&args.circuit, &args.steps)?;
        let json = serde_json::to_string_pretty(&out.bundle)
            .map_err(|e| format!("failed to serialize NIFS bundle: {e}"))?;
        fs::write(&args.out, &json)
            .map_err(|e| format!("failed to write NIFS bundle to {}: {e}", args.out.display()))?;
        eprintln!(
            "NIFS bundle written to {} ({} steps → one instance, u = {})",
            args.out.display(),
            out.bundle.n_steps,
            out.bundle.final_instance.u
        );
        return Ok(());
    }

    let bundle = run_fold(&args.circuit, &args.proving_key.unwrap(), &args.steps)?;

    let json = serde_json::to_string_pretty(&bundle)
        .map_err(|e| format!("failed to serialize IVC bundle: {e}"))?;
    fs::write(&args.out, &json)
        .map_err(|e| format!("failed to write IVC bundle to {}: {e}", args.out.display()))?;
    eprintln!("IVC bundle written to {}", args.out.display());
    Ok(())
}
