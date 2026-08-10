//! `params` subcommand — inspect a step circuit and emit a JSON descriptor.

use clap::Parser;
use nova_prover::run_params;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// Arguments for the `params` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the step circuit `.r1cs` file
    #[arg(long, value_name = "FILE")]
    pub circuit: PathBuf,

    /// Optional JSON output path.
    /// If omitted, the descriptor is printed to stdout.
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,
}

/// Run the `params` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let desc = run_params(&args.circuit)?;
    let json = serde_json::to_string_pretty(&desc)?;

    if let Some(out) = &args.out {
        fs::write(out, &json)
            .map_err(|e| format!("failed to write descriptor to {}: {e}", out.display()))?;
        eprintln!(
            "Step circuit {}: {} wires, {} constraints ({} out + {} in public, {} private) — OK",
            args.circuit.display(),
            desc.n_wires,
            desc.n_constraints,
            desc.n_pub_out,
            desc.n_pub_in,
            desc.n_prv_in
        );
        eprintln!("Descriptor written to {}", out.display());
    } else {
        println!("{json}");
    }
    Ok(())
}
