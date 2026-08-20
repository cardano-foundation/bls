//! `compress` subcommand — compress a NIFS bundle into one proof.
//!
//! Default: sumcheck compression (Implementation 10) — transparent, no
//! ceremony, O(log N) proof size.  With `--groth16` (Implementation 9),
//! produces a Groth16 compression proof (requires a proving key).
//! With `--slim` (Implementation 11), strips the HashPC opening proofs
//! from the sumcheck proof to produce an on-chain-friendly slim proof
//! (~4 KiB for 7,724-constraint steps).

use clap::Parser;
use nova_prover::{run_compress_opt, run_compress_sumcheck_opt, NifsSumcheckProof, OptFlags};
use std::error::Error;
use std::fs;
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
    /// Only needed with `--groth16` (Groth16 compression requires a setup).
    #[arg(long, value_name = "FILE", requires = "groth16")]
    pub proving_key: Option<PathBuf>,

    /// Output path for the compression proof JSON
    /// (`.proof.json` extension recommended)
    #[arg(long, value_name = "FILE")]
    pub out: PathBuf,

    /// Use Groth16 compression (Implementation 9) instead of the default
    /// sumcheck compression.  Requires a proving key from
    /// `trusted-setup ceremony-dev --sparse` on the compression circuit.
    #[arg(long)]
    pub groth16: bool,

    /// (With sumcheck) Strip HashPC opening proofs to produce a slim
    /// on-chain proof (Implementation 11).  Cuts proof size from ~470 KiB
    /// to ~4 KiB for 7,724-constraint steps.  The opening proofs are
    /// verified off-chain as an audit trail.
    #[arg(long)]
    pub slim: bool,

    /// Implementation 11 optimizations (comma-separated):
    ///   parallel  — use rayon for independent row/column operations
    ///   lazy      — defer Pedersen MSM to final step
    ///   all       — enable all optimizations
    #[arg(long, value_name = "OPTS", default_value = "none")]
    pub opt: String,
}

fn parse_opt_flags(s: &str) -> Result<OptFlags, Box<dyn Error>> {
    let mut flags = OptFlags::NONE;
    for part in s.split(',') {
        match part.trim() {
            "none" | "" => {}
            "parallel" | "p" => flags.parallel = true,
            "lazy" | "l" => flags.lazy_commit = true,
            "all" | "a" => flags = OptFlags::ALL,
            other => return Err(format!("unknown optimization: '{other}' — valid: parallel, lazy, all, none").into()),
        }
    }
    Ok(flags)
}

/// Run the `compress` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let opts = parse_opt_flags(&args.opt)?;
    if args.groth16 {
        run_compress_opt(
            &args.circuit,
            &args.steps,
            args.proving_key
                .as_deref()
                .expect("clap requires --proving-key with --groth16"),
            &args.out,
            opts,
        )?;
    } else if args.slim {
        // Sumcheck compress, then strip opening proofs for on-chain proof.
        let tmp = args.out.with_extension("full.json");
        run_compress_sumcheck_opt(&args.circuit, &args.steps, &tmp, opts)?;
        let full_bytes = fs::read(&tmp)?;
        let full_proof: NifsSumcheckProof = serde_json::from_slice(&full_bytes)?;
        let slim_proof = full_proof.to_slim();
        let slim_json = serde_json::to_string_pretty(&slim_proof)?;
        fs::write(&args.out, &slim_json)?;
        let full_size = full_bytes.len();
        let slim_size = slim_json.len();
        fs::remove_file(&tmp).ok();
        eprintln!(
            "Slim proof written to {} ({} bytes, down from {} bytes — {:.0}% reduction)",
            args.out.display(),
            slim_size,
            full_size,
            100.0 * (1.0 - slim_size as f64 / full_size as f64),
        );
    } else {
        // Default: sumcheck compression (no ceremony, transparent, O(log N)).
        run_compress_sumcheck_opt(&args.circuit, &args.steps, &args.out, opts)?;
    }
    Ok(())
}
