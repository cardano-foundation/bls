//! `verify` subcommand — verify a folded IVC bundle (or a NIFS bundle +
//! compression proof).

use clap::Parser;
use nova_prover::{run_verify, run_verify_sumcheck};
use std::error::Error;
use std::path::PathBuf;

/// Arguments for the `verify` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the IVC bundle produced by `nova fold`
    #[arg(long, value_name = "FILE")]
    pub ivc: PathBuf,

    /// Path to the step verifying key (from `nova ceremony`).
    /// Not used for NIFS bundles.
    #[arg(long, value_name = "FILE", required_unless_present_all = ["compression_proof", "sumcheck_proof"])]
    pub verifying_key: Option<PathBuf>,

    /// (NIFS bundles, Impl 9) Path to the Groth16 compression proof
    /// from `nova compress`
    #[arg(long, value_name = "FILE", conflicts_with = "sumcheck_proof")]
    pub compression_proof: Option<PathBuf>,

    /// (NIFS bundles, Impl 9) Path to the compression verifying key
    /// (from `trusted-setup ceremony-dev --sparse`)
    #[arg(long, value_name = "FILE", requires = "compression_proof")]
    pub compression_vk: Option<PathBuf>,

    /// (NIFS bundles, Impl 10) Path to the sumcheck compression proof
    /// from `nova compress --sumcheck`
    #[arg(long, value_name = "FILE", conflicts_with = "compression_proof")]
    pub sumcheck_proof: Option<PathBuf>,
}

/// Run the `verify` subcommand.
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    if let Some(ref sc_proof) = args.sumcheck_proof {
        let out = run_verify_sumcheck(&args.ivc, sc_proof)?;
        eprintln!(
            "Verified {} steps: sumcheck compression proof OK, commitments OK, state chain OK",
            out.steps
        );
        eprintln!("Final transcript: {}", out.transcript_final);
        return Ok(());
    }

    let out = run_verify(
        &args.ivc,
        args.verifying_key.as_deref().unwrap_or_else(|| {
            // Unreachable: clap requires verifying_key unless --compression-proof
            // or --sumcheck-proof is present, and run_verify never loads the
            // step VK for NIFS bundles.
            std::path::Path::new("")
        }),
        args.compression_proof.as_deref(),
        args.compression_vk.as_deref(),
    )?;

    eprintln!(
        "Verified {} steps: compression proof OK, commitments OK, state chain OK",
        out.steps
    );
    eprintln!("Final transcript: {}", out.transcript_final);
    Ok(())
}
