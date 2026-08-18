//! `verify` subcommand — verify a folded Lova instance.

use clap::Parser;
use lattice_prover::commitment::AjtaiParams;
use lattice_prover::fold;
use lattice_prover::params::LovaParams;
use std::error::Error;

/// Arguments for the `verify` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Number of steps that were folded
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
}

/// Run the `verify` subcommand.
///
/// Since the folded state is ephemeral (not serialized to JSON yet),
/// this command runs a fresh fold + verify cycle and reports verification.
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

    let result = lattice::run_fold_lova(&params, args.steps)?;

    // Verify the final state
    let ajtai = AjtaiParams::from_seed(params.m, params.n, 0);
    let t_start = std::time::Instant::now();
    fold::verify_folded_instance(
        &params,
        &ajtai,
        &result.final_instance,
        &result.final_witness,
        &result.final_error,
    )?;
    let verify_ms = t_start.elapsed().as_secs_f64() * 1000.0;

    eprintln!("Verification OK");
    eprintln!("  steps: {}", result.steps);
    eprintln!("  fold time: {:.2} ms", result.total_fold_ms);
    eprintln!("  verify time: {:.2} ms", verify_ms);
    eprintln!(
        "  proof size: {} bytes ({:.1} KiB)",
        result.proof_size_bytes,
        result.proof_size_bytes as f64 / 1024.0
    );

    Ok(())
}
