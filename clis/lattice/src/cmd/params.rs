//! `params` subcommand — display Lova parameters for a given configuration.

use clap::Parser;
use lattice_prover::params::LovaParams;
use std::error::Error;

/// Arguments for the `params` subcommand
#[derive(Debug, Parser)]
pub struct Args {
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

/// Run the `params` subcommand.
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

    let norm_ok = params.check_norm_constraint();
    let commitment_bytes = 2 * params.m * 8; // com_z + com_e
    let witness_bytes = params.n * 8;
    let proof_size =
        2 * params.m * 8 + params.n * 8 + params.n * 8 + params.decompose_digits * params.n * 8;

    eprintln!("Lova parameters:");
    eprintln!("  m (commitment rows):     {}", params.m);
    eprintln!("  n (witness dimension):   {}", params.n);
    eprintln!("  witness_chunk_size:      {}", params.witness_chunk_size);
    eprintln!("  decompose_base:          {}", params.decompose_base);
    eprintln!("  decompose_digits:        {}", params.decompose_digits);
    eprintln!("  witness_norm_bound:      {}", params.witness_norm_bound);
    eprintln!("  error_norm_bound:        {}", params.error_norm_bound);
    eprintln!("  num_rounds:              {}", params.num_rounds);
    eprintln!(
        "  norm constraint:         {} (2*k*b*sqrt(m) <= beta)",
        if norm_ok { "OK" } else { "VIOLATED" }
    );
    eprintln!(
        "  commitment size:         {} bytes ({:.1} KiB)",
        commitment_bytes,
        commitment_bytes as f64 / 1024.0
    );
    eprintln!(
        "  witness size:            {} bytes ({:.1} KiB)",
        witness_bytes,
        witness_bytes as f64 / 1024.0
    );
    eprintln!(
        "  estimated proof size:    {} bytes ({:.1} KiB)",
        proof_size,
        proof_size as f64 / 1024.0
    );

    Ok(())
}
