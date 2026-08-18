//! CLI for Lattice-based IVC folding (Lova prover)
//!
//! This crate provides a command-line interface for the Lova folding scheme,
//! a post-quantum IVC prover whose security relies on the unstructured SIS
//! assumption.
//!
//! The CLI covers the Lova folding lifecycle:
//!   1. `fold` — fold step witnesses into a relaxed instance
//!   2. `verify` — verify a folded instance
//!   3. `params` — display Lova parameters
//!
//! Usage: `lattice --lova <SUBCOMMAND>`
//!
//! The core folding logic lives in the `lattice-prover` crate; this crate only
//! adds the command-line interface on top of it.

use clap::{Parser, Subcommand};
use std::error::Error;

mod cmd;

/// CLI commands available
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Fold step witnesses into a relaxed instance (Lova folding)
    ///
    /// Runs the Lova decompose-and-fold protocol for the given number of
    /// steps, generating random short witnesses and folding them.
    ///
    /// Example:
    ///
    ///   $ lattice --lova fold --steps 32 --m 256 --n 128 --out folded.json
    Fold(cmd::fold::Args),

    /// Verify a folded Lova instance
    ///
    /// Checks that the folded instance satisfies norm bounds and commitment
    /// consistency.
    ///
    /// Example:
    ///
    ///   $ lattice --lova verify --state folded.json
    Verify(cmd::verify::Args),

    /// Display Lova parameters for a given configuration
    ///
    /// Example:
    ///
    ///   $ lattice --lova params --m 256 --n 128 --rounds 32
    Params(cmd::params::Args),
}

#[derive(Parser)]
#[clap(bin_name = "lattice")]
#[clap(author = "HAL Team <hal@cardanofoundation.org>")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(
    about = "Lattice-based IVC folding CLI (Lova prover)",
    long_about = "A command-line interface for the Lova post-quantum IVC folding scheme.\n\n\
Lova is the first folding scheme whose security relies on the unstructured SIS\n\
assumption (Fenzi, Knabenhans, Nguyen, Pham — ASIACRYPT 2024). This CLI provides\n\
end-to-end folding and verification.\n\n\
The core folding logic lives in the `lattice-prover` crate; this crate only\n\
adds the command-line interface on top of it."
)]
pub struct Cli {
    /// Use the Lova post-quantum folding scheme (required)
    #[arg(long)]
    pub lova: bool,

    #[command(subcommand)]
    pub command: Command,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    if !args.lova {
        eprintln!("Error: --lova flag is required. Usage: lattice --lova <SUBCOMMAND>");
        std::process::exit(1);
    }

    match args.command {
        Command::Fold(args) => cmd::fold::run(args),
        Command::Verify(args) => cmd::verify::run(args),
        Command::Params(args) => cmd::params::run(args),
    }
}
