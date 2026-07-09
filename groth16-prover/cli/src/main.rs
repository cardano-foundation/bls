//! CLI for Groth16 proof generation over BLS12-381
//!
//! This crate provides a command-line interface for generating Groth16
//! zero-knowledge proofs from Circom artifacts (`.r1cs` + `.wtns`).

use clap::{Parser, Subcommand};
use std::error::Error;

mod cmd;

/// CLI commands available
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a Groth16 proof from Circom artifacts
    ///
    /// Loads a circuit from `.r1cs` and a witness from `.wtns`,
    /// then produces a proof using FFT QAP engine + Pippenger MSM.
    ///
    /// Examples:
    ///
    ///   $ groth16-prover prove --circuit circuit.r1cs --witness witness.wtns --out proof.bin
    ///
    ///   $ groth16-prover prove --circuit circuit.r1cs --witness witness.wtns  # hex to stdout
    Prove(cmd::prove::Args),

    /// Verify a Groth16 proof against its public input
    ///
    /// Loads a proof file (192 bytes) and a public-input file (48 bytes),
    /// then checks the Groth16 pairing equation.
    ///
    /// The verification key is derived from hard-coded toxic-waste
    /// parameters (same as the prover). In production you would load a
    /// verification key generated during the trusted-setup ceremony.
    ///
    /// Examples:
    ///
    ///   $ groth16-prover verify --proof proof.bin --public proof.pub
    Verify(cmd::verify::Args),
}

#[derive(Debug, Parser)]
#[clap(name = "groth16-prover-cli")]
#[clap(bin_name = "groth16-prover")]
#[clap(author = "HAL Team <hal@cardanofoundation.org>")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "Groth16 prover CLI for BLS12-381")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    match args.command {
        Command::Prove(args) => cmd::prove::run(args),
        Command::Verify(args) => cmd::verify::run(args),
    }
}
