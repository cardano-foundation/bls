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
    /// Run a trusted-setup ceremony for a circuit
    ///
    /// Loads a circuit from `.r1cs`, generates random toxic waste,
    /// and produces a proving key + verification key.
    ///
    /// Example:
    ///
    ///   $ groth16-prover ceremony --circuit circuit.r1cs --proving-key circuit.pk --verifying-key circuit.vk
    Ceremony(cmd::ceremony::Args),

    /// Run a single-party dev ceremony that outputs a FullProvingKey (group elements only)
    ///
    /// This is the **insecure, dev-only** path.  It produces the same `.pk`
    /// format as a production MPC ceremony, but with locally-generated
    /// randomness.  Use this for testing, CI, and benchmarking.
    ///
    /// Example:
    ///
    ///   $ groth16-prover ceremony-dev --circuit circuit.r1cs --proving-key circuit.pk --verifying-key circuit.vk
    CeremonyDev(cmd::ceremony_dev::Args),

    /// Generate a Groth16 proof from Circom artifacts
    ///
    /// Loads a circuit from `.r1cs` and a witness from `.wtns`,
    /// then produces a proof using FFT QAP engine + Pippenger MSM.
    ///
    /// If a `--proving-key` is provided, the proof is generated with
    /// the random toxic waste from the ceremony step.  Otherwise the
    /// deterministic test values are used (dev only).
    ///
    /// Examples:
    ///
    ///   $ groth16-prover prove --circuit circuit.r1cs --witness witness.wtns --proving-key circuit.pk --out proof.bin
    ///
    ///   $ groth16-prover prove --circuit circuit.r1cs --witness witness.wtns  # hex to stdout (dev only)
    Prove(cmd::prove::Args),

    /// Verify a Groth16 proof against its public input
    ///
    /// Loads a proof file (192 bytes) and a public-input file (48 bytes),
    /// then checks the Groth16 pairing equation.
    ///
    /// If a `--verifying-key` is provided, the verification uses the
    /// CRS points from the ceremony step.  Otherwise the deterministic
    /// test values are used (dev only).
    ///
    /// Examples:
    ///
    ///   $ groth16-prover verify --proof proof.bin --public proof.pub --verifying-key circuit.vk
    Verify(cmd::verify::Args),

    /// Run a Phase-2 multi-party ceremony for a circuit
    ///
    /// Consumes a Phase-1 SRS (`.ptau`) and a circuit (`.r1cs`) to produce
    /// a circuit-specific proving key via a sequential MPC protocol.
    ///
    /// Subcommands:
    ///   new        — create initial accumulator
    ///   contribute — add your randomness
    ///   verify     — check all contributions
    ///   finalize   — convert to `.pk` / `.vk`
    #[command(subcommand)]
    Phase2(cmd::phase2::Phase2Command),
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
        Command::Ceremony(args) => cmd::ceremony::run(args),
        Command::CeremonyDev(args) => cmd::ceremony_dev::run(args),
        Command::Prove(args) => cmd::prove::run(args),
        Command::Verify(args) => cmd::verify::run(args),
        Command::Phase2(cmd) => cmd::phase2::run(cmd),
    }
}
