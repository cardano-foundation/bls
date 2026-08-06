//! CLI for Groth16 proof generation over BLS12-381
//!
//! This crate provides a command-line interface for generating Groth16
//! zero-knowledge proofs from Circom artifacts (`.r1cs` + `.wtns`).
//!
//! The CLI covers the proof lifecycle:
//!   1. Proof generation from circuit + witness files
//!   2. Proof verification against a verifying key
//!   3. Exporting verifying keys to Aiken source code
//!   4. Nova IVC folding for batching multiple step proofs
//!
//! Trusted-setup ceremonies (single-party dev or production MPC) live in the
//! standalone `trusted-setup` CLI (`clis/trusted-setup`). Sparse Merkle tree
//! operations and privacy-circuit witness-input generation live in the
//! standalone `smt` CLI (`clis/smt`).
//!
//! All outputs use arkworks' canonical compressed serialization so they
//! are directly consumable by on-chain Aiken verifiers.

use clap::{Parser, Subcommand};
use std::error::Error;

mod cmd;
mod util;

/// CLI commands available
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Generate a Groth16 proof from Circom artifacts
    ///
    /// Loads a circuit from `.r1cs` and a witness from `.wtns`,
    /// then produces a proof using FFT QAP engine + Pippenger MSM.
    ///
    /// If a `--proving-key` is provided, the proof is generated with
    /// the random toxic waste from the ceremony step.  Otherwise the
    /// deterministic test values are used (dev only).
    ///
    /// Use `--sparse` for large circuits (Implementation 6) to avoid
    /// dense matrix allocation.
    ///
    /// The `--engine` and `--prover` flags let you choose the QAP
    /// construction and MSM strategy.  See the examples below for all
    /// combinations.
    ///
    /// Examples:
    ///
    ///   $ groth16-prover prove --circuit circuit.r1cs --witness witness.wtns --proving-key circuit.pk --out proof.bin
    ///
    ///   $ groth16-prover prove --circuit circuit.r1cs --witness witness.wtns --sparse --out proof.bin
    ///
    ///   $ groth16-prover prove --circuit circuit.r1cs --witness witness.wtns --engine fft --prover pippenger --proving-key circuit.pk --out proof.bin
    ///
    ///   $ groth16-prover prove --circuit circuit.r1cs --witness witness.wtns --engine dense --prover naive --proving-key circuit.pk --out proof.bin
    Prove(cmd::prove::Args),

    /// Verify a Groth16 proof against its public input
    ///
    /// Loads a proof file (192 bytes) and a public-input file (48 bytes),
    /// then checks the Groth16 pairing equation:
    ///
    ///   e(A, B) == e(alpha·G1, beta·G2) · e(C, delta·G2) · e(V, gamma·G2)
    ///
    /// where `e` is the optimal Ate pairing on BLS12-381.
    ///
    /// If a `--verifying-key` is provided, the verification uses the
    /// CRS points from the ceremony step.  Otherwise the deterministic
    /// test values are used (dev only).
    ///
    /// Examples:
    ///
    ///   $ groth16-prover verify --proof proof.bin --public proof.pub --verifying-key circuit.vk
    ///
    ///   $ groth16-prover verify --proof proof.bin --public proof.pub
    Verify(cmd::verify::Args),

    /// Export a binary verifying key to Aiken source code
    ///
    /// Reads a `.vk` file produced by the ceremony step and emits a
    /// Groth16 `VerificationKey` record with hex-encoded compressed points,
    /// ready to paste into an Aiken validator or library.
    ///
    /// The output contains the `alpha_g1`, `beta_g2`, `gamma_g2`, `delta_g2`,
    /// `ic` list, and `n_public` fields.
    ///
    /// Example:
    ///
    ///   $ groth16-prover export-vk --verifying-key circuit.vk --out circuit_vk.ak
    ExportVk(cmd::export_vk::Args),

    /// Nova IVC folding + compression flow (Implementation 8)
    ///
    /// Splits a long computation into N identical step circuits and folds
    /// their Groth16 proofs into a single verifiable bundle.  Every step
    /// proof is individually verifiable and the state chain across steps
    /// is bound by a BLAKE2b transcript.
    ///
    /// The step circuits must satisfy the invariant that the number of
    /// public inputs equals the number of public outputs (n_pub_in == n_pub_out),
    /// so the public-input block of step i+1 equals the public-output block
    /// of step i.  Public inputs ARE the IVC state.
    ///
    /// Subcommands:
    ///   params    — inspect a step circuit and emit a JSON descriptor
    ///   ceremony  — single-party ceremony for a step circuit (per-step Groth16 keys)
    ///   fold      — fold step witnesses into an IVC bundle
    ///   verify    — verify a folded IVC bundle (pairings + chain + transcript)
    ///
    /// Example workflow:
    ///
    ///   $ groth16-prover nova params --circuit step_circuit.r1cs
    ///   $ groth16-prover nova ceremony --circuit step_circuit.r1cs --proving-key step.pk --verifying-key step.vk
    ///   $ groth16-prover nova fold --circuit step_circuit.r1cs --proving-key step.pk --steps ./step_witnesses/ --out bundle.ivc.json
    ///   $ groth16-prover nova verify --ivc bundle.ivc.json --verifying-key step.vk
    #[command(subcommand)]
    Nova(cmd::nova::NovaCommand),
}

#[derive(Debug, Parser)]
#[clap(name = "groth16-prover-cli")]
#[clap(bin_name = "groth16-prover")]
#[clap(author = "HAL Team <hal@cardanofoundation.org>")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "Groth16 prover CLI for BLS12-381",
       long_about = "A command-line interface for Groth16 zero-knowledge proof generation and verification on BLS12-381.\n\n\
This CLI covers proof generation, verification, verifying-key export, and Nova IVC folding. Trusted-setup \nceremonies live in the `trusted-setup` CLI; SMT and privacy witness-input generation live in the `smt` CLI.\n\n\
All outputs use arkworks' canonical compressed serialization so they are directly consumable by on-chain Aiken verifiers.")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    match args.command {
        Command::ExportVk(args) => cmd::export_vk::run(args),
        Command::Prove(args) => cmd::prove::run(args),
        Command::Verify(args) => cmd::verify::run(args),
        Command::Nova(cmd) => cmd::nova::run(cmd),
    }
}
