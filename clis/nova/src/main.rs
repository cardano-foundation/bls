//! CLI for Nova IVC folding over BLS12-381
//!
//! This crate provides a command-line interface for the Nova step-chain
//! flow (Implementation 8): a long computation is decomposed into `N`
//! identical step circuits, each proving `state_{i+1} = f(step_i, state_i)`,
//! and every step is proven as a standalone Groth16 proof bound by a
//! BLAKE2b512 transcript.
//!
//! The CLI covers the step-chain lifecycle:
//!   1. `params` — inspect a step circuit and validate the IVC invariant
//!   2. `ceremony` — single-party trusted setup for a step circuit
//!   3. `fold` — fold step witnesses into an IVC bundle + transcript
//!   4. `compress` — Groth16-compress a NIFS bundle into one proof
//!   5. `verify` — verify a folded IVC bundle (pairings + chain + transcript)
//!
//! The core IVC logic lives in the `nova-prover` crate; this crate only
//! adds the command-line interface on top of it.

use clap::{Parser, Subcommand};
use std::error::Error;

mod cmd;

/// CLI commands available
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Inspect a step circuit and emit a JSON descriptor
    ///
    /// Loads the step circuit from a `.r1cs` file, validates that it
    /// satisfies the IVC invariant (`n_pub_in == n_pub_out`), and prints
    /// or writes a JSON descriptor containing the circuit's wire and
    /// constraint counts.
    ///
    /// Example:
    ///
    ///   $ nova params --circuit step_circuit.r1cs
    Params(cmd::params::Args),

    /// Run a single-party ceremony for a step circuit
    ///
    /// Loads the step circuit from a `.r1cs` file, generates random toxic
    /// waste, and produces a per-step proving key (`.pk`) and verifying
    /// key (`.vk`) in binary format.
    ///
    /// This is the **insecure, dev-only** path — use `phase2` for
    /// production multi-party ceremonies.  The resulting `.pk` contains
    /// only curve points (no scalars), so the prover uses pure MSM.
    ///
    /// Use `--h-scalar` for h-query scalar compression (Implementation 7)
    /// to reduce proving key size.
    ///
    /// Example:
    ///
    ///   $ nova ceremony --circuit step_circuit.r1cs --proving-key step.pk --verifying-key step.vk
    Ceremony(cmd::ceremony::Args),

    /// Fold step witnesses into an IVC bundle
    ///
    /// Loads the step circuit, the per-step proving key, and a directory
    /// of witness files (`step_0000.wtns`, `step_0001.wtns`, …), then
    /// produces a Groth16 proof for each step and binds them together
    /// with a BLAKE2b transcript.
    ///
    /// With `--nifs` (Implementation 9) no proving key is needed: the step
    /// instances are folded into a single Relaxed-R1CS instance instead of
    /// producing one Groth16 proof per step.
    ///
    /// The output bundle (`.ivc.json`) contains all step proofs, the
    /// initial state, and the final transcript hash.  It is consumed by
    /// the `verify` subcommand.
    ///
    /// Example:
    ///
    ///   $ nova fold --circuit step_circuit.r1cs --proving-key step.pk --steps ./step_witnesses/ --out bundle.ivc.json
    ///   $ nova fold --nifs --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.json
    ///   $ nova fold --nifs --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.json --compression-r1cs compression.r1cs
    Fold(cmd::fold::Args),

    /// Compress a NIFS bundle into a single Groth16 proof (Implementation 9)
    ///
    /// Re-folds the step witnesses deterministically, builds the compression
    /// circuit (relaxed-equation check) and proves it with the compression
    /// proving key — producing one O(1) proof instead of one proof per step.
    ///
    /// The proving key comes from:
    ///
    ///   $ trusted-setup ceremony-dev --sparse --circuit compression.r1cs --proving-key compression.pk --verifying-key compression.vk
    ///
    /// The result is consumed by `nova verify` on the NIFS bundle.
    ///
    /// Example:
    ///
    ///   $ nova compress --circuit step_circuit.r1cs --steps ./step_witnesses/ --proving-key compression.pk --out compression.proof.json
    Compress(cmd::compress::Args),

    /// Verify a folded IVC bundle
    ///
    /// Loads an IVC bundle (`.ivc.json`), the step verifying key, and
    /// checks:
    ///   1. Each step's Groth16 pairing verification passes
    ///   2. The state chain is consistent (step[i].state_out == step[i+1].state_in)
    ///   3. The BLAKE2b transcript hashes match at every step
    ///
    /// For a NIFS bundle (from `fold --nifs`) pass the compression proof and
    /// verifying key instead of the step verifying key:
    ///
    ///   $ nova verify --ivc bundle.ivc.json --compression-proof compression.proof.json --compression-vk compression.vk
    ///
    /// Example:
    ///
    ///   $ nova verify --ivc bundle.ivc.json --verifying-key step.vk
    Verify(cmd::verify::Args),
}

#[derive(Parser)]
#[clap(bin_name = "nova")]
#[clap(author = "HAL Team <hal@cardanofoundation.org>")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "Nova IVC folding CLI for BLS12-381",
       long_about = "A command-line interface for the Nova step-chain IVC flow on BLS12-381.\n\n\
A long computation is decomposed into N identical step circuits and each step is proven\n\
either as a standalone Groth16 proof bound together by a BLAKE2b512 transcript\n\
(Implementation 8: params, ceremony, fold, verify) or folded into one Relaxed-R1CS\n\
instance with a NIFS and compressed into a single Groth16 proof\n\
(Implementation 9: fold --nifs, compress, verify --compression-proof).\n\n\
The core IVC logic lives in the `nova-prover` crate; the Groth16 proof-system core lives\n\
in `groth16-prover` / `trusted-setup`. Step proofs use arkworks' canonical serialization\n\
and are directly consumable by on-chain Aiken verifiers.")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    match args.command {
        Command::Params(args) => cmd::params::run(args),
        Command::Ceremony(args) => cmd::ceremony::run(args),
        Command::Fold(args) => cmd::fold::run(args),
        Command::Compress(args) => cmd::compress::run(args),
        Command::Verify(args) => cmd::verify::run(args),
    }
}
