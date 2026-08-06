//! `trusted-setup` CLI — Groth16 trusted-setup ceremonies over BLS12-381.
//!
//! This CLI covers the trusted-setup lifecycle for Groth16 circuits:
//!   1. Single-party dev ceremonies (`ceremony-dev`, or the deprecated
//!      `ceremony`) producing `.pk` / `.vk`
//!   2. Production multi-party Phase-2 MPC ceremonies (`phase2`) consuming a
//!      Phase-1 `.ptau` SRS and producing `.zkey` accumulators
//!
//! The proof lifecycle (`prove`, `verify`, `export-vk`, `nova`) lives in the
//! `groth16-prover` CLI; both share the `trusted_setup` library crate.
//!
//! All outputs use arkworks' canonical serialization so they are directly
//! consumable by the `groth16-prover` CLI and on-chain Aiken verifiers.

use clap::{Parser, Subcommand};
use std::error::Error;

/// CLI commands available
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Run a legacy single-party trusted-setup ceremony for a circuit
    ///
    /// Loads a circuit from `.r1cs`, generates random toxic waste,
    /// and produces a proving key + verification key.
    ///
    /// ⚠️ **Deprecated.** This command produces a legacy `ProvingKey` that
    /// contains scalar toxic waste, making it unsuitable for production use.
    /// Use `ceremony-dev` (for dev/testing) or `phase2` (for production) instead.
    ///
    /// Example:
    ///
    ///   $ trusted-setup ceremony --circuit circuit.r1cs --proving-key circuit.pk --verifying-key circuit.vk
    Ceremony(trusted_setup::cmd::ceremony::Args),

    /// Run a single-party dev ceremony that outputs a FullProvingKey (group elements only)
    ///
    /// This is the **insecure, dev-only** path.  It produces the same `.pk`
    /// format as a production MPC ceremony, but with locally-generated
    /// randomness.  Use this for testing, CI, and benchmarking.
    ///
    /// The resulting `.pk` contains only curve points (no scalars), so the
    /// prover uses pure multi-scalar multiplication (MSM) instead of
    /// re-evaluating polynomials from raw scalars on every proof.
    ///
    /// Use `--sparse` for large circuits (Implementation 6) to avoid dense
    /// matrix allocation, and `--h-scalar` for h-query scalar compression
    /// (Implementation 7) to reduce proving key size.
    ///
    /// Examples:
    ///
    ///   $ trusted-setup ceremony-dev --circuit circuit.r1cs --proving-key circuit.pk --verifying-key circuit.vk
    ///
    ///   $ trusted-setup ceremony-dev --circuit circuit.r1cs --proving-key circuit.pk --verifying-key circuit.vk --sparse
    ///
    ///   $ trusted-setup ceremony-dev --circuit circuit.r1cs --proving-key circuit.pk --verifying-key circuit.vk --h-scalar
    CeremonyDev(trusted_setup::cmd::ceremony_dev::Args),

    /// Run a Phase-2 multi-party ceremony for a circuit
    ///
    /// Consumes a Phase-1 SRS (`.ptau`) and a circuit (`.r1cs`) to produce
    /// a circuit-specific proving key via a sequential MPC protocol.
    ///
    /// Each participant contributes randomness locally; the coordinator is
    /// just a passive file host. Even if N-1 participants collude, the
    /// ceremony remains secure as long as at least one participant
    /// honestly discards their contribution.
    ///
    /// Subcommands:
    ///   new        — create initial accumulator from SRS + circuit
    ///   contribute — add your randomness contribution
    ///   verify     — check all contributions are valid
    ///   finalize   — convert accumulator to `.pk` / `.vk`
    ///
    /// Example workflow:
    ///
    ///   $ trusted-setup phase2 new --circuit circuit.r1cs --srs universal.ptau --zkey circuit_0000.zkey
    ///   $ trusted-setup phase2 contribute --zkey-in circuit_0000.zkey --zkey-out circuit_0001.zkey --name "Alice"
    ///   $ trusted-setup phase2 verify --zkey circuit_0001.zkey
    ///   $ trusted-setup phase2 finalize --zkey circuit_final.zkey --proving-key circuit.pk --verifying-key circuit.vk
    #[command(subcommand)]
    Phase2(trusted_setup::cmd::phase2::Phase2Command),
}

#[derive(Debug, Parser)]
#[clap(name = "trusted-setup-cli")]
#[clap(bin_name = "trusted-setup")]
#[clap(author = "HAL Team <hal@cardanofoundation.org>")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "Groth16 trusted-setup CLI for BLS12-381",
       long_about = "A command-line interface for Groth16 trusted-setup ceremonies on BLS12-381.\n\n\
This CLI covers single-party dev ceremonies (ceremony-dev) and production multi-party Phase-2 MPC \nceremonies (phase2), producing the .pk / .vk / .zkey files consumed by the groth16-prover CLI.\n\n\
All outputs use arkworks' canonical serialization so they are directly consumable by on-chain Aiken verifiers.")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    match args.command {
        Command::Ceremony(args) => trusted_setup::cmd::ceremony::run(args),
        Command::CeremonyDev(args) => trusted_setup::cmd::ceremony_dev::run(args),
        Command::Phase2(cmd) => trusted_setup::cmd::phase2::run(cmd),
    }
}
