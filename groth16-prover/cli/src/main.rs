//! CLI for Groth16 proof generation over BLS12-381
//!
//! This crate provides a command-line interface for generating Groth16
//! zero-knowledge proofs from Circom artifacts (`.r1cs` + `.wtns`).
//!
//! The CLI covers the full proof lifecycle:
//!   1. Trusted-setup ceremonies (dev single-party or production MPC)
//!   2. Proof generation from circuit + witness files
//!   3. Proof verification against a verifying key
//!   4. Exporting verifying keys to Aiken source code
//!   5. Computing witness inputs for shielded-spend circuits
//!   6. Sparse Merkle tree operations for privacy-preserving circuits
//!   7. Nova IVC folding for batching multiple step proofs
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
    ///   $ groth16-prover ceremony --circuit circuit.r1cs --proving-key circuit.pk --verifying-key circuit.vk
    Ceremony(cmd::ceremony::Args),

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
    ///   $ groth16-prover ceremony-dev --circuit circuit.r1cs --proving-key circuit.pk --verifying-key circuit.vk
    ///
    ///   $ groth16-prover ceremony-dev --circuit circuit.r1cs --proving-key circuit.pk --verifying-key circuit.vk --sparse
    ///
    ///   $ groth16-prover ceremony-dev --circuit circuit.r1cs --proving-key circuit.pk --verifying-key circuit.vk --h-scalar
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

    /// Compute witness inputs for the Spend(depth) circuit
    ///
    /// Reads a transcript file (one nullifier-nonce pair per line) and
    /// produces a JSON file with the private Merkle-path data needed by
    /// the Circom witness generator for the Spend(depth) circuit.
    ///
    /// The transcript format: each line contains either one field element
    /// (raw commitment) or two space-separated field elements
    /// (`nullifier nonce`). Empty lines are skipped.
    ///
    /// Example:
    ///
    ///   $ groth16-prover compute-inputs --depth 2 --transcript transcript.txt --nullifier 2 --out input.json
    ComputeInputs(cmd::compute_inputs::Args),

    /// Sparse Merkle Tree operations for BLS12-381
    ///
    /// Provides insert-only SMT commands backed by MiMC(x^7) hashing.
    ///
    /// Subcommands:
    ///   leaf    — compute a MiMC leaf commitment (MultiMiMC7 over 6 limbs)
    ///   insert  — insert items into the tree and persist tree state
    ///   digest  — print the current tree digest (Merkle root)
    ///   path    — print the Merkle path for a given leaf
    ///   verify  — verify a Merkle path hashes back to the stored digest
    ///   export  — export witness input JSON for the Privacy circuit
    ///
    /// Example:
    ///
    ///   $ groth16-prover smt leaf --items "x0,x1,x2,y0,y1,y2"
    ///   $ groth16-prover smt insert --depth 2 --items "1 100,2 200,3 300" --state smt.json
    ///   $ groth16-prover smt digest --state smt.json
    ///   $ groth16-prover smt path --state smt.json --leaf <commitment>
    ///   $ groth16-prover smt verify --state smt.json --leaf <commitment>
    ///   $ groth16-prover smt export --state smt.json --nullifier 1 --out input.json
    #[command(subcommand)]
    Smt(cmd::smt::SmtCommand),

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
    ///   $ groth16-prover phase2 new --circuit circuit.r1cs --srs universal.ptau --zkey circuit_0000.zkey
    ///   $ groth16-prover phase2 contribute --zkey-in circuit_0000.zkey --zkey-out circuit_0001.zkey --name "Alice"
    ///   $ groth16-prover phase2 verify --zkey circuit_0001.zkey
    ///   $ groth16-prover phase2 finalize --zkey circuit_final.zkey --proving-key circuit.pk --verifying-key circuit.vk
    #[command(subcommand)]
    Phase2(cmd::phase2::Phase2Command),

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
       long_about = "A command-line interface for the full Groth16 zero-knowledge proof lifecycle on BLS12-381.\n\n\
This CLI covers everything from trusted-setup ceremonies (both dev and multi-party MPC) through proof \ngeneration and verification, plus auxiliary tools for privacy-preserving circuits: witness-input \ncomputation for shielded spends and sparse Merkle tree operations.\n\n\
All outputs use arkworks' canonical compressed serialization so they are directly consumable by \non-chain Aiken verifiers.")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    match args.command {
        Command::Ceremony(args) => cmd::ceremony::run(args),
        Command::CeremonyDev(args) => cmd::ceremony_dev::run(args),
        Command::ComputeInputs(args) => cmd::compute_inputs::run(args),
        Command::ExportVk(args) => cmd::export_vk::run(args),
        Command::Prove(args) => cmd::prove::run(args),
        Command::Smt(cmd) => cmd::smt::run(cmd),
        Command::Verify(args) => cmd::verify::run(args),
        Command::Phase2(cmd) => cmd::phase2::run(cmd),
        Command::Nova(cmd) => cmd::nova::run(cmd),
    }
}
