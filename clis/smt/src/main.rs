//! CLI for Sparse Merkle Tree operations over BLS12-381.
//!
//! Provides insert-only SMT commands backed by MiMC(x^7) hashing, plus
//! witness-input computation for the privacy-preserving circuits that build
//! on top of the tree: the Spend(depth) circuit (`compute-inputs`) and the
//! CardanoKeyOwnershipSMT circuit (`key`, `cardano-input`).
//!
//! All outputs use arkworks' canonical compressed serialization so they are
//! directly consumable by on-chain Aiken verifiers.

use clap::{Parser, Subcommand};
use std::error::Error;

mod cmd;

/// CLI commands available
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Compute witness inputs for the Spend(depth) circuit
    ///
    /// Reads a transcript file (one nullifier-nonce pair per line) and
    /// produces a JSON file with the private Merkle-path data needed by
    /// the Circom witness generator for the Spend(depth) circuit.
    ///
    /// Example:
    ///
    ///   $ smt compute-inputs --depth 2 --transcript transcript.txt --nullifier 2 --out input.json
    ComputeInputs(cmd::compute_inputs::Args),

    /// Derive CardanoKeyOwnershipSMT witness data from a payment key
    ///
    /// Decompresses the compressed Ed25519 public key `--vk` to extended
    /// coordinates, splits each coordinate into three base-2^85 limbs, and
    /// computes the MiMC leaf commitment over the `x` and `y` limbs — exactly
    /// what the circuit re-derives in-circuit. With `--xsk` (the 32-byte
    /// scalar from the extended signing key) it additionally emits the
    /// little-endian bits of the clamped scalar (`sk`).
    ///
    /// `--json` emits the machine-readable record consumed by `cardano-input`:
    ///
    ///   {"vk", "PointA", "leaf", "A", "sk"}
    ///
    /// Example:
    ///
    ///   $ smt key --vk <pk-hex> --xsk <scalar-hex> --json
    Key(cmd::smt::KeyArgs),

    /// Compute a MiMC leaf commitment (MultiMiMC7 over 6 limbs, k = 0)
    ///
    /// Hashes the six base-2^85 limbs `x0,x1,x2,y0,y1,y2` of a decompressed
    /// Ed25519 public key via `MultiMiMC7(6, 91)` with `k = 0` — exactly the
    /// `leaf` commitment the CardanoKeyOwnershipSMT circuit re-derives
    /// in-circuit from `PointA`. The leaf is what `insert` stores.
    ///
    /// `--items` is a comma-separated list of exactly six field elements in
    /// the order `x0,x1,x2,y0,y1,y2`.
    ///
    /// Example:
    ///
    ///   $ smt leaf --items "x0,x1,x2,y0,y1,y2"
    Leaf(cmd::smt::LeafArgs),

    /// Insert items into the SMT and persist the updated tree state
    ///
    /// Items are specified as a comma-separated list of either:
    ///   - a single field element (raw commitment), or
    ///   - two space-separated field elements (`nullifier nonce`)
    ///
    /// Alternatively, use `--transcript` to load items from a file
    /// (one item per line).  The `--items` and `--transcript` flags
    /// are mutually exclusive.
    ///
    /// The tree state (digest + transcript) is saved to `--state`
    /// so it can be reused by `digest`, `path`, `verify`, and `export`.
    ///
    /// Example:
    ///
    ///   $ smt insert --depth 2 --items "1 100,2 200" --state smt.json
    Insert(cmd::smt::InsertArgs),

    /// Print the current Merkle root (digest) of a persisted tree
    ///
    /// Reads the tree state from `--state` and prints the digest
    /// (a single field element in decimal string form).
    ///
    /// Example:
    ///
    ///   $ smt digest --state smt.json
    Digest(cmd::smt::DigestArgs),

    /// Print the Merkle authentication path for a given leaf
    ///
    /// Rebuilds the tree from the persisted state, computes the path
    /// from the root to the specified leaf, and prints each sibling
    /// together with its direction (left or right).
    ///
    /// With `--json`, emits `{"digest", "siblings", "directions"}`
    /// where both lists are decimal field-element strings (direction
    /// `1` = sibling on the left) for machine consumption.
    ///
    /// Example:
    ///
    ///   $ smt path --state smt.json --leaf <commitment>
    Path(cmd::smt::PathArgs),

    /// Verify that a Merkle path hashes back to the stored digest
    ///
    /// Rebuilds the tree from the persisted state, computes the path
    /// for the given leaf, and checks that re-hashing the path
    /// reproduces the stored digest.
    ///
    /// Example:
    ///
    ///   $ smt verify --state smt.json --leaf <commitment>
    Verify(cmd::smt::VerifyArgs),

    /// Export witness input JSON for the Privacy circuit
    ///
    /// Reads the persisted tree state and produces a JSON file
    /// containing the Merkle-path data needed by the Circom
    /// witness generator for the Spend circuit.
    ///
    /// The output JSON contains: `digest`, `nullifier`, `nonce`,
    /// `siblings` (list of field elements), and `direction` bits.
    ///
    /// Example:
    ///
    ///   $ smt export --state smt.json --nullifier 1 --out input.json
    Export(cmd::smt::ExportArgs),

    /// Assemble the full CardanoKeyOwnershipSMT circuit input
    ///
    /// Combines a persisted tree (`--state`) with a key record produced by
    /// `key --json` (`--key`) into the complete witness input for the
    /// CardanoKeyOwnershipSMT circuit: `A`, `sk`, `PointA`, `smt_root`,
    /// `smt_siblings`, and `smt_directions`.
    ///
    /// The key's MiMC leaf is looked up in the tree by value and its Merkle
    /// path becomes the proof. The key record must contain `sk` (i.e. it must
    /// have been generated with `--xsk`).
    ///
    /// Example:
    ///
    ///   $ smt cardano-input --state smt.json --key key.json --out input.json
    CardanoInput(cmd::smt::CardanoInputArgs),
}

#[derive(Debug, Parser)]
#[clap(name = "smt")]
#[clap(author = "HAL Team <hal@cardanofoundation.org>")]
#[clap(version = env!("CARGO_PKG_VERSION"))]
#[clap(about = "Sparse Merkle Tree CLI for BLS12-381",
       long_about = "A command-line interface for sparse Merkle tree operations on BLS12-381.\n\n\
This CLI builds insert-only SMTs backed by MiMC(x^7) hashing and produces the witness inputs for \
the privacy-preserving circuits that consume them: the Spend(depth) circuit (compute-inputs, \
export) and the CardanoKeyOwnershipSMT circuit (key, cardano-input).")]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    match args.command {
        Command::ComputeInputs(args) => cmd::compute_inputs::run(args),
        Command::Key(args) => cmd::smt::run_key(args),
        Command::Leaf(args) => cmd::smt::run_leaf(args),
        Command::Insert(args) => cmd::smt::run_insert(args),
        Command::Digest(args) => cmd::smt::run_digest(args),
        Command::Path(args) => cmd::smt::run_path(args),
        Command::Verify(args) => cmd::smt::run_verify(args),
        Command::Export(args) => cmd::smt::run_export(args),
        Command::CardanoInput(args) => cmd::smt::run_cardano_input(args),
    }
}
