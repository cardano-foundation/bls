//! Sparse Merkle Tree operations for BLS12-381.
//!
//! Provides insert-only SMT commands backed by MiMC(x^7) hashing.
//!
//! Subcommands:
//!   insert  — insert items into the tree and print the new digest
//!   digest  — print the current digest of a persisted tree
//!   path    — print the Merkle path for a given leaf
//!
//! Example:
//!
//!   $ groth16-prover smt insert --depth 2 --items "1 100,2 200" --state smt.json
//!   $ groth16-prover smt path --state smt.json --leaf <commitment>

use clap::{Parser, Subcommand};
use groth16_prover::mimc::mimc2;
use groth16_prover::sparse_merkle_tree::SparseMerkleTree;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use ark_bls12_381::Fr;

/// SMT subcommands
#[derive(Debug, Subcommand)]
pub enum SmtCommand {
    /// Insert items into the tree
    Insert(InsertArgs),
    /// Print the current tree digest
    Digest(DigestArgs),
    /// Print the Merkle path for a leaf
    Path(PathArgs),
}

/// Arguments for `smt insert`
#[derive(Debug, Parser)]
pub struct InsertArgs {
    /// Merkle tree depth
    #[arg(long, value_name = "N")]
    depth: usize,

    /// Items to insert. Comma-separated list of:
    /// - single value (raw commitment), or
    /// - two space-separated values: "nullifier nonce"
    #[arg(long, value_name = "ITEMS")]
    items: String,

    /// Path to persist / load the tree state (JSON)
    #[arg(long, value_name = "FILE", default_value = "smt.json")]
    state: PathBuf,
}

/// Arguments for `smt digest`
#[derive(Debug, Parser)]
pub struct DigestArgs {
    /// Path to the persisted tree state (JSON)
    #[arg(long, value_name = "FILE", default_value = "smt.json")]
    state: PathBuf,
}

/// Arguments for `smt path`
#[derive(Debug, Parser)]
pub struct PathArgs {
    /// Path to the persisted tree state (JSON)
    #[arg(long, value_name = "FILE", default_value = "smt.json")]
    state: PathBuf,

    /// Leaf value to compute the path for (string field element)
    #[arg(long, value_name = "VALUE")]
    leaf: String,
}

/// Run the SMT command
pub fn run(cmd: SmtCommand) -> Result<(), Box<dyn Error>> {
    match cmd {
        SmtCommand::Insert(cmd_args) => run_insert(cmd_args),
        SmtCommand::Digest(cmd_args) => run_digest(cmd_args),
        SmtCommand::Path(cmd_args) => run_path(cmd_args),
    }
}

fn run_insert(args: InsertArgs) -> Result<(), Box<dyn Error>> {
    let mut tree = SparseMerkleTree::new(args.depth);

    // Parse and insert items
    for item_str in args.items.split(',') {
        let item_str = item_str.trim();
        if item_str.is_empty() {
            continue;
        }
        let parts: Vec<&str> = item_str.split_whitespace().collect();
        match parts.len() {
            1 => {
                let val = Fr::from_str(parts[0])
                    .map_err(|_| format!("invalid field element: {}", parts[0]))?;
                tree.insert(val);
            }
            2 => {
                let nf = Fr::from_str(parts[0])
                    .map_err(|_| format!("invalid nullifier: {}", parts[0]))?;
                let nonce = Fr::from_str(parts[1])
                    .map_err(|_| format!("invalid nonce: {}", parts[1]))?;
                let commitment = mimc2(nf, nonce);
                tree.insert(commitment);
            }
            n => return Err(format!("expected 1 or 2 values, got {}: {}", n, item_str).into()),
        }
    }

    // Persist state
    let state = SmtState {
        depth: args.depth,
        digest: tree.digest().to_string(),
    };
    let json = serde_json::to_string_pretty(&state)
        .map_err(|e| format!("failed to serialize state: {e}"))?;
    fs::write(&args.state, json)
        .map_err(|e| format!("failed to write state: {e}"))?;

    eprintln!("Inserted items into SMT (depth {})", args.depth);
    eprintln!("  digest: {}", state.digest);
    eprintln!("  state saved to {}", args.state.display());

    Ok(())
}

fn run_digest(args: DigestArgs) -> Result<(), Box<dyn Error>> {
    let state: SmtState = load_state(&args.state)?;
    println!("{}", state.digest);
    Ok(())
}

fn run_path(args: PathArgs) -> Result<(), Box<dyn Error>> {
    let state: SmtState = load_state(&args.state)?;
    let _leaf = Fr::from_str(&args.leaf)
        .map_err(|_| format!("invalid leaf value: {}", args.leaf))?;

    // Note: path computation requires rebuilding the tree from state.
    // For a full implementation we'd persist the full tree nodes.
    // Here we print a helpful message about the limitation.
    eprintln!("SMT path for leaf {}", args.leaf);
    eprintln!("  (Full path computation requires tree rebuild from transcript.");
    eprintln!("   Use `compute-inputs` for end-to-end witness generation.)");
    println!("digest: {}", state.digest);

    Ok(())
}

fn load_state(path: &PathBuf) -> Result<SmtState, Box<dyn Error>> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("failed to read state file: {e}"))?;
    let state: SmtState = serde_json::from_str(&text)
        .map_err(|e| format!("failed to parse state: {e}"))?;
    Ok(state)
}

/// Persisted SMT state (minimal — just digest for now)
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SmtState {
    depth: usize,
    digest: String,
}
