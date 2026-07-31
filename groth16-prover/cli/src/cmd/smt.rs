//! Sparse Merkle Tree operations for BLS12-381.
//!
//! Provides insert-only SMT commands backed by MiMC(x^7) hashing.
//!
//! Subcommands:
//!   insert    — insert items into the tree and print the new digest
//!   digest    — print the current digest of a persisted tree
//!   path      — print the Merkle path for a given leaf
//!   verify    — verify a Merkle path hashes back to the stored digest
//!   export    — export witness input JSON for the Privacy circuit
//!
//! Example:
//!
//!   $ groth16-prover smt insert --depth 2 --items "1 100,2 200" --state smt.json
//!   $ groth16-prover smt path --state smt.json --leaf <commitment>
//!   $ groth16-prover smt verify --state smt.json --leaf <commitment>
//!   $ groth16-prover smt export --state smt.json --nullifier 1 --out input.json

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
    /// Verify a Merkle path for a leaf
    Verify(VerifyArgs),
    /// Export witness input JSON for the Privacy circuit
    Export(ExportArgs),
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
    #[arg(long, value_name = "ITEMS", conflicts_with = "transcript")]
    items: Option<String>,

    /// Path to a transcript file (one item per line) for bulk loading.
    /// Each line is either a single commitment or "nullifier nonce".
    #[arg(long, value_name = "FILE", conflicts_with = "items")]
    transcript: Option<PathBuf>,

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

/// Arguments for `smt verify`
#[derive(Debug, Parser)]
pub struct VerifyArgs {
    /// Path to the persisted tree state (JSON)
    #[arg(long, value_name = "FILE", default_value = "smt.json")]
    state: PathBuf,

    /// Leaf value to verify (string field element)
    #[arg(long, value_name = "VALUE")]
    leaf: String,
}

/// Arguments for `smt export`
#[derive(Debug, Parser)]
pub struct ExportArgs {
    /// Path to the persisted tree state (JSON)
    #[arg(long, value_name = "FILE", default_value = "smt.json")]
    state: PathBuf,

    /// Target nullifier to prove membership for
    #[arg(long, value_name = "VALUE")]
    nullifier: String,

    /// Output path for the JSON witness input
    #[arg(long, value_name = "FILE", default_value = "input.json")]
    out: PathBuf,
}

/// Run the SMT command
pub fn run(cmd: SmtCommand) -> Result<(), Box<dyn Error>> {
    match cmd {
        SmtCommand::Insert(cmd_args) => run_insert(cmd_args),
        SmtCommand::Digest(cmd_args) => run_digest(cmd_args),
        SmtCommand::Path(cmd_args) => run_path(cmd_args),
        SmtCommand::Verify(cmd_args) => run_verify(cmd_args),
        SmtCommand::Export(cmd_args) => run_export(cmd_args),
    }
}

fn run_insert(args: InsertArgs) -> Result<(), Box<dyn Error>> {
    let mut tree = SparseMerkleTree::new(args.depth);

    // Collect items from --items or --transcript
    let item_strings: Vec<String>;

    if let Some(transcript_path) = &args.transcript {
        let text = fs::read_to_string(transcript_path)
            .map_err(|e| format!("failed to read transcript: {e}"))?;
        item_strings = text.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    } else if let Some(items) = &args.items {
        item_strings = items.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    } else {
        return Err("either --items or --transcript is required".into());
    }

    // Parse and insert items
    for item_str in &item_strings {
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

    // Persist state (include transcript for rebuild)
    let state = SmtState {
        depth: args.depth,
        digest: tree.digest().to_string(),
        items: item_strings.clone(),
    };
    let json = serde_json::to_string_pretty(&state)
        .map_err(|e| format!("failed to serialize state: {e}"))?;
    fs::write(&args.state, json)
        .map_err(|e| format!("failed to write state: {e}"))?;

    eprintln!("Inserted {} item(s) into SMT (depth {})", item_strings.len(), args.depth);
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
    let leaf = Fr::from_str(&args.leaf)
        .map_err(|_| format!("invalid leaf value: {}", args.leaf))?;

    // Rebuild tree from transcript
    let mut tree = SparseMerkleTree::new(state.depth);
    for item_str in &state.items {
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
                tree.insert(mimc2(nf, nonce));
            }
            n => return Err(format!("expected 1 or 2 values, got {}: {}", n, item_str).into()),
        }
    }

    let Some(path) = tree.path(leaf) else {
        println!("Leaf {} not found in tree", leaf);
        return Ok(());
    };
    println!("digest: {}", tree.digest());
    for (i, (sibling, direction)) in path.iter().enumerate() {
        println!("  level {}: sibling={}  direction={}",
            i, sibling, if *direction { "right (leaf is left)" } else { "left (leaf is right)" });
    }

    Ok(())
}

fn rebuild_tree(state: &SmtState) -> Result<SparseMerkleTree, Box<dyn Error>> {
    let mut tree = SparseMerkleTree::new(state.depth);
    for item_str in &state.items {
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
                tree.insert(mimc2(nf, nonce));
            }
            n => return Err(format!("expected 1 or 2 values, got {}: {}", n, item_str).into()),
        }
    }
    Ok(tree)
}

fn run_verify(args: VerifyArgs) -> Result<(), Box<dyn Error>> {
    let state: SmtState = load_state(&args.state)?;
    let leaf = Fr::from_str(&args.leaf)
        .map_err(|_| format!("invalid leaf value: {}", args.leaf))?;

    let tree = rebuild_tree(&state)?;
    let Some(path) = tree.path(leaf) else {
        println!("❌ INVALID — leaf {} not found in tree", leaf);
        println!("  digest: {}", tree.digest());
        return Ok(());
    };

    // Recompute root from path
    let mut current = leaf;
    for (sibling, direction) in &path {
        current = if *direction {
            // leaf was on the left, sibling on the right
            mimc2(current, *sibling)
        } else {
            // leaf was on the right, sibling on the left
            mimc2(*sibling, current)
        };
    }

    let expected = tree.digest();
    if current == expected {
        println!("✅ VALID — path hashes to stored digest");
        println!("  digest: {}", expected);
    } else {
        println!("❌ INVALID — recomputed root does not match stored digest");
        println!("  expected: {}", expected);
        println!("  got:      {}", current);
    }

    Ok(())
}

fn run_export(args: ExportArgs) -> Result<(), Box<dyn Error>> {
    use groth16_prover::privacy_inputs::{compute_spend_inputs, parse_transcript_lines};

    let state: SmtState = load_state(&args.state)?;

    // Convert items to transcript lines
    let lines: Vec<String> = state.items.iter().map(|s| s.to_string()).collect();
    let transcript = parse_transcript_lines(&lines)
        .map_err(|e| format!("failed to parse transcript: {e}"))?;

    let inputs = compute_spend_inputs(state.depth, &transcript, &args.nullifier)
        .map_err(|e| format!("failed to compute inputs: {e}"))?;

    let mut json_map = serde_json::Map::new();
    for (key, value) in inputs.to_json_map() {
        json_map.insert(key, serde_json::Value::String(value));
    }
    let json = serde_json::to_string_pretty(&json_map)
        .map_err(|e| format!("failed to serialize JSON: {e}"))?;

    fs::write(&args.out, json)
        .map_err(|e| format!("failed to write output: {e}"))?;

    eprintln!("Witness input written to {}", args.out.display());
    eprintln!("  digest:      {}", inputs.digest);
    eprintln!("  nullifier:   {}", inputs.nullifier);
    eprintln!("  nonce:       {}", inputs.nonce);
    eprintln!("  siblings:    {}", inputs.siblings.len());

    Ok(())
}

fn load_state(path: &PathBuf) -> Result<SmtState, Box<dyn Error>> {
    let text = fs::read_to_string(path)
        .map_err(|e| format!("failed to read state file: {e}"))?;
    let state: SmtState = serde_json::from_str(&text)
        .map_err(|e| format!("failed to parse state: {e}"))?;
    Ok(state)
}

/// Persisted SMT state.
///
/// Stores the transcript (list of inserted items) so the tree can be
/// rebuilt on demand for path computation, verification, and export.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SmtState {
    depth: usize,
    digest: String,
    /// Raw item strings as provided to `smt insert`.
    /// Each entry is either a single commitment or "nullifier nonce".
    #[serde(default)]
    items: Vec<String>,
}
