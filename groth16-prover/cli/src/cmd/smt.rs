//! Sparse Merkle Tree operations for BLS12-381.
//!
//! Provides insert-only SMT commands backed by MiMC(x^7) hashing.
//!
//! Subcommands:
//!   leaf      — compute a MiMC leaf commitment (MultiMiMC7 over 6 limbs)
//!   insert    — insert items into the tree and print the new digest
//!   digest    — print the current digest of a persisted tree
//!   path      — print the Merkle path for a given leaf
//!   verify    — verify a Merkle path hashes back to the stored digest
//!   export    — export witness input JSON for the Privacy circuit
//!
//! Examples:
//!
//!   Compute a MiMC leaf commitment (the CardanoKeyOwnershipSMT leaf, from
//!   the six base-2^85 limbs x0,x1,x2,y0,y1,y2 of the decompressed key):
//!
//!     $ groth16-prover smt leaf --items "x0,x1,x2,y0,y1,y2"
//!     $ groth16-prover smt leaf --items "x0,x1,x2,y0,y1,y2" --json
//!
//!   Insert items into a tree:
//!
//!     $ groth16-prover smt insert --depth 2 --items "1 100,2 200" --state smt.json
//!
//!   Insert a single item at an explicit leaf index (0-padded tree):
//!
//!     $ groth16-prover smt insert --depth 2 --items "42" --index 3 --state smt.json
//!
//!   Insert from a transcript file (one item per line):
//!
//!     $ groth16-prover smt insert --depth 2 --transcript items.txt --state smt.json
//!
//!   Print the current tree digest:
//!
//!     $ groth16-prover smt digest --state smt.json
//!
//!   Print the Merkle path for a leaf (human-readable, or `--json`):
//!
//!     $ groth16-prover smt path --state smt.json --leaf <commitment>
//!     $ groth16-prover smt path --state smt.json --leaf <commitment> --json
//!
//!   Verify a Merkle path:
//!
//!     $ groth16-prover smt verify --state smt.json --leaf <commitment>
//!
//!   Export witness input JSON for the Privacy circuit:
//!
//!     $ groth16-prover smt export --state smt.json --nullifier 1 --out input.json

use clap::{Parser, Subcommand};
use groth16_prover::mimc::{mimc2, mimc_hash};
use groth16_prover::sparse_merkle_tree::SparseMerkleTree;
use std::error::Error;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use ark_bls12_381::Fr;
use ark_ff::Zero;

/// SMT subcommands
#[derive(Debug, Subcommand)]
pub enum SmtCommand {
    /// Compute a MiMC leaf commitment (MultiMiMC7 over 6 limbs, k = 0)
    ///
    /// Hashes the six base-2^85 limbs `x0,x1,x2,y0,y1,y2` of a decompressed
    /// Ed25519 public key via `MultiMiMC7(6, 91)` with `k = 0` — exactly the
    /// `leaf` commitment the CardanoKeyOwnershipSMT circuit re-derives
    /// in-circuit from `PointA`. The leaf is what `smt insert` stores.
    ///
    /// `--items` is a comma-separated list of exactly six field elements in
    /// the order `x0,x1,x2,y0,y1,y2`.
    ///
    /// Example:
    ///
    ///   $ groth16-prover smt leaf --items "x0,x1,x2,y0,y1,y2"
    Leaf(LeafArgs),

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
    ///   $ groth16-prover smt insert --depth 2 --items "1 100,2 200" --state smt.json
    Insert(InsertArgs),

    /// Print the current Merkle root (digest) of a persisted tree
    ///
    /// Reads the tree state from `--state` and prints the digest
    /// (a single field element in decimal string form).
    ///
    /// Example:
    ///
    ///   $ groth16-prover smt digest --state smt.json
    Digest(DigestArgs),

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
    ///   $ groth16-prover smt path --state smt.json --leaf <commitment>
    Path(PathArgs),

    /// Verify that a Merkle path hashes back to the stored digest
    ///
    /// Rebuilds the tree from the persisted state, computes the path
    /// for the given leaf, and checks that re-hashing the path
    /// reproduces the stored digest.
    ///
    /// Example:
    ///
    ///   $ groth16-prover smt verify --state smt.json --leaf <commitment>
    Verify(VerifyArgs),

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
    ///   $ groth16-prover smt export --state smt.json --nullifier 1 --out input.json
    Export(ExportArgs),
}

/// Arguments for `smt leaf`
#[derive(Debug, Parser)]
pub struct LeafArgs {
    /// Six comma-separated base-2^85 limbs of the decompressed point:
    /// `x0,x1,x2,y0,y1,y2` (in that order).
    #[arg(long, value_name = "ITEMS")]
    items: String,

    /// Emit machine-readable JSON (`{"leaf": "..."}`).
    #[arg(long)]
    json: bool,
}

/// Arguments for `smt insert`
#[derive(Debug, Parser)]
pub struct InsertArgs {
    /// Merkle tree depth (number of levels)
    #[arg(long, value_name = "N")]
    depth: usize,

    /// Comma-separated list of items to insert.
    /// Each item is either a single field element (raw commitment)
    /// or two space-separated field elements (`nullifier nonce`).
    /// Mutually exclusive with `--transcript`.
    #[arg(long, value_name = "ITEMS", conflicts_with = "transcript")]
    items: Option<String>,

    /// Path to a transcript file (one item per line) for bulk loading.
    /// Each line is either a single commitment or "nullifier nonce".
    /// Mutually exclusive with `--items`.
    #[arg(long, value_name = "FILE", conflicts_with = "items")]
    transcript: Option<PathBuf>,

    /// Place a single `--items` value at this explicit leaf index instead of
    /// the next open slot (so the rest of the tree stays zero-padded).
    /// Requires exactly one raw commitment (single field element) item and
    /// is mutually exclusive with `--transcript`.
    #[arg(long, value_name = "N", requires = "items", conflicts_with = "transcript")]
    index: Option<usize>,

    /// Path to persist / load the tree state (JSON).
    /// Defaults to `smt.json`.
    #[arg(long, value_name = "FILE", default_value = "smt.json")]
    state: PathBuf,
}

/// Arguments for `smt digest`
#[derive(Debug, Parser)]
pub struct DigestArgs {
    /// Path to the persisted tree state (JSON).
    /// Defaults to `smt.json`.
    #[arg(long, value_name = "FILE", default_value = "smt.json")]
    state: PathBuf,
}

/// Arguments for `smt path`
#[derive(Debug, Parser)]
pub struct PathArgs {
    /// Path to the persisted tree state (JSON).
    /// Defaults to `smt.json`.
    #[arg(long, value_name = "FILE", default_value = "smt.json")]
    state: PathBuf,

    /// Leaf value to compute the Merkle path for
    /// (a decimal field element string).
    #[arg(long, value_name = "VALUE")]
    leaf: String,

    /// Emit machine-readable JSON instead of the human-readable listing.
    #[arg(long)]
    json: bool,
}

/// Arguments for `smt verify`
#[derive(Debug, Parser)]
pub struct VerifyArgs {
    /// Path to the persisted tree state (JSON).
    /// Defaults to `smt.json`.
    #[arg(long, value_name = "FILE", default_value = "smt.json")]
    state: PathBuf,

    /// Leaf value to verify (a decimal field element string).
    #[arg(long, value_name = "VALUE")]
    leaf: String,
}

/// Arguments for `smt export`
#[derive(Debug, Parser)]
pub struct ExportArgs {
    /// Path to the persisted tree state (JSON).
    /// Defaults to `smt.json`.
    #[arg(long, value_name = "FILE", default_value = "smt.json")]
    state: PathBuf,

    /// Target nullifier to prove membership for
    /// (a decimal field element string).
    #[arg(long, value_name = "VALUE")]
    nullifier: String,

    /// Output path for the JSON witness input file.
    /// Defaults to `input.json`.
    #[arg(long, value_name = "FILE", default_value = "input.json")]
    out: PathBuf,
}

/// Run the SMT command
pub fn run(cmd: SmtCommand) -> Result<(), Box<dyn Error>> {
    match cmd {
        SmtCommand::Leaf(cmd_args) => run_leaf(cmd_args),
        SmtCommand::Insert(cmd_args) => run_insert(cmd_args),
        SmtCommand::Digest(cmd_args) => run_digest(cmd_args),
        SmtCommand::Path(cmd_args) => run_path(cmd_args),
        SmtCommand::Verify(cmd_args) => run_verify(cmd_args),
        SmtCommand::Export(cmd_args) => run_export(cmd_args),
    }
}

fn run_leaf(args: LeafArgs) -> Result<(), Box<dyn Error>> {
    let parts: Vec<&str> = args
        .items
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if parts.len() != 6 {
        return Err(format!(
            "expected exactly 6 field elements (x0,x1,x2,y0,y1,y2), got {}: {}",
            parts.len(),
            args.items
        )
        .into());
    }

    let mut inputs = Vec::with_capacity(6);
    for p in &parts {
        let fr = Fr::from_str(p)
            .map_err(|_| format!("invalid field element: {}", p))?;
        inputs.push(fr);
    }

    let leaf = mimc_hash(&inputs, Fr::zero());
    if args.json {
        let out = serde_json::json!({ "leaf": field_to_string(leaf) });
        println!("{}", serde_json::to_string(&out)?);
    } else {
        println!("{}", field_to_string(leaf));
    }
    Ok(())
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

    // An explicit leaf index is only valid with a single raw commitment item.
    let indices: Vec<Option<usize>> = if let Some(index) = args.index {
        if item_strings.len() != 1 {
            return Err("--index can only be used with a single --items value".into());
        }
        if item_strings[0].split_whitespace().count() != 1 {
            return Err("--index requires a single field element (raw commitment), not 'nullifier nonce'".into());
        }
        vec![Some(index)]
    } else {
        vec![None; item_strings.len()]
    };

    // Parse and insert items
    for (item_str, index) in item_strings.iter().zip(&indices) {
        let parts: Vec<&str> = item_str.split_whitespace().collect();
        match parts.len() {
            1 => {
                let val = Fr::from_str(parts[0])
                    .map_err(|_| format!("invalid field element: {}", parts[0]))?;
                match index {
                    Some(i) => tree.insert_at(val, *i),
                    None => tree.insert(val),
                }
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
        indices,
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
    let tree = rebuild_tree(&state)?;

    let Some(path) = tree.path(leaf) else {
        println!("Leaf {} not found in tree", leaf);
        return Ok(());
    };

    if args.json {
        let siblings: Vec<String> = path.iter().map(|(s, _)| field_to_string(*s)).collect();
        let directions: Vec<String> = path
            .iter()
            .map(|(_, d)| (if *d { "1" } else { "0" }).to_string())
            .collect();
        let out = serde_json::json!({
            "digest": field_to_string(tree.digest()),
            "siblings": siblings,
            "directions": directions,
        });
        println!("{}", serde_json::to_string(&out)?);
    } else {
        println!("digest: {}", field_to_string(tree.digest()));
        for (i, (sibling, direction)) in path.iter().enumerate() {
            println!("  level {}: sibling={}  direction={}",
                i, field_to_string(*sibling), if *direction { "left (sibling on left)" } else { "right (sibling on right)" });
        }
    }

    Ok(())
}

/// Render a field element as a decimal string, mapping zero to `"0"`
/// (ark-ff's `Display` prints zero as an empty string).
fn field_to_string(fr: Fr) -> String {
    if fr == Fr::zero() {
        "0".to_string()
    } else {
        fr.to_string()
    }
}

fn rebuild_tree(state: &SmtState) -> Result<SparseMerkleTree, Box<dyn Error>> {
    let mut tree = SparseMerkleTree::new(state.depth);
    for (i, item_str) in state.items.iter().enumerate() {
        let explicit_index = state.indices.get(i).copied().flatten();
        let parts: Vec<&str> = item_str.split_whitespace().collect();
        match parts.len() {
            1 => {
                let val = Fr::from_str(parts[0])
                    .map_err(|_| format!("invalid field element: {}", parts[0]))?;
                match explicit_index {
                    Some(index) => tree.insert_at(val, index),
                    None => tree.insert(val),
                }
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
            // sibling is on the left
            mimc2(*sibling, current)
        } else {
            // sibling is on the right
            mimc2(current, *sibling)
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
    /// Optional explicit leaf index per item (parallel to `items`).
    /// `None` means the item was inserted sequentially.
    #[serde(default)]
    indices: Vec<Option<usize>>,
}
