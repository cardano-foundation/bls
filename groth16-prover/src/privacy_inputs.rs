// Compute witness inputs for the Spend(depth) circuit.
// This project is strictly focused on BLS12-381. BN254 is not supported.
//
// This is the Rust counterpart of `circom/Privacy/helpers_js/compute_spend_inputs.js`.

use ark_bls12_381::Fr;
use std::str::FromStr;
use crate::mimc::mimc2;
use crate::sparse_merkle_tree::SparseMerkleTree;

/// A single entry in the transcript.
///
/// - `Commitment(fr)` — a raw commitment value already hashed.
/// - `NullifierNonce(nullifier, nonce)` — two field elements to be hashed into a commitment.
pub enum TranscriptEntry {
    Commitment(Fr),
    NullifierNonce(Fr, Fr),
}

/// Witness inputs for the Spend(depth) circuit, ready to be serialized to `input.json`.
pub struct SpendInputs {
    pub digest: String,
    pub nullifier: String,
    pub nonce: String,
    pub siblings: Vec<String>,
    pub directions: Vec<String>,
}

impl SpendInputs {
    /// Serialize to a JSON-like map (signal name → string field element).
    pub fn to_json_map(&self) -> Vec<(String, String)> {
        let mut map = vec![
            ("digest".to_string(), self.digest.clone()),
            ("nullifier".to_string(), self.nullifier.clone()),
            ("nonce".to_string(), self.nonce.clone()),
        ];
        for (i, sibling) in self.siblings.iter().enumerate() {
            map.push((format!("sibling[{}]", i), sibling.clone()));
        }
        for (i, direction) in self.directions.iter().enumerate() {
            map.push((format!("direction[{}]", i), direction.clone()));
        }
        map
    }
}

/// Compute the witness inputs for a Spend(depth) proof.
///
/// # Arguments
/// * `depth` — Merkle tree depth.
/// * `transcript` — list of items added to the tree.
/// * `nullifier` — the nullifier to prove membership for (must appear in transcript).
///
/// # Errors
/// Returns an error string if the nullifier is not found in the transcript.
pub fn compute_spend_inputs(
    depth: usize,
    transcript: &[TranscriptEntry],
    nullifier: &str,
) -> Result<SpendInputs, String> {
    let nullifier_fr = Fr::from_str(nullifier)
        .map_err(|_| format!("invalid nullifier: {}", nullifier))?;

    let mut tree = SparseMerkleTree::new(depth);
    let mut target_nonce: Option<Fr> = None;

    for entry in transcript {
        match entry {
            TranscriptEntry::Commitment(fr) => {
                tree.insert(*fr);
            }
            TranscriptEntry::NullifierNonce(nf, nonce) => {
                let commitment = mimc2(*nf, *nonce);
                tree.insert(commitment);
                if nf.to_string() == nullifier {
                    target_nonce = Some(*nonce);
                }
            }
        }
    }

    let Some(nonce) = target_nonce else {
        return Err("Nullifier not found in transcript".to_string());
    };

    let commitment = mimc2(nullifier_fr, nonce);
    let path = tree.path(commitment);

    let siblings: Vec<String> = path.iter().map(|(s, _)| s.to_string()).collect();
    let directions: Vec<String> = path.iter().map(|(_, d)| if *d { "1".to_string() } else { "0".to_string() }).collect();

    Ok(SpendInputs {
        digest: tree.digest().to_string(),
        nullifier: nullifier.to_string(),
        nonce: nonce.to_string(),
        siblings,
        directions,
    })
}

/// Convenience helper: parse a transcript from raw string lines.
///
/// Each line is split on whitespace:
/// - one token → `Commitment(token)`
/// - two tokens → `NullifierNonce(token0, token1)`
///
/// Empty lines are skipped.
pub fn parse_transcript_lines(lines: &[String]) -> Result<Vec<TranscriptEntry>, String> {
    let mut entries = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        match parts.len() {
            1 => {
                let fr = Fr::from_str(parts[0])
                    .map_err(|_| format!("invalid field element: {}", parts[0]))?;
                entries.push(TranscriptEntry::Commitment(fr));
            }
            2 => {
                let nf = Fr::from_str(parts[0])
                    .map_err(|_| format!("invalid nullifier: {}", parts[0]))?;
                let nonce = Fr::from_str(parts[1])
                    .map_err(|_| format!("invalid nonce: {}", parts[1]))?;
                entries.push(TranscriptEntry::NullifierNonce(nf, nonce));
            }
            n => return Err(format!("expected 1 or 2 tokens, got {}: {}", n, line)),
        }
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_spend_inputs() {
        let transcript = vec![
            TranscriptEntry::NullifierNonce(Fr::from(1u64), Fr::from(100u64)),
            TranscriptEntry::NullifierNonce(Fr::from(2u64), Fr::from(200u64)),
        ];
        let inputs = compute_spend_inputs(2, &transcript, "2").unwrap();
        assert_eq!(inputs.nullifier, "2");
        assert_eq!(inputs.nonce, "200");
        assert_eq!(inputs.siblings.len(), 2);
        assert_eq!(inputs.directions.len(), 2);
    }
}
