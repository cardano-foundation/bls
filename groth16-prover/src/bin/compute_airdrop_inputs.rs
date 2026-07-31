// Temporary helper: compute witness inputs for AnonymousAirdrop(depth=2)
// This project is strictly focused on BLS12-381. BN254 is not supported.

use ark_bls12_381::Fr;
use groth16_prover::mimc::mimc2;
use groth16_prover::sparse_merkle_tree::SparseMerkleTree;

fn fr_to_str(fr: Fr) -> String {
    let s = fr.to_string();
    if s.is_empty() { "0".to_string() } else { s }
}

fn print_json(
    digest: Fr,
    min_score: u64,
    nullifier: u64,
    nonce: u64,
    score: u64,
    path: &[(Fr, bool)],
) {
    println!("{{");
    println!("  \"digest\": \"{}\",", fr_to_str(digest));
    println!("  \"minScore\": \"{}\",", min_score);
    println!("  \"nullifier\": \"{}\",", nullifier);
    println!("  \"nonce\": \"{}\",", nonce);
    println!("  \"score\": \"{}\",", score);
    print!("  \"sibling\": [");
    for (i, (sibling, _)) in path.iter().enumerate() {
        if i > 0 { print!(", "); }
        print!("\"{}\"", fr_to_str(*sibling));
    }
    println!("],");
    print!("  \"direction\": [");
    for (i, (_, direction)) in path.iter().enumerate() {
        if i > 0 { print!(", "); }
        print!("\"{}\"", if *direction { "1" } else { "0" });
    }
    println!("]");
    println!("}}");
}

fn main() {
    let credentials: Vec<(u64, u64, u64)> = vec![
        (1, 100, 85),   // Alice: score 85
        (2, 200, 42),   // Bob:   score 42
        (3, 300, 120),  // Carol: score 120
    ];

    let depth = 2;
    let mut tree = SparseMerkleTree::new(depth);

    let mut commitments = Vec::new();
    for &(nullifier, nonce, score) in &credentials {
        let nf = Fr::from(nullifier);
        let n = Fr::from(nonce);
        let s = Fr::from(score);
        let temp = mimc2(nf, n);
        let commitment = mimc2(temp, s);
        tree.insert(commitment);
        commitments.push((nullifier, nonce, score, commitment));
    }

    let digest = tree.digest();
    println!("SMT digest (root): {}", digest);
    println!();

    // Carol (nullifier=3) wants to claim
    let target_nullifier = 3u64;
    let min_score = 100u64;
    let target = commitments.iter().find(|&&(nf, _, _, _)| nf == target_nullifier).unwrap();
    let (_, _, score, commitment) = *target;
    let path = tree.path(commitment).unwrap();

    println!("--- ACCEPTED case: Carol (score={}) with minScore={} ---", score, min_score);
    print_json(digest, min_score, target_nullifier, target.1, score, &path);
    println!();

    // Bob (nullifier=2) rejected
    let rejected = credentials.iter().find(|&&(nf, _, _)| nf == 2).unwrap();
    let (_, rej_nonce, rej_score) = *rejected;
    let nf = Fr::from(2u64);
    let n = Fr::from(rej_nonce);
    let s = Fr::from(rej_score);
    let temp = mimc2(nf, n);
    let rej_commitment = mimc2(temp, s);
    let rej_path = tree.path(rej_commitment).unwrap();

    println!("--- REJECTED case: Bob (score={}) with minScore={} ---", rej_score, min_score);
    print_json(digest, min_score, 2, rej_nonce, rej_score, &rej_path);
}
