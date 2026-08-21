/// Generate Fiat-Shamir test vectors for the Aiken on-chain verifier.
///
/// Run with: cargo run --example gen_fiat_shamir_vectors
use ark_bls12_381::Fr;
use ark_ff::{BigInteger, Field, PrimeField, Zero};
use blake2::{Blake2b, Digest};
use blake2::digest::consts::U32;

fn hash_field_elements(elems: &[Fr]) -> Vec<u8> {
    let mut h = Blake2b::<U32>::new();
    for e in elems {
        h.update(e.into_bigint().to_bytes_le());
    }
    h.finalize().to_vec()
}

fn challenge_from_hash(hash: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(hash)
}

fn main() {
    // === Test 1: Simple 2-round case ===
    // Round 0: claims=[42], poly=[10, 20]
    //   hash_input = [42, 10, 20] (3 elements × 32 bytes = 96 bytes)
    // Round 1: claims=[42, claim1], poly=[30, 40]
    //   hash_input = [42, claim1, 30, 40]
    // But we need to know claim1. In sumcheck, claim1 is NOT derived from round 0's
    // polynomial. The claims are independent — they're the prover's claimed evaluations.
    // Let's use claims = [42, 100, 200] (3 claims for 2 rounds).

    println!("=== Test 1: Simple 2-round ===");

    let claims_1 = vec![Fr::from(42u64), Fr::from(100u64), Fr::from(200u64)];
    let polys_1 = vec![
        vec![Fr::from(10u64), Fr::from(20u64)],
        vec![Fr::from(30u64), Fr::from(40u64)],
    ];

    // Round 0: hash([42, 10, 20])
    let h0_input = vec![Fr::from(42u64), Fr::from(10u64), Fr::from(20u64)];
    let h0 = hash_field_elements(&h0_input);
    let ch0 = challenge_from_hash(&h0);
    println!("round_0_hash_input = [42, 10, 20]");
    println!("round_0_hash_hex = {}", hex::encode(&h0));
    println!("round_0_challenge = {}", ch0);

    // Round 1: hash([42, 100, 200, 30, 40])
    let h1_input = vec![
        Fr::from(42u64), Fr::from(100u64), Fr::from(200u64),
        Fr::from(30u64), Fr::from(40u64),
    ];
    let h1 = hash_field_elements(&h1_input);
    let ch1 = challenge_from_hash(&h1);
    println!("round_1_hash_input = [42, 100, 200, 30, 40]");
    println!("round_1_hash_hex = {}", hex::encode(&h1));
    println!("round_1_challenge = {}", ch1);

    // Print LE bytes of challenges as hex (32 bytes each)
    println!("challenge_0_le = {}", hex::encode(&ch0.into_bigint().to_bytes_le()));
    println!("challenge_1_le = {}", hex::encode(&ch1.into_bigint().to_bytes_le()));

    // Print LE bytes of each input element (for Aiken bytearray comparison)
    println!("\n--- element LE bytes ---");
    for (i, e) in h0_input.iter().enumerate() {
        println!("h0_input[{}] = {} -> le_hex = {}", i, e, hex::encode(&e.into_bigint().to_bytes_le()));
    }
    for (i, e) in h1_input.iter().enumerate() {
        println!("h1_input[{}] = {} -> le_hex = {}", i, e, hex::encode(&e.into_bigint().to_bytes_le()));
    }

    // === Test 2: CKO all-zeros (verifier logic: claims[..=round] ++ poly) ===
    println!("\n=== Test 2: CKO all-zeros, 13 rounds ===");
    let claims_2: Vec<Fr> = vec![Fr::ZERO; 14];
    let polys_2: Vec<Vec<Fr>> = vec![vec![Fr::ZERO, Fr::ZERO]; 13];

    for i in 0..13 {
        // Match verifier logic: proof.claims[..=round] ++ poly
        let mut hash_input: Vec<Fr> = claims_2[..=i].to_vec();
        for c in &polys_2[i] {
            hash_input.push(*c);
        }
        let h = hash_field_elements(&hash_input);
        let ri = challenge_from_hash(&h);
        println!("round_{}_challenge = {}", i, ri);
        println!("round_{}_hash_input_len = {}", i, hash_input.len());
    }

    // === Test 3: Single round with value ===
    println!("\n=== Test 3: Single round ===");
    let claims_3 = vec![Fr::from(777u64)];
    let polys_3 = vec![vec![Fr::from(500u64), Fr::from(277u64)]];
    let h3 = hash_field_elements(&[Fr::from(777u64), Fr::from(500u64), Fr::from(277u64)]);
    let ch3 = challenge_from_hash(&h3);
    println!("hash_input = [777, 500, 277]");
    println!("hash_hex = {}", hex::encode(&h3));
    println!("challenge = {}", ch3);
    println!("challenge_le = {}", hex::encode(&ch3.into_bigint().to_bytes_le()));
}
