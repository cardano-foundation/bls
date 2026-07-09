use ark_bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective, Fr};
use ark_ec::Group;
use groth16_prover::engine::FftQapEngine;
use groth16_prover::prover::{NaiveProver, PippengerProver, Prover};
use groth16_prover::r1cs::WITNESS;

fn main() {
    println!("=== Step 3.1: Pippenger MSM Proof Assembly ===\n");

    let engine = FftQapEngine::new();
    let naive = NaiveProver::new();
    let pippenger = PippengerProver::new();

    let witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();
    let tau = Fr::from(3u64);
    let alpha = Fr::from(5u64);
    let beta = Fr::from(7u64);
    let gamma = Fr::from(11u64);
    let delta = Fr::from(13u64);

    // ------------------------------------------------------------------
    // Naive prover (Implementation 2 style)
    // ------------------------------------------------------------------
    println!("--- Naive prover (scalar-by-scalar) ---");
    let (proof_naive, public_naive) =
        naive.prove(&engine, &witness, tau, alpha, beta, gamma, delta);

    println!("A (G1) x = {}", proof_naive.a.x);
    println!("A (G1) y = {}", proof_naive.a.y);
    println!("B (G2) x = {}", proof_naive.b.x);
    println!("B (G2) y = {}", proof_naive.b.y);
    println!("C (G1) x = {}", proof_naive.c.x);
    println!("C (G1) y = {}", proof_naive.c.y);
    println!("V (G1) x = {}", public_naive.v.x);
    println!("V (G1) y = {}", public_naive.v.y);

    // ------------------------------------------------------------------
    // Pippenger prover (Implementation 3)
    // ------------------------------------------------------------------
    println!("\n--- Pippenger prover (batched MSM) ---");
    let (proof_pip, public_pip) =
        pippenger.prove(&engine, &witness, tau, alpha, beta, gamma, delta);

    println!("A (G1) x = {}", proof_pip.a.x);
    println!("A (G1) y = {}", proof_pip.a.y);
    println!("B (G2) x = {}", proof_pip.b.x);
    println!("B (G2) y = {}", proof_pip.b.y);
    println!("C (G1) x = {}", proof_pip.c.x);
    println!("C (G1) y = {}", proof_pip.c.y);
    println!("V (G1) x = {}", public_pip.v.x);
    println!("V (G1) y = {}", public_pip.v.y);

    // ------------------------------------------------------------------
    // Parity assertion
    // ------------------------------------------------------------------
    assert_eq!(proof_naive.a, proof_pip.a, "A must match");
    assert_eq!(proof_naive.b, proof_pip.b, "B must match");
    assert_eq!(proof_naive.c, proof_pip.c, "C must match");
    assert_eq!(public_naive.v, public_pip.v, "V must match");

    println!("\n✓ Pippenger proof matches naive proof bit-for-bit.");

    // ------------------------------------------------------------------
    // Pairing check
    // ------------------------------------------------------------------
    let g1_proj = G1Projective::generator();
    let g2_proj = G2Projective::generator();
    let alpha_g1 = G1Affine::from(g1_proj * alpha);
    let beta_g2 = G2Affine::from(g2_proj * beta);
    let gamma_g2 = G2Affine::from(g2_proj * gamma);
    let delta_g2 = G2Affine::from(g2_proj * delta);

    assert!(
        groth16_prover::prover::verify_proof(
            &proof_pip,
            &public_pip,
            &alpha_g1,
            &beta_g2,
            &gamma_g2,
            &delta_g2,
        ),
        "Pippenger proof must pass pairing check"
    );

    println!("✓ Pairing check PASSED.");
    println!("✓ Step 3.1 printouts complete.");
}
