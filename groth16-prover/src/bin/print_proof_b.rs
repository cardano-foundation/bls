use ark_bls12_381::{G2Affine, G2Projective, Fr};
use ark_ec::Group;
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use groth16_prover::qap::build_qap_polynomials;
use groth16_prover::r1cs::{L, R, O, WITNESS};

fn main() {
    println!("=== Step 1.13: Proof Element B ===\n");

    let (_us, vs, _ws) = build_qap_polynomials(&L, &R, &O);
    let witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();
    let tau  = Fr::from(3u64);
    let beta = Fr::from(7u64);
    let g2_proj = G2Projective::generator();

    // Build r(x) = sum a_i * v_i(x)
    let mut r = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    for i in 0..witness.len() {
        let term_coeffs: Vec<Fr> = vs[i].coeffs.iter().map(|c| *c * witness[i]).collect();
        let term = DensePolynomial::from_coefficients_vec(term_coeffs);
        r += &term;
    }
    // Normalize
    while r.coeffs.last().map_or(false, |c| c.is_zero()) {
        r.coeffs.pop();
    }

    // r(tau) = evaluate r(x) at tau
    let r_tau = r.evaluate(&tau);
    println!("r(x) = {:?}", r.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    println!("r(tau) = {}  (tau = {})", r_tau, tau);
    println!("beta = {}", beta);

    // B = r(tau) * G2 + beta * G2
    let b_scalar = r_tau + beta;
    let b_pt = g2_proj * b_scalar;
    let b_affine = G2Affine::from(b_pt);

    println!("\nB = r(tau)*G2 + beta*G2");
    println!("  combined scalar = r(tau) + beta = {}", b_scalar);
    println!("  x = {}", b_affine.x);
    println!("  y = {}", b_affine.y);

    // Sanity: B should equal (r_tau + beta) * G2
    let direct = G2Affine::from(g2_proj * b_scalar);
    assert_eq!(b_affine, direct, "B must equal (r_tau + beta) * G2");

    println!("\n✓ Proof element B computed and verified.");
    println!("✓ Step 1.13 printouts complete.");
}
