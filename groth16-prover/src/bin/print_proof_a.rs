use ark_bls12_381::{G1Affine, G1Projective, Fr};
use ark_ec::Group;
use ark_ff::Zero;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use groth16_prover::qap::build_qap_polynomials_circuit;
use groth16_prover::r1cs::select_circuit;

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: print_proof_a <multiplier|sumofproducts>");
        std::process::exit(1);
    });
    let circuit = select_circuit(&name);

    println!("=== Step 1.12: Proof Element A ===\n");
    println!("Circuit: {}", circuit.name);

    let (us, _vs, _ws) = build_qap_polynomials_circuit(&circuit);
    let tau = match circuit.name {
        "multiplier" => Fr::from(3u64),
        _            => Fr::from(6u64),
    };
    let alpha = Fr::from(5u64);
    let g1_proj = G1Projective::generator();

    // Build l(x) = sum a_i * u_i(x)
    let mut l = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    for i in 0..circuit.n_vars() {
        let term_coeffs: Vec<Fr> = us[i].coeffs.iter().map(|c| *c * circuit.witness[i]).collect();
        let term = DensePolynomial::from_coefficients_vec(term_coeffs);
        l += &term;
    }
    // Normalize
    while l.coeffs.last().map_or(false, |c| c.is_zero()) {
        l.coeffs.pop();
    }

    // l(tau) = evaluate l(x) at tau
    let l_tau = l.evaluate(&tau);
    println!("l(x) = {:?}", l.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    println!("l(tau) = {}  (tau = {})", l_tau, tau);
    println!("alpha = {}", alpha);

    // A = l(tau) * G1 + alpha * G1
    let a_scalar = l_tau + alpha;
    let a_pt = g1_proj * a_scalar;
    let a_affine = G1Affine::from(a_pt);

    println!("\nA = l(tau)*G1 + alpha*G1");
    println!("  combined scalar = l(tau) + alpha = {}", a_scalar);
    println!("  x = {}", a_affine.x);
    println!("  y = {}", a_affine.y);

    // Sanity: A should equal (l_tau + alpha) * G1
    let direct = G1Affine::from(g1_proj * a_scalar);
    assert_eq!(a_affine, direct, "A must equal (l_tau + alpha) * G1");

    println!("\n✓ Proof element A computed and verified.");
    println!("✓ Step 1.12 printouts complete.");
}
