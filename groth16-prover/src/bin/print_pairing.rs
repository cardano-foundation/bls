use ark_bls12_381::{Bls12_381, G1Affine, G1Projective, G2Affine, G2Projective, Fr};
use ark_ec::{pairing::Pairing, Group};
use ark_ff::{Field, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use groth16_prover::engine::{DenseQapEngine, QapEngine};
use groth16_prover::qap::build_qap_polynomials_circuit;
use groth16_prover::r1cs::select_circuit;

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: print_pairing <multiplier|sumofproducts>");
        std::process::exit(1);
    });
    let circuit = select_circuit(&name);

    println!("=== Step 1.16: Pairing Check ===\n");
    println!("Circuit: {}", circuit.name);

    let (us, vs, ws) = build_qap_polynomials_circuit(&circuit);
    let tau = match circuit.name {
        "multiplier" => Fr::from(3u64),
        _            => Fr::from(6u64),
    };
    let alpha = Fr::from(5u64);
    let beta  = Fr::from(7u64);
    let gamma = Fr::from(11u64);
    let delta = Fr::from(13u64);
    let gamma_inv = gamma.inverse().unwrap();
    let delta_inv = delta.inverse().unwrap();
    let g1_proj = G1Projective::generator();
    let g2_proj = G2Projective::generator();

    // ------------------------------------------------------------------
    // Build l(x), r(x), o(x)
    // ------------------------------------------------------------------
    let mut l = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    let mut r = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    let mut o = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    for i in 0..circuit.n_vars() {
        let lc: Vec<Fr> = us[i].coeffs.iter().map(|c| *c * circuit.witness[i]).collect();
        let rc: Vec<Fr> = vs[i].coeffs.iter().map(|c| *c * circuit.witness[i]).collect();
        let oc: Vec<Fr> = ws[i].coeffs.iter().map(|c| *c * circuit.witness[i]).collect();
        l += &DensePolynomial::from_coefficients_vec(lc);
        r += &DensePolynomial::from_coefficients_vec(rc);
        o += &DensePolynomial::from_coefficients_vec(oc);
    }
    while l.coeffs.last().map_or(false, |c| c.is_zero()) { l.coeffs.pop(); }
    while r.coeffs.last().map_or(false, |c| c.is_zero()) { r.coeffs.pop(); }
    while o.coeffs.last().map_or(false, |c| c.is_zero()) { o.coeffs.pop(); }

    let engine = DenseQapEngine::new();
    let n_constraints = circuit.n_constraints();
    let t = engine.target_poly(n_constraints);
    let t_tau = t.evaluate(&tau);

    // Compute h(x) properly via the engine
    let h = engine.compute_quotient(&l, &r, &o, &t);
    let h_tau = h.evaluate(&tau);

    // ------------------------------------------------------------------
    // Compute proof elements
    // ------------------------------------------------------------------
    let l_tau = l.evaluate(&tau);
    let r_tau = r.evaluate(&tau);

    // A = (l_tau + alpha) * G1
    let a_affine = G1Affine::from(g1_proj * (l_tau + alpha));

    // B = (r_tau + beta) * G2
    let b_affine = G2Affine::from(g2_proj * (r_tau + beta));

    let n_public = circuit.n_public;

    // C = sum_{private} a_i * Psi_P_G1 + h_tau_G1
    let mut c_scalar = Fr::zero();
    for i in n_public..circuit.n_vars() {
        let u_tau = us[i].evaluate(&tau);
        let v_tau = vs[i].evaluate(&tau);
        let w_tau = ws[i].evaluate(&tau);
        c_scalar += (v_tau * alpha + u_tau * beta + w_tau) * delta_inv * circuit.witness[i];
    }
    c_scalar += h_tau * t_tau * delta_inv;
    let c_affine = G1Affine::from(g1_proj * c_scalar);

    // V = sum_{public} a_i * Psi_V_G1
    let mut v_scalar = Fr::zero();
    for i in 0..n_public {
        let u_tau = us[i].evaluate(&tau);
        let v_tau = vs[i].evaluate(&tau);
        let w_tau = ws[i].evaluate(&tau);
        v_scalar += (v_tau * alpha + u_tau * beta + w_tau) * gamma_inv * circuit.witness[i];
    }
    let v_affine = G1Affine::from(g1_proj * v_scalar);

    // CRS points
    let alpha_g1 = G1Affine::from(g1_proj * alpha);
    let beta_g2  = G2Affine::from(g2_proj * beta);
    let delta_g2 = G2Affine::from(g2_proj * delta);
    let gamma_g2 = G2Affine::from(g2_proj * gamma);

    println!("A = {} * G1", l_tau + alpha);
    println!("B = {} * G2", r_tau + beta);
    println!("C = {} * G1 (combined scalar)", c_scalar);
    println!("V = {} * G1 (combined scalar)", v_scalar);
    println!();

    // ------------------------------------------------------------------
    // Pairing check: e(A, B) == e(alpha*G1, beta*G2) * e(C, delta*G2) * e(V, gamma*G2)
    // ------------------------------------------------------------------
    let lhs = Bls12_381::pairing(a_affine, b_affine);
    let rhs1 = Bls12_381::pairing(alpha_g1, beta_g2);
    let rhs2 = Bls12_381::pairing(c_affine, delta_g2);
    let rhs3 = Bls12_381::pairing(v_affine, gamma_g2);
    // In arkworks, the target group GT is written additively, so the
    // multiplicative product e(A,B)*e(C,D)*e(E,F) becomes rhs1 + rhs2 + rhs3.
    let rhs = rhs1 + rhs2 + rhs3;

    println!("e(A, B)          = {:?}", lhs);
    println!("e(alpha*G1, beta*G2) = {:?}", rhs1);
    println!("e(C, delta*G2)       = {:?}", rhs2);
    println!("e(V, gamma*G2)       = {:?}", rhs3);
    println!("product RHS          = {:?}", rhs);

    assert_eq!(lhs, rhs, "Groth16 pairing check FAILED");
    println!("\n✓ Pairing check PASSED. The proof is valid.");
    println!("✓ Step 1.16 printouts complete.");
}
