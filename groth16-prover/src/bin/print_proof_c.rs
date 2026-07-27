use ark_bls12_381::{G1Affine, G1Projective, Fr};
use ark_ec::Group;
use ark_ff::{Field, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use groth16_prover::engine::{DenseQapEngine, QapEngine};
use groth16_prover::qap::build_qap_polynomials_circuit;
use groth16_prover::r1cs::select_circuit;

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: print_proof_c <multiplier|sumofproducts>");
        std::process::exit(1);
    });
    let circuit = select_circuit(&name);

    println!("=== Step 1.14: Proof Element C ===\n");
    println!("Circuit: {}", circuit.name);

    let (us, vs, ws) = build_qap_polynomials_circuit(&circuit);
    let tau = match circuit.name {
        "multiplier" => Fr::from(3u64),
        _            => Fr::from(6u64),
    };
    let alpha = Fr::from(5u64);
    let beta  = Fr::from(7u64);
    let delta = Fr::from(13u64);
    let delta_inv = delta.inverse().unwrap();
    let g1_proj = G1Projective::generator();

    // Build l(x), r(x), o(x)
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

    // ------------------------------------------------------------------
    // Psi_P_G1 for private inputs
    // ------------------------------------------------------------------
    let n_public = circuit.n_public;
    println!("--- Psi_P_G1 accumulation ---");
    let mut psi_with_a = G1Projective::zero();
    for i in n_public..circuit.n_vars() {
        let u_tau = us[i].evaluate(&tau);
        let v_tau = vs[i].evaluate(&tau);
        let w_tau = ws[i].evaluate(&tau);
        let psi_scalar = (v_tau * alpha + u_tau * beta + w_tau) * delta_inv;
        let pt = g1_proj * psi_scalar;
        let weighted = pt * circuit.witness[i];
        psi_with_a += weighted;
        println!("Variable {}: a_i = {}, psi_scalar = {}, contribution scalar = {}",
                 i, circuit.witness[i], psi_scalar, psi_scalar * circuit.witness[i]);
    }

    // ------------------------------------------------------------------
    // h(tau) in the exponent via SRS3
    // ------------------------------------------------------------------
    let h_tau = h.evaluate(&tau);
    let h_tau_scalar = h_tau * t_tau * delta_inv;
    let h_tau_g1 = g1_proj * h_tau_scalar;
    println!("\nT(tau) = {}", t_tau);
    println!("h(tau) = {}", h_tau);
    println!("h_tau_G1 scalar = h(tau) * T(tau) / delta = {}", h_tau_scalar);

    // ------------------------------------------------------------------
    // C = Psi_with_a + h_tau_G1
    // ------------------------------------------------------------------
    let c_pt = psi_with_a + h_tau_g1;
    let c_affine = G1Affine::from(c_pt);

    println!("\nC = sum(a_i * Psi_P_G1) + h_tau_G1");
    println!("  x = {}", c_affine.x);
    println!("  y = {}", c_affine.y);

    // Sanity: compute total scalar directly
    let mut total_scalar = Fr::zero();
    for i in n_public..circuit.n_vars() {
        let u_tau = us[i].evaluate(&tau);
        let v_tau = vs[i].evaluate(&tau);
        let w_tau = ws[i].evaluate(&tau);
        total_scalar += (v_tau * alpha + u_tau * beta + w_tau) * delta_inv * circuit.witness[i];
    }
    total_scalar += h_tau_scalar;
    println!("\nTotal combined scalar = {}", total_scalar);
    let direct = G1Affine::from(g1_proj * total_scalar);
    assert_eq!(c_affine, direct, "C must equal total_scalar * G1");

    println!("\n✓ Proof element C computed and verified.");
    println!("✓ Step 1.14 printouts complete.");
}
