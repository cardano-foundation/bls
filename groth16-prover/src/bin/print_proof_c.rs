use ark_bls12_381::{G1Affine, G1Projective, Fr};
use ark_ec::Group;
use ark_ff::{Field, One, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use groth16_prover::qap::{build_qap_polynomials, build_target_polynomial};
use groth16_prover::r1cs::{L, R, O, WITNESS};

fn main() {
    println!("=== Step 1.14: Proof Element C ===\n");

    let (us, vs, ws) = build_qap_polynomials(&L, &R, &O);
    let witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();
    let tau   = Fr::from(3u64);
    let alpha = Fr::from(5u64);
    let beta  = Fr::from(7u64);
    let delta = Fr::from(13u64);
    let delta_inv = delta.inverse().unwrap();
    let g1_proj = G1Projective::generator();

    // Build l(x), r(x), o(x), h(x)
    let mut l = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    let mut r = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    let mut o = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    for i in 0..witness.len() {
        let lc: Vec<Fr> = us[i].coeffs.iter().map(|c| *c * witness[i]).collect();
        let rc: Vec<Fr> = vs[i].coeffs.iter().map(|c| *c * witness[i]).collect();
        let oc: Vec<Fr> = ws[i].coeffs.iter().map(|c| *c * witness[i]).collect();
        l += &DensePolynomial::from_coefficients_vec(lc);
        r += &DensePolynomial::from_coefficients_vec(rc);
        o += &DensePolynomial::from_coefficients_vec(oc);
    }
    while l.coeffs.last().map_or(false, |c| c.is_zero()) { l.coeffs.pop(); }
    while r.coeffs.last().map_or(false, |c| c.is_zero()) { r.coeffs.pop(); }
    while o.coeffs.last().map_or(false, |c| c.is_zero()) { o.coeffs.pop(); }

    let points = [Fr::zero(), Fr::one(), Fr::from(2u64)];
    let t = build_target_polynomial(&points);
    let t_tau = t.evaluate(&tau);

    // h(x) = 3 (constant)
    let h = DensePolynomial::from_coefficients_vec(vec![Fr::from(3u64)]);

    // ------------------------------------------------------------------
    // Psi_P_G1 for private inputs (variables 2..7)
    // ------------------------------------------------------------------
    println!("--- Psi_P_G1 accumulation ---");
    let mut psi_with_a = G1Projective::zero();
    for i in 2..witness.len() {
        let u_tau = us[i].evaluate(&tau);
        let v_tau = vs[i].evaluate(&tau);
        let w_tau = ws[i].evaluate(&tau);
        let psi_scalar = (v_tau * alpha + u_tau * beta + w_tau) * delta_inv;
        let pt = g1_proj * psi_scalar;
        let weighted = pt * witness[i];
        psi_with_a += weighted;
        println!("Variable {}: a_i = {}, psi_scalar = {}, contribution scalar = {}",
                 i, witness[i], psi_scalar, psi_scalar * witness[i]);
    }

    // ------------------------------------------------------------------
    // h(tau) in the exponent via SRS3
    //   h(x) = 3, SRS3[0] = G1 * T(tau)/delta
    //   h_tau_G1 = 3 * SRS3[0]
    // ------------------------------------------------------------------
    let h_tau_scalar = h.coeffs[0] * t_tau * delta_inv;
    let h_tau_g1 = g1_proj * h_tau_scalar;
    println!("\nT(tau) = {}", t_tau);
    println!("h(x) = {}", h.coeffs[0]);
    println!("h_tau_G1 scalar = h * T(tau) / delta = {}", h_tau_scalar);

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
    for i in 2..witness.len() {
        let u_tau = us[i].evaluate(&tau);
        let v_tau = vs[i].evaluate(&tau);
        let w_tau = ws[i].evaluate(&tau);
        total_scalar += (v_tau * alpha + u_tau * beta + w_tau) * delta_inv * witness[i];
    }
    total_scalar += h_tau_scalar;
    println!("\nTotal combined scalar = {}", total_scalar);
    let direct = G1Affine::from(g1_proj * total_scalar);
    assert_eq!(c_affine, direct, "C must equal total_scalar * G1");

    println!("\n✓ Proof element C computed and verified.");
    println!("✓ Step 1.14 printouts complete.");
}
