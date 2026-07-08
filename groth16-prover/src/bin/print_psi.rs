use ark_bls12_381::{G1Affine, G1Projective, Fr};
use ark_ec::{AffineRepr, Group};
use ark_ff::{Field, Zero};
use ark_poly::Polynomial;
use groth16_prover::qap::build_qap_polynomials;
use groth16_prover::r1cs::{L, R, O};

fn main() {
    println!("=== Step 1.9: Per-Variable CRS ===\n");

    let (us, vs, ws) = build_qap_polynomials(&L, &R, &O);

    let tau   = Fr::from(3u64);
    let alpha = Fr::from(5u64);
    let beta  = Fr::from(7u64);
    let gamma = Fr::from(11u64);
    let delta = Fr::from(13u64);
    let gamma_inv = gamma.inverse().unwrap();
    let delta_inv = delta.inverse().unwrap();
    let g1_proj = G1Projective::generator();

    println!(
        "tau = {}, alpha = {}, beta = {}, gamma = {}, delta = {}\n",
        tau, alpha, beta, gamma, delta
    );

    // ------------------------------------------------------------------
    // Psi_V_G1 : public inputs (variables 0 and 1), divided by gamma
    // ------------------------------------------------------------------
    println!("--- Psi_V_G1 (public inputs, divided by gamma) ---");
    for i in 0..2 {
        let u_tau = us[i].evaluate(&tau);
        let v_tau = vs[i].evaluate(&tau);
        let w_tau = ws[i].evaluate(&tau);
        let scalar = v_tau * alpha + u_tau * beta + w_tau;
        let psi_scalar = scalar * gamma_inv;
        let pt = g1_proj * psi_scalar;
        let affine = G1Affine::from(pt);

        println!("Variable {}: u_i(tau) = {}, v_i(tau) = {}, w_i(tau) = {}",
                 i, u_tau, v_tau, w_tau);
        println!("  combined scalar = v*alpha + u*beta + w = {}", scalar);
        println!("  psi_scalar = combined / gamma = {}", psi_scalar);
        if affine.is_zero() {
            println!("  point = (point at infinity)");
        } else {
            println!("  x = {}", affine.x);
            println!("  y = {}", affine.y);
        }
    }

    // ------------------------------------------------------------------
    // Psi_P_G1 : private inputs (variables 2..7), divided by delta
    // ------------------------------------------------------------------
    println!("\n--- Psi_P_G1 (private inputs, divided by delta) ---");
    for i in 2..8 {
        let u_tau = us[i].evaluate(&tau);
        let v_tau = vs[i].evaluate(&tau);
        let w_tau = ws[i].evaluate(&tau);
        let scalar = v_tau * alpha + u_tau * beta + w_tau;
        let psi_scalar = scalar * delta_inv;
        let pt = g1_proj * psi_scalar;
        let affine = G1Affine::from(pt);

        println!("Variable {}: u_i(tau) = {}, v_i(tau) = {}, w_i(tau) = {}",
                 i, u_tau, v_tau, w_tau);
        println!("  combined scalar = v*alpha + u*beta + w = {}", scalar);
        println!("  psi_scalar = combined / delta = {}", psi_scalar);
        if affine.is_zero() {
            println!("  point = (point at infinity)");
        } else {
            println!("  x = {}", affine.x);
            println!("  y = {}", affine.y);
        }
    }

    // Sanity checks
    assert_eq!(us[0].evaluate(&tau), Fr::zero(), "u_0(tau) must be zero");
    assert_eq!(vs[0].evaluate(&tau), Fr::zero(), "v_0(tau) must be zero");
    assert_eq!(ws[0].evaluate(&tau), Fr::zero(), "w_0(tau) must be zero");
    println!("\n✓ Step 1.9 sanity checks passed.");
    println!("✓ Step 1.9 printouts complete.");
}
