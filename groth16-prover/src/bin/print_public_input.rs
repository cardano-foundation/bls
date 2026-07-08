use ark_bls12_381::{G1Affine, G1Projective, Fr};
use ark_ec::Group;
use ark_ff::{Field, Zero};
use ark_poly::Polynomial;
use groth16_prover::qap::build_qap_polynomials;
use groth16_prover::r1cs::{L, R, O, WITNESS};

fn main() {
    println!("=== Step 1.15: Public-Input Commitment V ===\n");

    let (us, vs, ws) = build_qap_polynomials(&L, &R, &O);
    let witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();
    let tau   = Fr::from(3u64);
    let alpha = Fr::from(5u64);
    let beta  = Fr::from(7u64);
    let gamma = Fr::from(11u64);
    let gamma_inv = gamma.inverse().unwrap();
    let g1_proj = G1Projective::generator();

    // ------------------------------------------------------------------
    // Psi_V_G1 for public inputs (variables 0 and 1), divided by gamma
    // ------------------------------------------------------------------
    println!("--- Psi_V_G1 accumulation ---");
    let mut v = G1Projective::zero();
    for i in 0..2 {
        let u_tau = us[i].evaluate(&tau);
        let v_tau = vs[i].evaluate(&tau);
        let w_tau = ws[i].evaluate(&tau);
        let psi_scalar = (v_tau * alpha + u_tau * beta + w_tau) * gamma_inv;
        let pt = g1_proj * psi_scalar;
        let weighted = pt * witness[i];
        v += weighted;
        println!("Variable {}: a_i = {}, psi_scalar = {}, contribution scalar = {}",
                 i, witness[i], psi_scalar, psi_scalar * witness[i]);
    }

    let v_affine = G1Affine::from(v);
    println!("\nV = sum(a_i * Psi_V_G1)");
    println!("  x = {}", v_affine.x);
    println!("  y = {}", v_affine.y);

    // Sanity: compute total scalar directly
    let mut total_scalar = Fr::zero();
    for i in 0..2 {
        let u_tau = us[i].evaluate(&tau);
        let v_tau = vs[i].evaluate(&tau);
        let w_tau = ws[i].evaluate(&tau);
        total_scalar += (v_tau * alpha + u_tau * beta + w_tau) * gamma_inv * witness[i];
    }
    println!("\nTotal combined scalar = {}", total_scalar);
    let direct = G1Affine::from(g1_proj * total_scalar);
    assert_eq!(v_affine, direct, "V must equal total_scalar * G1");

    println!("\n✓ Public-input commitment V computed and verified.");
    println!("✓ Step 1.15 printouts complete.");
}
