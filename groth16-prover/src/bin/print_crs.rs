use ark_bls12_381::{G1Affine, G2Affine, G1Projective, G2Projective, Fr};
use ark_ec::Group;

fn main() {
    println!("=== Step 1.8: CRS Fixed Points ===\n");

    // Fixed deterministic toxic waste (same as Step 1.6)
    let alpha = Fr::from(5u64);
    let beta  = Fr::from(7u64);
    let gamma = Fr::from(11u64);
    let delta = Fr::from(13u64);

    let g1_proj = G1Projective::generator();
    let g2_proj = G2Projective::generator();

    // ------------------------------------------------------------------
    // alpha * G1
    // ------------------------------------------------------------------
    let alpha_g1 = G1Affine::from(g1_proj * alpha);
    println!("--- alpha * G1 ---");
    println!("scalar = alpha = {}", alpha);
    println!("x = {}", alpha_g1.x);
    println!("y = {}", alpha_g1.y);

    // ------------------------------------------------------------------
    // beta * G2
    // ------------------------------------------------------------------
    let beta_g2 = G2Affine::from(g2_proj * beta);
    println!("\n--- beta * G2 ---");
    println!("scalar = beta = {}", beta);
    println!("x = {}", beta_g2.x);
    println!("y = {}", beta_g2.y);

    // ------------------------------------------------------------------
    // gamma * G2
    // ------------------------------------------------------------------
    let gamma_g2 = G2Affine::from(g2_proj * gamma);
    println!("\n--- gamma * G2 ---");
    println!("scalar = gamma = {}", gamma);
    println!("x = {}", gamma_g2.x);
    println!("y = {}", gamma_g2.y);

    // ------------------------------------------------------------------
    // delta * G2
    // ------------------------------------------------------------------
    let delta_g2 = G2Affine::from(g2_proj * delta);
    println!("\n--- delta * G2 ---");
    println!("scalar = delta = {}", delta);
    println!("x = {}", delta_g2.x);
    println!("y = {}", delta_g2.y);

    // Sanity check: alpha*G1 is a valid point on G1
    assert!(alpha_g1.is_on_curve(), "alpha*G1 must be on the curve");
    assert!(alpha_g1.is_in_correct_subgroup_assuming_on_curve(),
            "alpha*G1 must be in the correct subgroup");
    assert!(beta_g2.is_on_curve(), "beta*G2 must be on the curve");
    assert!(gamma_g2.is_on_curve(), "gamma*G2 must be on the curve");
    assert!(delta_g2.is_on_curve(), "delta*G2 must be on the curve");

    println!("\n✓ CRS fixed-point sanity checks passed.");
    println!("✓ Step 1.8 printouts complete.");
}
