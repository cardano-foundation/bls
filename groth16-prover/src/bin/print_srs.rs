use ark_bls12_381::{G1Affine, G2Affine, G1Projective, G2Projective, Fr};
use ark_ec::{AffineRepr, Group};
use ark_ff::{Field, One};
use ark_poly::Polynomial;
use groth16_prover::engine::{DenseQapEngine, QapEngine};
use groth16_prover::r1cs::select_circuit;

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: print_srs <multiplier|sumofproducts>");
        std::process::exit(1);
    });
    let circuit = select_circuit(&name);

    println!("=== Step 1.7: SRS Points ===\n");
    println!("Circuit: {}", circuit.name);

    let tau   = match circuit.name {
        "multiplier" => Fr::from(3u64),
        _            => Fr::from(6u64),
    };
    let delta = Fr::from(13u64);

    let engine = DenseQapEngine::new();
    let n_constraints = circuit.n_constraints();
    let t_poly = engine.target_poly(n_constraints);
    let t_tau = t_poly.evaluate(&tau);
    println!("T(tau) = {}  (tau = {})", t_tau, tau);

    let n = n_constraints;

    // Use projective generators so scalar mul returns Projective
    let g1_proj = G1Projective::generator();
    let g2_proj = G2Projective::generator();

    // ------------------------------------------------------------------
    // SRS1 : G1 * tau^i
    // ------------------------------------------------------------------
    println!("\n--- SRS1 : G1 * tau^i ---");
    for i in 0..n {
        let scalar = tau.pow(&[i as u64]);
        let pt = g1_proj * scalar;
        let affine = G1Affine::from(pt);
        println!("SRS1[{}] scalar = tau^{} = {}", i, i, scalar);
        println!("         x = {}", affine.x);
        println!("         y = {}", affine.y);
    }

    // ------------------------------------------------------------------
    // SRS2 : G2 * tau^i
    // ------------------------------------------------------------------
    println!("\n--- SRS2 : G2 * tau^i ---");
    for i in 0..n {
        let scalar = tau.pow(&[i as u64]);
        let pt = g2_proj * scalar;
        let affine = G2Affine::from(pt);
        println!("SRS2[{}] scalar = tau^{} = {}", i, i, scalar);
        println!("         x = {}", affine.x);
        println!("         y = {}", affine.y);
    }

    // ------------------------------------------------------------------
    // SRS3 : G1 * T(tau) * tau^i / delta
    // ------------------------------------------------------------------
    println!("\n--- SRS3 : G1 * T(tau) * tau^i / delta ---");
    let delta_inv = delta.inverse().unwrap();
    let base_scalar = t_tau * delta_inv;
    println!("Base scalar = T(tau)/delta = {}", base_scalar);
    for i in 0..(n - 1) {
        let scalar = base_scalar * tau.pow(&[i as u64]);
        let pt = g1_proj * scalar;
        let affine = G1Affine::from(pt);
        println!("SRS3[{}] scalar = T(tau)*tau^{}/delta = {}", i, i, scalar);
        println!("         x = {}", affine.x);
        println!("         y = {}", affine.y);
    }

    // Sanity checks
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    assert_eq!(G1Affine::from(g1_proj * Fr::one()), g1,
               "SRS1[0] must be the G1 generator");
    assert_eq!(G2Affine::from(g2_proj * Fr::one()), g2,
               "SRS2[0] must be the G2 generator");
    println!("\n✓ SRS sanity checks passed.");
    println!("✓ Step 1.7 printouts complete.");
}
