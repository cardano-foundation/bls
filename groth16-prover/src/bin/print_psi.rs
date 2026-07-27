use ark_bls12_381::{G1Affine, G1Projective, Fr};
use ark_ec::{AffineRepr, Group};
use ark_ff::Field;
use ark_poly::Polynomial;
use groth16_prover::qap::build_qap_polynomials_circuit;
use groth16_prover::r1cs::select_circuit;

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: print_psi <multiplier|sumofproducts>");
        std::process::exit(1);
    });
    let circuit = select_circuit(&name);

    println!("=== Step 1.9: Per-Variable CRS ===\n");
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

    let n_public = circuit.n_public;
    let n_vars = circuit.n_vars();

    println!(
        "tau = {}, alpha = {}, beta = {}, gamma = {}, delta = {}\n",
        tau, alpha, beta, gamma, delta
    );

    // ------------------------------------------------------------------
    // Psi_V_G1 : public inputs, divided by gamma
    // ------------------------------------------------------------------
    println!("--- Psi_V_G1 (public inputs, divided by gamma) ---");
    for i in 0..n_public {
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
    // Psi_P_G1 : private inputs, divided by delta
    // ------------------------------------------------------------------
    println!("\n--- Psi_P_G1 (private inputs, divided by delta) ---");
    for i in n_public..n_vars {
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

    println!();
    println!("✓ Step 1.9 printouts complete.");
}
