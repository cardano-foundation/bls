use groth16_prover::qap::{build_qap_polynomials_circuit, build_target_polynomial, print_poly};
use groth16_prover::r1cs::select_circuit;

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: print_qap <multiplier|sumofproducts>");
        std::process::exit(1);
    });
    let circuit = select_circuit(&name);

    println!("=== Step 1.3: QAP Polynomial Interpolation ===\n");
    println!("Circuit: {}", circuit.name);

    let (us, vs, ws) = build_qap_polynomials_circuit(&circuit);

    for i in 0..us.len() {
        print_poly(&format!("u_{}", i), &us[i]);
    }
    println!();
    for i in 0..vs.len() {
        print_poly(&format!("v_{}", i), &vs[i]);
    }
    println!();
    for i in 0..ws.len() {
        print_poly(&format!("w_{}", i), &ws[i]);
    }

    println!("\n✓ Step 1.3 coefficient printouts complete.");

    // ------------------------------------------------------------------------
    // Step 1.5 explicit verification: QAP polynomials reproduce R1CS columns
    // ------------------------------------------------------------------------
    println!("\n=== Step 1.5: QAP Verification at Constraint Points ===\n");

    use ark_bls12_381::Fr;
    use ark_poly::Polynomial;

    let n_constraints = circuit.n_constraints();
    let n_vars = circuit.n_vars();
    let xs: Vec<Fr> = (0..n_constraints as u64).map(Fr::from).collect();
    for j in 0..n_constraints {
        let x = xs[j];
        for i in 0..n_vars {
            let u_val = us[i].evaluate(&x);
            let v_val = vs[i].evaluate(&x);
            let w_val = ws[i].evaluate(&x);
            let expected_l = circuit.l[j][i];
            let expected_r = circuit.r[j][i];
            let expected_o = circuit.o[j][i];

            assert_eq!(u_val, expected_l, "u_{}({}) mismatch", i, j);
            assert_eq!(v_val, expected_r, "v_{}({}) mismatch", i, j);
            assert_eq!(w_val, expected_o, "w_{}({}) mismatch", i, j);
        }
        println!("  x = {}: all u_i, v_i, w_i match L, R, O columns", j);
    }

    println!("\n✓ All {} evaluations ({} variables × {} points) pass.",
             n_vars * n_constraints, n_vars, n_constraints);

    // ------------------------------------------------------------------------
    // Step 1.4 explicit printouts for cross-checking with Sage
    // ------------------------------------------------------------------------
    println!("\n=== Step 1.4: Target Polynomial T(x) ===\n");

    let t = build_target_polynomial(&xs);
    print_poly("T", &t);

    println!("\nT(x) vanishes at all constraint points:");
    for j in 0..n_constraints {
        let val = t.evaluate(&xs[j]);
        let s = val.to_string();
        let display = if s.is_empty() { "0" } else { &s };
        println!("  T({}) = {}", j, display);
        assert_eq!(val, Fr::from(0u64), "T({}) should be zero", j);
    }

    println!("\n✓ Target polynomial verified.");
}
