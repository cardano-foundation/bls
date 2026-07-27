use ark_bls12_381::Fr;
use ark_ff::{One, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use groth16_prover::engine::{DenseQapEngine, QapEngine};
use groth16_prover::qap::build_qap_polynomials_circuit;
use groth16_prover::r1cs::select_circuit;

/// Multiply a polynomial by a scalar.
fn poly_scalar_mul(poly: &DensePolynomial<Fr>, scalar: Fr) -> DensePolynomial<Fr> {
    let coeffs: Vec<Fr> = poly.coeffs.iter().map(|c| *c * scalar).collect();
    let mut result = DensePolynomial::from_coefficients_vec(coeffs);
    normalize(&mut result);
    result
}

/// Add two polynomials.
fn poly_add(a: &DensePolynomial<Fr>, b: &DensePolynomial<Fr>) -> DensePolynomial<Fr> {
    let mut result = a.clone();
    result += b;
    normalize(&mut result);
    result
}

/// Subtract two polynomials.
fn poly_sub(a: &DensePolynomial<Fr>, b: &DensePolynomial<Fr>) -> DensePolynomial<Fr> {
    poly_add(a, &poly_scalar_mul(b, -Fr::one()))
}

/// Trim trailing zeros so degree() works correctly.
fn normalize(poly: &mut DensePolynomial<Fr>) {
    while poly.coeffs.last().map_or(false, |c| c.is_zero()) {
        poly.coeffs.pop();
    }
    if poly.coeffs.is_empty() {
        poly.coeffs.push(Fr::zero());
    }
}

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: print_quotient <multiplier|sumofproducts>");
        std::process::exit(1);
    });
    let circuit = select_circuit(&name);

    println!("=== Step 1.11: Quotient Polynomial h(x) ===\n");
    println!("Circuit: {}", circuit.name);

    let (us, vs, ws) = build_qap_polynomials_circuit(&circuit);

    // Build l(x), r(x), o(x)
    let mut l = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    let mut r = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    let mut o = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    for i in 0..circuit.n_vars() {
        l = poly_add(&l, &poly_scalar_mul(&us[i], circuit.witness[i]));
        r = poly_add(&r, &poly_scalar_mul(&vs[i], circuit.witness[i]));
        o = poly_add(&o, &poly_scalar_mul(&ws[i], circuit.witness[i]));
    }

    // Build T(x) using the engine
    let engine = DenseQapEngine::new();
    let n_constraints = circuit.n_constraints();
    let t = engine.target_poly(n_constraints);

    // Compute p(x) = l(x)*r(x) - o(x)
    let prod = l.naive_mul(&r);
    let p = poly_sub(&prod, &o);

    println!("l(x) degree = {}, coeffs = {:?}", l.degree(),
             l.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    println!("r(x) degree = {}, coeffs = {:?}", r.degree(),
             r.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    println!("o(x) degree = {}, coeffs = {:?}", o.degree(),
             o.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    println!("T(x) degree = {}, coeffs = {:?}", t.degree(),
             t.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    println!();
    println!("p(x) = l(x)*r(x) - o(x) degree = {}, coeffs = {:?}", p.degree(),
             p.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());

    // Compute quotient via the engine
    let h = engine.compute_quotient(&l, &r, &o, &t);
    println!("h(x) degree = {}, coeffs = {:?}", h.degree(),
             h.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());

    // Verify: p(x) == T(x) * h(x)
    let t_times_h = t.naive_mul(&h);
    println!("\nT(x) * h(x) degree = {}, coeffs = {:?}", t_times_h.degree(),
             t_times_h.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    assert_eq!(p, t_times_h, "p(x) must equal T(x) * h(x) — division has non-zero remainder!");

    println!("\n✓ p(x) == T(x) * h(x) — zero remainder confirmed.");
    println!("✓ Step 1.11 printouts complete.");
}
