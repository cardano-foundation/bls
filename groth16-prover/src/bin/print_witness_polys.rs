use ark_bls12_381::Fr;
use ark_ff::{One, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, Polynomial};
use groth16_prover::qap::build_qap_polynomials;
use groth16_prover::r1cs::{L, R, O, WITNESS};

/// Multiply a polynomial by a scalar field element.
fn poly_scalar_mul(poly: &DensePolynomial<Fr>, scalar: Fr) -> DensePolynomial<Fr> {
    let coeffs: Vec<Fr> = poly.coeffs.iter().map(|c| *c * scalar).collect();
    let mut result = DensePolynomial::from_coefficients_vec(coeffs);
    normalize(&mut result);
    result
}

/// Normalize a polynomial by trimming trailing zero coefficients.
fn normalize(poly: &mut DensePolynomial<Fr>) {
    while poly.coeffs.last().map_or(false, |c| c.is_zero()) {
        poly.coeffs.pop();
    }
    if poly.coeffs.is_empty() {
        poly.coeffs.push(Fr::zero());
    }
}

/// Add two polynomials.
fn poly_add(a: &DensePolynomial<Fr>, b: &DensePolynomial<Fr>) -> DensePolynomial<Fr> {
    let mut result = a.clone();
    result += b;
    normalize(&mut result);
    result
}

fn main() {
    println!("=== Step 1.10: Witness Polynomials l(x), r(x), o(x) ===\n");

    let (us, vs, ws) = build_qap_polynomials(&L, &R, &O);
    let witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();

    // l(x) = sum a_i * u_i(x)
    let mut l = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    for i in 0..witness.len() {
        let term = poly_scalar_mul(&us[i], witness[i]);
        l = poly_add(&l, &term);
    }

    // r(x) = sum a_i * v_i(x)
    let mut r = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    for i in 0..witness.len() {
        let term = poly_scalar_mul(&vs[i], witness[i]);
        r = poly_add(&r, &term);
    }

    // o(x) = sum a_i * w_i(x)
    let mut o = DensePolynomial::from_coefficients_vec(vec![Fr::zero()]);
    for i in 0..witness.len() {
        let term = poly_scalar_mul(&ws[i], witness[i]);
        o = poly_add(&o, &term);
    }

    println!("Witness a = {:?}", WITNESS);
    println!();
    println!("l(x) degree = {}, coeffs = {:?}", l.degree(),
             l.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    println!("r(x) degree = {}, coeffs = {:?}", r.degree(),
             r.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    println!("o(x) degree = {}, coeffs = {:?}", o.degree(),
             o.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());

    // Sanity check: evaluate at constraint points x = 0, 1, 2
    let xs = [Fr::zero(), Fr::one(), Fr::from(2u64)];
    println!("\nEvaluation at constraint points:");
    for (j, x) in xs.iter().enumerate() {
        let l_val = l.evaluate(x);
        let r_val = r.evaluate(x);
        let o_val = o.evaluate(x);
        println!("  x = {}: l(x) = {}, r(x) = {}, o(x) = {}", j, l_val, r_val, o_val);

        // Check: l(x) * r(x) == o(x) at constraint points
        assert_eq!(l_val * r_val, o_val,
                   "l({}) * r({}) != o({})", j, j, j);
    }
    println!("\n✓ l(x)*r(x) == o(x) at all constraint points.");
    println!("✓ Step 1.10 printouts complete.");
}
