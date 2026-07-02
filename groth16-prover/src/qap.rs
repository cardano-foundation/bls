use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
use ark_std::{One, vec::Vec};

/// Lagrange interpolation for three fixed evaluation points x ∈ {0, 1, 2}.
/// Given values y0, y1, y2 returns the unique degree ≤ 2 polynomial p(x)
/// such that p(0)=y0, p(1)=y1, p(2)=y2.
pub fn interpolate_3_points(y0: Fr, y1: Fr, y2: Fr) -> DensePolynomial<Fr> {
    // Basis polynomials over xs = [0, 1, 2]:
    //   L0(x) = (x-1)(x-2)/2  = 1 - 3/2·x + 1/2·x^2
    //   L1(x) = x(x-2)/(-1)   = 0 + 2·x   - 1·x^2
    //   L2(x) = x(x-1)/2      = 0 - 1/2·x + 1/2·x^2
    let two_inv = Fr::from(2u64).inverse().unwrap();

    let c0 = y0;
    let c1 = y0 * (-Fr::from(3u64) * two_inv)
           + y1 * Fr::from(2u64)
           - y2 * two_inv;
    let c2 = y0 * two_inv
           - y1
           + y2 * two_inv;

    DensePolynomial::from_coefficients_vec(vec![c0, c1, c2])
}

/// Build the QAP polynomials u_i(x), v_i(x), w_i(x) by interpolating each
/// column of L, R, O over the evaluation points {0, 1, 2}.
pub fn build_qap_polynomials(
    l: &[[u64; 8]],
    r: &[[u64; 8]],
    o: &[[u64; 8]],
) -> (Vec<DensePolynomial<Fr>>, Vec<DensePolynomial<Fr>>, Vec<DensePolynomial<Fr>>) {
    let n_vars = l[0].len();
    let n_constraints = l.len();
    assert_eq!(n_constraints, 3, "only 3-point interpolation is supported");

    let mut us = Vec::with_capacity(n_vars);
    let mut vs = Vec::with_capacity(n_vars);
    let mut ws = Vec::with_capacity(n_vars);

    for i in 0..n_vars {
        let y0_l = Fr::from(l[0][i]);
        let y1_l = Fr::from(l[1][i]);
        let y2_l = Fr::from(l[2][i]);
        us.push(interpolate_3_points(y0_l, y1_l, y2_l));

        let y0_r = Fr::from(r[0][i]);
        let y1_r = Fr::from(r[1][i]);
        let y2_r = Fr::from(r[2][i]);
        vs.push(interpolate_3_points(y0_r, y1_r, y2_r));

        let y0_o = Fr::from(o[0][i]);
        let y1_o = Fr::from(o[1][i]);
        let y2_o = Fr::from(o[2][i]);
        ws.push(interpolate_3_points(y0_o, y1_o, y2_o));
    }

    (us, vs, ws)
}

/// Build the target polynomial T(x) = ∏(x - xi) for the given constraint points.
/// For points [0, 1, 2] this yields x³ - 3x² + 2x.
pub fn build_target_polynomial(points: &[Fr]) -> DensePolynomial<Fr> {
    let mut result = DensePolynomial::from_coefficients_vec(vec![Fr::one()]);
    for &p in points {
        let factor = DensePolynomial::from_coefficients_vec(vec![-p, Fr::one()]);
        result = result.naive_mul(&factor);
    }
    result
}

/// Pretty-print a polynomial with named coefficients.
/// arkworks 0.4 formats Fr::zero() as an empty string, so we remap it to "0".
pub fn print_poly(name: &str, poly: &DensePolynomial<Fr>) {
    let coeffs: Vec<String> = poly
        .coeffs
        .iter()
        .map(|c| {
            let s = c.to_string();
            if s.is_empty() {
                "0".to_string()
            } else {
                s
            }
        })
        .collect();
    println!("{} coeffs = {:?}", name, coeffs);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::{L, R, O};
    use ark_poly::Polynomial;
    use ark_std::{One, Zero};

    #[test]
    fn test_interpolation_reproduces_r1cs_columns() {
        let (us, vs, ws) = build_qap_polynomials(&L, &R, &O);

        let xs = [Fr::zero(), Fr::one(), Fr::from(2u64)];

        for j in 0..3 {
            let x = xs[j];
            for i in 0..8 {
                let expected_l = Fr::from(L[j][i]);
                let expected_r = Fr::from(R[j][i]);
                let expected_o = Fr::from(O[j][i]);

                assert_eq!(
                    us[i].evaluate(&x),
                    expected_l,
                    "u_{}({}) should equal L[{}][{}]",
                    i,
                    j,
                    j,
                    i
                );
                assert_eq!(
                    vs[i].evaluate(&x),
                    expected_r,
                    "v_{}({}) should equal R[{}][{}]",
                    i,
                    j,
                    j,
                    i
                );
                assert_eq!(
                    ws[i].evaluate(&x),
                    expected_o,
                    "w_{}({}) should equal O[{}][{}]",
                    i,
                    j,
                    j,
                    i
                );
            }
        }
    }

    #[test]
    fn test_interpolate_constant_column() {
        // Column [5, 5, 5] should interpolate to constant polynomial 5
        let poly = interpolate_3_points(Fr::from(5u64), Fr::from(5u64), Fr::from(5u64));
        assert_eq!(poly.degree(), 0);
        assert_eq!(poly.evaluate(&Fr::zero()), Fr::from(5u64));
        assert_eq!(poly.evaluate(&Fr::from(2u64)), Fr::from(5u64));
    }

    #[test]
    fn test_interpolate_linear_column() {
        // Column [0, 1, 2] should interpolate to p(x) = x
        let poly = interpolate_3_points(Fr::zero(), Fr::one(), Fr::from(2u64));
        assert_eq!(poly.evaluate(&Fr::zero()), Fr::zero());
        assert_eq!(poly.evaluate(&Fr::one()), Fr::one());
        assert_eq!(poly.evaluate(&Fr::from(2u64)), Fr::from(2u64));
    }

    #[test]
    fn test_target_polynomial() {
        let points = [Fr::zero(), Fr::one(), Fr::from(2u64)];
        let t = build_target_polynomial(&points);

        // T(x) = x(x-1)(x-2) = x³ - 3x² + 2x
        assert_eq!(t.degree(), 3);
        assert_eq!(t.evaluate(&Fr::zero()), Fr::zero());
        assert_eq!(t.evaluate(&Fr::one()), Fr::zero());
        assert_eq!(t.evaluate(&Fr::from(2u64)), Fr::zero());

        // Check coefficients: [0, 2, -3, 1]
        let expected = DensePolynomial::from_coefficients_vec(vec![
            Fr::zero(),
            Fr::from(2u64),
            -Fr::from(3u64),
            Fr::one(),
        ]);
        assert_eq!(t, expected);
    }

}
