use ark_bls12_381::Fr;
use ark_ff::{Field, One, Zero};
use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial};
use ark_std::vec::Vec;

/// Trait abstracting over the two QAP construction strategies:
/// - `DenseQapEngine` — classical dense Lagrange (pedagogical, O(n²))
/// - `FftQapEngine` — FFT over roots of unity (production, O(N log N))
///
/// The trait is generic over the matrix element type `T` with `T: Copy + Into<Fr>`,
/// so it accepts both fixed-size arrays (`&[[u64; 8]]`) and dynamic vectors
/// (`&[Vec<Fr>]`). This lets the same engine work with hard-coded circuits
/// and Circom-generated R1CS files.
pub trait QapEngine {
    /// Build the QAP polynomials u_s(x), v_s(x), w_s(x) from R1CS matrices.
    fn build_qap<T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
        &self,
        l: &[L],
        r: &[R],
        o: &[O],
    ) -> (Vec<DensePolynomial<Fr>>, Vec<DensePolynomial<Fr>>, Vec<DensePolynomial<Fr>>);

    /// Return the evaluation domain size for the given number of constraints.
    /// For FFT engines this is next-power-of-2; for dense engines it equals n_constraints.
    fn domain_size(&self, num_constraints: usize) -> usize;

    /// Build the target polynomial T(x) that vanishes at all constraint points.
    fn target_poly(&self, num_constraints: usize) -> DensePolynomial<Fr>;

    /// Compute h(x) = (l(x)·r(x) − o(x)) / T(x).
    /// Returns the quotient polynomial (remainder must be zero for a valid witness).
    fn compute_quotient(
        &self,
        l: &DensePolynomial<Fr>,
        r: &DensePolynomial<Fr>,
        o: &DensePolynomial<Fr>,
        t: &DensePolynomial<Fr>,
    ) -> DensePolynomial<Fr>;

    /// Evaluate the per-variable QAP contributions at τ:
    ///   u_s(τ), v_s(τ), w_s(τ) for each wire s.
    ///
    /// In the dense path this evaluates each stored polynomial.
    /// In the FFT path this is a dot-product against Lagrange basis values.
    fn evaluate_qap_at_tau<T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
        &self,
        l: &[L],
        r: &[R],
        o: &[O],
        tau: Fr,
    ) -> (Vec<Fr>, Vec<Fr>, Vec<Fr>);
}

/// Dense Lagrange path — the original pedagogical implementation.
pub struct DenseQapEngine;

impl DenseQapEngine {
    pub fn new() -> Self {
        Self
    }
}

impl QapEngine for DenseQapEngine {
    fn build_qap<T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
        &self,
        l: &[L],
        r: &[R],
        o: &[O],
    ) -> (Vec<DensePolynomial<Fr>>, Vec<DensePolynomial<Fr>>, Vec<DensePolynomial<Fr>>) {
        let n_vars = l[0].as_ref().len();
        let n_constraints = l.len();
        assert_eq!(n_constraints, 3, "DenseQapEngine only supports 3 constraints");

        let mut us = Vec::with_capacity(n_vars);
        let mut vs = Vec::with_capacity(n_vars);
        let mut ws = Vec::with_capacity(n_vars);

        let two_inv = Fr::from(2u64).inverse().unwrap();

        for i in 0..n_vars {
            // u_i(x) from L column
            let y0_l = l[0].as_ref()[i].into();
            let y1_l = l[1].as_ref()[i].into();
            let y2_l = l[2].as_ref()[i].into();
            us.push(interpolate_3_points(y0_l, y1_l, y2_l, two_inv));

            // v_i(x) from R column
            let y0_r = r[0].as_ref()[i].into();
            let y1_r = r[1].as_ref()[i].into();
            let y2_r = r[2].as_ref()[i].into();
            vs.push(interpolate_3_points(y0_r, y1_r, y2_r, two_inv));

            // w_i(x) from O column
            let y0_o = o[0].as_ref()[i].into();
            let y1_o = o[1].as_ref()[i].into();
            let y2_o = o[2].as_ref()[i].into();
            ws.push(interpolate_3_points(y0_o, y1_o, y2_o, two_inv));
        }

        (us, vs, ws)
    }

    fn domain_size(&self, num_constraints: usize) -> usize {
        num_constraints
    }

    fn target_poly(&self, _num_constraints: usize) -> DensePolynomial<Fr> {
        // T(x) = (x - 0)(x - 1)(x - 2) = x³ - 3x² + 2x
        let points = [Fr::zero(), Fr::one(), Fr::from(2u64)];
        let mut result = DensePolynomial::from_coefficients_vec(vec![Fr::one()]);
        for &p in &points {
            let factor = DensePolynomial::from_coefficients_vec(vec![-p, Fr::one()]);
            result = result.naive_mul(&factor);
        }
        result
    }

    fn compute_quotient(
        &self,
        l: &DensePolynomial<Fr>,
        r: &DensePolynomial<Fr>,
        o: &DensePolynomial<Fr>,
        t: &DensePolynomial<Fr>,
    ) -> DensePolynomial<Fr> {
        let prod = l.naive_mul(r);
        let numerator = poly_sub(&prod, o);
        // Use ark-poly's Div trait: &numerator / t returns the quotient
        let q = &numerator / t;
        // Verify no remainder by checking q * T == numerator
        let check = q.naive_mul(t);
        assert_eq!(check, numerator, "Quotient verification failed: remainder is non-zero");
        q
    }

    fn evaluate_qap_at_tau<T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
        &self,
        l: &[L],
        r: &[R],
        o: &[O],
        tau: Fr,
    ) -> (Vec<Fr>, Vec<Fr>, Vec<Fr>) {
        let (us, vs, ws) = self.build_qap(l, r, o);
        let us_tau: Vec<Fr> = us.iter().map(|p| p.evaluate(&tau)).collect();
        let vs_tau: Vec<Fr> = vs.iter().map(|p| p.evaluate(&tau)).collect();
        let ws_tau: Vec<Fr> = ws.iter().map(|p| p.evaluate(&tau)).collect();
        (us_tau, vs_tau, ws_tau)
    }
}

/// FFT over roots of unity — the production-fast path.
pub struct FftQapEngine;

impl FftQapEngine {
    pub fn new() -> Self {
        Self
    }

    pub fn domain_size(num_constraints: usize) -> usize {
        let mut n = 1;
        while n < num_constraints {
            n <<= 1;
        }
        n
    }
}

impl QapEngine for FftQapEngine {
    fn domain_size(&self, num_constraints: usize) -> usize {
        Self::domain_size(num_constraints)
    }

    fn build_qap<T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
        &self,
        l: &[L],
        r: &[R],
        o: &[O],
    ) -> (Vec<DensePolynomial<Fr>>, Vec<DensePolynomial<Fr>>, Vec<DensePolynomial<Fr>>) {
        let n_vars = l[0].as_ref().len();
        let n_constraints = l.len();
        let domain_size = Self::domain_size(n_constraints);
        let domain = GeneralEvaluationDomain::<Fr>::new(domain_size)
            .expect("Failed to create evaluation domain");

        let mut us = Vec::with_capacity(n_vars);
        let mut vs = Vec::with_capacity(n_vars);
        let mut ws = Vec::with_capacity(n_vars);

        for i in 0..n_vars {
            // Build padded evaluations for column i of L
            let mut evals: Vec<Fr> = (0..domain_size)
                .map(|j| {
                    if j < n_constraints {
                        l[j].as_ref()[i].into()
                    } else {
                        Fr::zero()
                    }
                })
                .collect();
            domain.ifft_in_place(&mut evals);
            us.push(DensePolynomial::from_coefficients_vec(evals));

            // Same for R
            let mut evals: Vec<Fr> = (0..domain_size)
                .map(|j| {
                    if j < n_constraints {
                        r[j].as_ref()[i].into()
                    } else {
                        Fr::zero()
                    }
                })
                .collect();
            domain.ifft_in_place(&mut evals);
            vs.push(DensePolynomial::from_coefficients_vec(evals));

            // Same for O
            let mut evals: Vec<Fr> = (0..domain_size)
                .map(|j| {
                    if j < n_constraints {
                        o[j].as_ref()[i].into()
                    } else {
                        Fr::zero()
                    }
                })
                .collect();
            domain.ifft_in_place(&mut evals);
            ws.push(DensePolynomial::from_coefficients_vec(evals));
        }

        (us, vs, ws)
    }

    fn target_poly(&self, num_constraints: usize) -> DensePolynomial<Fr> {
        let domain_size = Self::domain_size(num_constraints);
        // T(x) = x^domain_size - 1
        let mut coeffs = vec![Fr::zero(); domain_size + 1];
        coeffs[0] = -Fr::one();
        coeffs[domain_size] = Fr::one();
        DensePolynomial::from_coefficients_vec(coeffs)
    }

    fn compute_quotient(
        &self,
        l: &DensePolynomial<Fr>,
        r: &DensePolynomial<Fr>,
        o: &DensePolynomial<Fr>,
        t: &DensePolynomial<Fr>,
    ) -> DensePolynomial<Fr> {
        let prod = l.naive_mul(r);
        let numerator = poly_sub(&prod, o);

        // T(x) = x^domain_size - 1, so its degree is the domain size
        let domain_size = t.degree();
        let domain = GeneralEvaluationDomain::<Fr>::new(domain_size)
            .expect("Failed to create evaluation domain");

        let (quotient, remainder) = numerator
            .divide_by_vanishing_poly(domain)
            .expect("Division by vanishing polynomial failed");

        assert!(remainder.is_zero(), "Quotient remainder must be zero");
        quotient
    }

    fn evaluate_qap_at_tau<T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
        &self,
        l: &[L],
        r: &[R],
        o: &[O],
        tau: Fr,
    ) -> (Vec<Fr>, Vec<Fr>, Vec<Fr>) {
        let n_constraints = l.len();
        let domain_size = Self::domain_size(n_constraints);
        let domain = GeneralEvaluationDomain::<Fr>::new(domain_size)
            .expect("Failed to create evaluation domain");

        // Compute all Lagrange basis evaluations at tau: L_0(tau), L_1(tau), ..., L_{N-1}(tau)
        let lagrange_at_tau = domain.evaluate_all_lagrange_coefficients(tau);

        let n_vars = l[0].as_ref().len();
        let mut us_tau = Vec::with_capacity(n_vars);
        let mut vs_tau = Vec::with_capacity(n_vars);
        let mut ws_tau = Vec::with_capacity(n_vars);

        for s in 0..n_vars {
            // u_s(tau) = sum_c L[c][s] * L_c(tau)
            let mut u = Fr::zero();
            let mut v = Fr::zero();
            let mut w = Fr::zero();
            for c in 0..n_constraints {
                let lc = lagrange_at_tau[c];
                u += l[c].as_ref()[s].into() * lc;
                v += r[c].as_ref()[s].into() * lc;
                w += o[c].as_ref()[s].into() * lc;
            }
            us_tau.push(u);
            vs_tau.push(v);
            ws_tau.push(w);
        }

        (us_tau, vs_tau, ws_tau)
    }
}

/// Lagrange interpolation for three points {0, 1, 2}.
fn interpolate_3_points(y0: Fr, y1: Fr, y2: Fr, two_inv: Fr) -> DensePolynomial<Fr> {
    let c0 = y0;
    let c1 = y0 * (-Fr::from(3u64) * two_inv)
           + y1 * Fr::from(2u64)
           - y2 * two_inv;
    let c2 = y0 * two_inv
           - y1
           + y2 * two_inv;

    DensePolynomial::from_coefficients_vec(vec![c0, c1, c2])
}

/// Polynomial addition.
pub fn poly_add(a: &DensePolynomial<Fr>, b: &DensePolynomial<Fr>) -> DensePolynomial<Fr> {
    let max_len = a.coeffs.len().max(b.coeffs.len());
    let mut coeffs = vec![Fr::zero(); max_len];
    for i in 0..a.coeffs.len() {
        coeffs[i] += a.coeffs[i];
    }
    for i in 0..b.coeffs.len() {
        coeffs[i] += b.coeffs[i];
    }
    DensePolynomial::from_coefficients_vec(coeffs)
}

/// Polynomial subtraction.
pub fn poly_sub(a: &DensePolynomial<Fr>, b: &DensePolynomial<Fr>) -> DensePolynomial<Fr> {
    let max_len = a.coeffs.len().max(b.coeffs.len());
    let mut coeffs = vec![Fr::zero(); max_len];
    for i in 0..a.coeffs.len() {
        coeffs[i] += a.coeffs[i];
    }
    for i in 0..b.coeffs.len() {
        coeffs[i] -= b.coeffs[i];
    }
    DensePolynomial::from_coefficients_vec(coeffs)
}

/// Multiply a polynomial by a scalar.
pub fn poly_scalar_mul(poly: &DensePolynomial<Fr>, scalar: Fr) -> DensePolynomial<Fr> {
    let coeffs: Vec<Fr> = poly.coeffs.iter().map(|&c| c * scalar).collect();
    DensePolynomial::from_coefficients_vec(coeffs)
}

/// Evaluate witness polynomials at τ using a QapEngine.
/// Returns (l(τ), r(τ), o(τ), h(τ), T(τ)) where h is the quotient.
pub fn evaluate_witness_and_quotient<E: QapEngine, T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
    engine: &E,
    l: &[L],
    r: &[R],
    o: &[O],
    witness: &[Fr],
    tau: Fr,
) -> (Fr, Fr, Fr, Fr, Fr) {
    let (us, vs, ws) = engine.build_qap(l, r, o);

    // Build l(x), r(x), o(x) as linear combinations
    let mut l_poly = DensePolynomial::zero();
    let mut r_poly = DensePolynomial::zero();
    let mut o_poly = DensePolynomial::zero();

    for i in 0..witness.len() {
        l_poly = poly_add(&l_poly, &poly_scalar_mul(&us[i], witness[i]));
        r_poly = poly_add(&r_poly, &poly_scalar_mul(&vs[i], witness[i]));
        o_poly = poly_add(&o_poly, &poly_scalar_mul(&ws[i], witness[i]));
    }

    let t = engine.target_poly(l.len());
    let h = engine.compute_quotient(&l_poly, &r_poly, &o_poly, &t);

    let l_tau = l_poly.evaluate(&tau);
    let r_tau = r_poly.evaluate(&tau);
    let o_tau = o_poly.evaluate(&tau);
    let h_tau = h.evaluate(&tau);
    let t_tau = t.evaluate(&tau);

    (l_tau, r_tau, o_tau, h_tau, t_tau)
}

// ------------------------------------------------------------------
// Sparse QAP helpers (Implementation 6)
// ------------------------------------------------------------------

/// Evaluate the per-variable QAP contributions at τ from **sparse** constraints.
///
/// Instead of materialising the full `u_i(x)` polynomials, we accumulate
/// `u_s(τ), v_s(τ), w_s(τ)` directly via the Lagrange basis:
///
///   `u_s(τ) = Σ_{c} L[c][s] · L_c(τ)`   (summed over non-zero entries only)
///
/// where `L_c(τ)` is the c-th Lagrange basis polynomial evaluated at τ.
///
/// Complexity: `O(#non_zero_entries)` field ops + `O(domain_size)` for Lagrange evals.
pub fn evaluate_qap_at_tau_sparse(
    n_vars: usize,
    n_constraints: usize,
    tau: Fr,
    sparse_l: &[Vec<(u32, Fr)>],
    sparse_r: &[Vec<(u32, Fr)>],
    sparse_o: &[Vec<(u32, Fr)>],
) -> (Vec<Fr>, Vec<Fr>, Vec<Fr>) {
    let domain_size = FftQapEngine::domain_size(n_constraints);
    let domain = GeneralEvaluationDomain::<Fr>::new(domain_size)
        .expect("Failed to create evaluation domain");

    // Compute all Lagrange basis evaluations at tau: L_0(tau), L_1(tau), ..., L_{N-1}(tau)
    let lagrange_at_tau = domain.evaluate_all_lagrange_coefficients(tau);

    let mut us_tau = vec![Fr::zero(); n_vars];
    let mut vs_tau = vec![Fr::zero(); n_vars];
    let mut ws_tau = vec![Fr::zero(); n_vars];

    for c in 0..n_constraints {
        let lc = lagrange_at_tau[c];
        for &(wire_id, coeff) in &sparse_l[c] {
            us_tau[wire_id as usize] += coeff * lc;
        }
        for &(wire_id, coeff) in &sparse_r[c] {
            vs_tau[wire_id as usize] += coeff * lc;
        }
        for &(wire_id, coeff) in &sparse_o[c] {
            ws_tau[wire_id as usize] += coeff * lc;
        }
    }

    (us_tau, vs_tau, ws_tau)
}

/// Build witness polynomials `l(x)`, `r(x)`, `o(x)` directly from **sparse**
/// constraints and a witness vector, without materialising the per-variable
/// QAP polynomials `u_i(x)`, `v_i(x)`, `w_i(x)`.
///
/// The trick: in the FFT domain the constraint points are the `domain_size`-th
/// roots of unity `ω^j`.  At each root `l(ω^j) = Σ_{(i, coeff) ∈ constraint j} w_i·coeff`.
/// We compute these evaluations in one sparse pass, then do **three** IFFTs
/// (one per wire polynomial) to get the coefficient forms.
///
/// Memory: `O(domain_size × 3)` for the three dense witness polynomials,
/// plus the already-held sparse constraint data.  No `O(n_vars × domain_size)`
/// dense-matrix allocation is needed.
pub fn build_witness_polys_sparse(
    domain: &GeneralEvaluationDomain<Fr>,
    domain_size: usize,
    n_constraints: usize,
    sparse_l: &[Vec<(u32, Fr)>],
    sparse_r: &[Vec<(u32, Fr)>],
    sparse_o: &[Vec<(u32, Fr)>],
    witness: &[Fr],
) -> (DensePolynomial<Fr>, DensePolynomial<Fr>, DensePolynomial<Fr>) {
    let mut l_evals = vec![Fr::zero(); domain_size];
    let mut r_evals = vec![Fr::zero(); domain_size];
    let mut o_evals = vec![Fr::zero(); domain_size];

    for j in 0..n_constraints {
        for &(wire_id, coeff) in &sparse_l[j] {
            l_evals[j] += witness[wire_id as usize] * coeff;
        }
        for &(wire_id, coeff) in &sparse_r[j] {
            r_evals[j] += witness[wire_id as usize] * coeff;
        }
        for &(wire_id, coeff) in &sparse_o[j] {
            o_evals[j] += witness[wire_id as usize] * coeff;
        }
    }

    // IFFT to get coefficient form
    domain.ifft_in_place(&mut l_evals);
    domain.ifft_in_place(&mut r_evals);
    domain.ifft_in_place(&mut o_evals);

    (
        DensePolynomial::from_coefficients_vec(l_evals),
        DensePolynomial::from_coefficients_vec(r_evals),
        DensePolynomial::from_coefficients_vec(o_evals),
    )
}

/// Sanity check: evaluate each QAP polynomial on the constraint points
/// and assert they match the original matrix entries.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::{L, R, O, WITNESS};
    use ark_std::Zero;

    #[test]
    fn test_dense_qap_matches_matrix() {
        let engine = DenseQapEngine::new();
        let (us, vs, ws) = engine.build_qap(&L, &R, &O);

        let xs = [Fr::zero(), Fr::one(), Fr::from(2u64)];
        for j in 0..3 {
            let x = xs[j];
            for i in 0..8 {
                assert_eq!(us[i].evaluate(&x), Fr::from(L[j][i]),
                    "Dense u_{}({}) mismatch", i, j);
                assert_eq!(vs[i].evaluate(&x), Fr::from(R[j][i]),
                    "Dense v_{}({}) mismatch", i, j);
                assert_eq!(ws[i].evaluate(&x), Fr::from(O[j][i]),
                    "Dense w_{}({}) mismatch", i, j);
            }
        }
    }

    #[test]
    fn test_fft_qap_matches_matrix_at_roots_of_unity() {
        let engine = FftQapEngine::new();
        let (us, vs, ws) = engine.build_qap(&L, &R, &O);

        let domain_size = FftQapEngine::domain_size(3);
        let domain = GeneralEvaluationDomain::<Fr>::new(domain_size).unwrap();
        let elements: Vec<Fr> = domain.elements().collect();

        // FFT QAP matches the matrix at the ROOTS OF UNITY, not at {0,1,2}
        for (j, &x) in elements.iter().enumerate().take(3) {
            for i in 0..8 {
                assert_eq!(us[i].evaluate(&x), Fr::from(L[j][i]),
                    "FFT u_{} at root {} mismatch", i, j);
                assert_eq!(vs[i].evaluate(&x), Fr::from(R[j][i]),
                    "FFT v_{} at root {} mismatch", i, j);
                assert_eq!(ws[i].evaluate(&x), Fr::from(O[j][i]),
                    "FFT w_{} at root {} mismatch", i, j);
            }
        }
    }

    #[test]
    fn test_fft_quotient_is_exact() {
        let engine = FftQapEngine::new();
        let witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();

        let (_, _, _, _, _) = evaluate_witness_and_quotient(&engine, &L, &R, &O, &witness, Fr::from(3u64));
        // evaluate_witness_and_quotient already asserts that the quotient
        // has zero remainder inside compute_quotient
    }

    #[test]
    fn test_dense_quotient_is_exact() {
        let engine = DenseQapEngine::new();
        let witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();

        let (_, _, _, _, _) = evaluate_witness_and_quotient(&engine, &L, &R, &O, &witness, Fr::from(3u64));
    }

    #[test]
    fn test_engines_produce_different_qap_at_tau() {
        // This test documents the EXPECTED difference between the two paths.
        // The dense path interpolates over {0,1,2}; the FFT path interpolates
        // over the 4-th roots of unity. Evaluating at the same tau=3 gives
        // DIFFERENT values, which is why proof coordinates do not match.
        let dense = DenseQapEngine::new();
        let fft = FftQapEngine::new();
        let tau = Fr::from(3u64);

        let (dense_u, _, _) = dense.evaluate_qap_at_tau(&L, &R, &O, tau);
        let (fft_u, _, _) = fft.evaluate_qap_at_tau(&L, &R, &O, tau);

        // Wire 2 (x1) should have DIFFERENT u_s(tau) values
        assert_ne!(dense_u[2], fft_u[2],
            "Dense and FFT u_2(tau) should differ because they use different QAP domains");
    }
}
