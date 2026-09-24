//! Lagrange-basis h-SRS for the FFT proving path (item (p)).
//!
//! The `h`-commitment of Groth16 is the group element `δ⁻¹·h(τ)·T(τ)·G1`.
//! Two SRS representations can deliver it:
//!
//! - **Monomial ("power") basis** (the classical layout, this crate's
//!   `FullProvingKey::h_query`): the prover extracts the *coefficients* of
//!   `h(x)` (a polynomial division over the domain — the "monomial
//!   conversion"), then folds them against `τ^j·T(τ)·δ⁻¹·G1`.
//! - **Coset-Lagrange basis** (this module, the production FFT pattern):
//!   the SRS stores `Q_j = δ⁻¹·T(τ)·L_j^{(c)}(τ)·G1` for the `N` points of
//!   a coset `c·⟨ω⟩`. Because `deg h < N`, `h` is fixed by its values on the
//!   coset and
//!
//!   ```text
//!   δ⁻¹·T(τ)·h(τ) = Σ_j h(c·ω^j)·Q_j ,
//!   ```
//!
//!   with `h(c·ω^j) = P(c·ω^j) / T(c·ω^j)` and `T(c·ω^j) = c^N − 1` constant
//!   on the coset (`P = l·r − o`). No quotient coefficients are ever
//!   materialised, so the prover path needs no `h` IFFT/division — it
//!   evaluates the witness polynomials on the coset, divides pointwise by the
//!   constant `T`, and folds the resulting values with a single MSM.
//!
//! Point ordering follows `EvaluationDomain::elements()`, i.e. the exact same
//! ordering `fft_in_place` emits, so the coset values and the SRS points line
//! up no matter how a backend permutes the group elements internally.

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{Field, One, Zero};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain};
use ark_std::vec::Vec;

/// A Lagrange-basis `h`-SRS: the `N` coset-Lagrange points
/// `Q_j = δ⁻¹·T(τ)·L_j^{(c)}(τ)·G1`.
pub struct LagrangeHQuery {
    /// The coset scaling factor `c` (an element outside `⟨ω⟩`).
    pub coset: Fr,
    /// The domain size `N`.
    pub n_domain: usize,
    /// The `N` group points used to fold `h`'s coset values (indexed in
    /// `EvaluationDomain::elements()` order).
    pub points: Vec<G1Affine>,
}

/// Pick a small field element `c` that is **not** an `N`-th root of unity,
/// i.e. `c^N ≠ 1`, so that `c·⟨ω⟩` is a distinct coset (so the interpolation
/// of `h` from its coset values is always well-defined).
pub fn coset_factor(domain_size: usize) -> Fr {
    let n = domain_size as u64;
    let mut c = Fr::from(2u64);
    loop {
        if c.pow([n]) != Fr::one() {
            return c;
        }
        c += Fr::one();
    }
}

/// Build the coset-Lagrange `h`-query from the ceremony scalars.
///
/// Closed form (with `z(x) = x^N − c^N` the coset vanishing polynomial):
///
/// ```text
/// Q_j = δ⁻¹·T(τ)·L_j^{(c)}(τ)·G1
/// where L_j^{(c)}(τ) = c·ω^j·(τ^N − c^N) / (N·c^N·(τ − c·ω^j))
/// ```
///
/// The `N` denominators `τ − c·ω^j` are inverted with a single
/// batch-inversion pass.
pub fn build_lagrange_h_query(n_domain: usize, tau: Fr, delta: Fr) -> LagrangeHQuery {
    assert!(n_domain >= 1 && n_domain.is_power_of_two(), "domain size must be a power of two");

    let domain = GeneralEvaluationDomain::<Fr>::new(n_domain)
        .expect("Failed to create evaluation domain");
    // The domain's canonical element order — matches fft_in_place output.
    let points_order: Vec<Fr> = domain.elements().collect();
    let n = n_domain as u64;

    // Pick a coset that avoids the degenerate cases: c^N ≠ 1 (outside the
    // subgroup) AND c^N ≠ τ^N (τ not on the coset, so all denominators
    // τ − c·ω^j are non-zero and the Lagrange interpolation is regular).
    let tau_pow_n = tau.pow([n]);
    let mut c = Fr::from(2u64);
    loop {
        let c_pow_n = c.pow([n]);
        if c_pow_n != Fr::one() && c_pow_n != tau_pow_n {
            break;
        }
        c += Fr::one();
    }

    let c_pow_n = c.pow([n]);
    // T(τ) = τ^N − 1 and A = τ^N − c^N.
    let t_tau = tau_pow_n - Fr::one();
    let a = tau_pow_n - c_pow_n;
    // Q_j scalar = c·ω^j · S / (τ − c·ω^j), with S = δ⁻¹·T(τ)·A·(N·c^N)⁻¹.
    let s = delta.inverse().unwrap()
        * t_tau
        * a
        * (Fr::from(n) * c_pow_n).inverse().unwrap();

    let g1 = G1Projective::from(G1Affine::generator());

    // Denominators τ − c·ω^j, batch-inverted.
    let mut denominators: Vec<Fr> = points_order.iter().map(|w| tau - c * w).collect();
    batch_invert(&mut denominators);

    let mut points = Vec::with_capacity(n_domain);
    for (j, w) in points_order.iter().enumerate() {
        let scalar = c * w * s * denominators[j];
        points.push(G1Affine::from(g1 * scalar));
    }

    LagrangeHQuery {
        coset: c,
        n_domain,
        points,
    }
}

/// Fold the witness polynomials into `h`'s values on the coset:
///
/// ```text
/// h(c·ω^j) = P(c·ω^j) / T(c·ω^j),  T(c·ω^j) = c^N − 1.
/// ```
///
/// `l, r, o` arrive in **coefficient** form (as produced by
/// [`crate::engine::build_witness_polys_sparse`]); the coset evaluation is
/// done with one FFT per wire polynomial on the `c`-scaled coefficients.
/// The returned vector is indexed like the SRS `points` (elements order).
pub fn h_coset_values(
    domain: &GeneralEvaluationDomain<Fr>,
    l_poly: &DensePolynomial<Fr>,
    r_poly: &DensePolynomial<Fr>,
    o_poly: &DensePolynomial<Fr>,
    coset: Fr,
) -> Vec<Fr> {
    let n = domain.size();
    let mut l_scale = padded_coeffs(l_poly, n);
    let mut r_scale = padded_coeffs(r_poly, n);
    let mut o_scale = padded_coeffs(o_poly, n);

    scale_by_coset_powers(&mut l_scale, coset);
    scale_by_coset_powers(&mut r_scale, coset);
    scale_by_coset_powers(&mut o_scale, coset);

    // FFT of f(c·x) at ω^j yields f(c·ω^j), in the domain element order.
    domain.fft_in_place(&mut l_scale);
    domain.fft_in_place(&mut r_scale);
    domain.fft_in_place(&mut o_scale);

    // T is constant on the coset: T(c·ω^j) = c^N − 1.
    let t_coset = coset.pow([n as u64]) - Fr::one();
    let t_coset_inv = t_coset.inverse().unwrap();

    (0..n)
        .map(|j| (l_scale[j] * r_scale[j] - o_scale[j]) * t_coset_inv)
        .collect()
}

/// Compute the full `h`-commitment `δ⁻¹·h(τ)·T(τ)·G1` straight from the
/// coset values — one MSM over the Lagrange-basis SRS, no quotient needed.
pub fn h_commitment_lagrange(
    domain: &GeneralEvaluationDomain<Fr>,
    query: &LagrangeHQuery,
    l_poly: &DensePolynomial<Fr>,
    r_poly: &DensePolynomial<Fr>,
    o_poly: &DensePolynomial<Fr>,
) -> G1Projective {
    let evals = h_coset_values(domain, l_poly, r_poly, o_poly, query.coset);
    G1Projective::msm(&query.points, &evals).expect("h-coset MSM length mismatch")
}

/// Pad a polynomial's coefficient vector to exactly `n` entries.
fn padded_coeffs(poly: &DensePolynomial<Fr>, n: usize) -> Vec<Fr> {
    let mut coeffs = poly.coeffs.clone();
    coeffs.resize(n, Fr::zero());
    coeffs
}

/// Multiply coefficient `j` by `c^j` — equivalent to transforming `f(x)`
/// into `f(c·x)`, whose FFT at the roots gives `f`'s evals on `c·⟨ω⟩`.
fn scale_by_coset_powers(coeffs: &mut [Fr], c: Fr) {
    let mut pow = Fr::one();
    for coeff in coeffs.iter_mut() {
        *coeff *= pow;
        pow *= c;
    }
}

/// Invert all elements in place with a single field inversion (Montgomery
/// batch inversion). Caller ensures no zero denominators.
fn batch_invert(vals: &mut [Fr]) {
    let n = vals.len();
    if n == 0 {
        return;
    }
    let mut prefix = Vec::with_capacity(n);
    let mut acc = Fr::one();
    for v in vals.iter() {
        acc *= *v;
        prefix.push(acc);
    }
    let mut inv = prefix[n - 1].inverse().unwrap();
    for i in (0..n).rev() {
        let v = vals[i];
        vals[i] = inv * if i == 0 { Fr::one() } else { prefix[i - 1] };
        inv *= v;
    }
}

// ------------------------------------------------------------------
// Verus specifications (bounds & structural invariants)
// ------------------------------------------------------------------

#[cfg(feature = "verus")]
use vstd::prelude::*;

#[cfg(feature = "verus")]
verus! {

    /// Spec: [`padded_coeffs`] returns a vector of exactly `n` elements.
    #[verifier::external_body]
    pub fn spec_padded_coeffs(poly: &DensePolynomial<Fr>, n: usize) -> (r: Vec<Fr>)
        ensures r.len() == n
    {
        padded_coeffs(poly, n)
    }

    /// Spec: [`scale_by_coset_powers`] preserves slice length.
    #[verifier::external_body]
    pub fn spec_scale_by_coset_powers(coeffs: &mut [Fr], c: Fr)
        ensures coeffs.len() == old(coeffs).len()
    {
        scale_by_coset_powers(coeffs, c)
    }

    /// Spec: [`batch_invert`] preserves slice length and is a no-op for empty input.
    #[verifier::external_body]
    pub fn spec_batch_invert(vals: &mut [Fr])
        ensures vals.len() == old(vals).len()
    {
        batch_invert(vals)
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::build_witness_polys_sparse;
    use crate::r1cs::random_sparse_r1cs_circuit;
    use ark_ff::UniformRand;
    use ark_poly::{DenseUVPolynomial, Polynomial};
    use rand::RngCore;

    /// A tiny deterministic RNG so the fixture tests are reproducible.
    #[derive(Clone)]
    struct XorShiftRng(u64);
    impl XorShiftRng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
    }
    impl RngCore for XorShiftRng {
        fn next_u32(&mut self) -> u32 {
            self.next() as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.next()
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    fn sparse(dense: &[Vec<Fr>]) -> Vec<Vec<(u32, Fr)>> {
        dense
            .iter()
            .map(|row| {
                row.iter()
                    .enumerate()
                    .filter_map(|(i, &v)| if v.is_zero() { None } else { Some((i as u32, v)) })
                    .collect()
            })
            .collect()
    }

    #[test]
    fn test_coset_factor_not_in_subgroup() {
        for n in [4usize, 8, 16, 32] {
            let c = coset_factor(n);
            assert_ne!(c.pow([n as u64]), Fr::one(), "c must be outside ⟨ω⟩ for N={n}");
        }
    }

    #[test]
    fn test_lagrange_points_match_closed_form() {
        let n_domain = 16usize;
        let tau = Fr::from(3u64);
        let delta = Fr::from(13u64);
        let domain = GeneralEvaluationDomain::<Fr>::new(n_domain).unwrap();
        let order: Vec<Fr> = domain.elements().collect();
        let query = build_lagrange_h_query(n_domain, tau, delta);
        let c = query.coset;
        let c_pow_n = c.pow([n_domain as u64]);
        let tau_pow_n = tau.pow([n_domain as u64]);
        let t_tau = tau_pow_n - Fr::one();
        let a = tau_pow_n - c_pow_n;
        let s =
            delta.inverse().unwrap() * t_tau * a * (Fr::from(n_domain as u64) * c_pow_n).inverse().unwrap();

        let g1 = G1Projective::from(G1Affine::generator());
        for (j, w) in order.iter().enumerate() {
            let scalar = c * w * s * (tau - c * w).inverse().unwrap();
            assert_eq!(
                query.points[j],
                G1Affine::from(g1 * scalar),
                "Q_{j} must match the closed form"
            );
        }
    }

    #[test]
    fn test_h_coset_values_match_direct_evaluation() {
        let n_domain = 16usize;
        let domain = GeneralEvaluationDomain::<Fr>::new(n_domain).unwrap();
        let order: Vec<Fr> = domain.elements().collect();
        let mut rng = rand::thread_rng();
        let c = Fr::from(2u64);

        // Random degree-<N witness-shaped polynomials.
        let lp = DensePolynomial::from_coefficients_vec(vec![Fr::rand(&mut rng); 8]);
        let rp = DensePolynomial::from_coefficients_vec(vec![Fr::rand(&mut rng); 9]);
        let op = DensePolynomial::from_coefficients_vec(vec![Fr::rand(&mut rng); 6]);

        let evals = h_coset_values(&domain, &lp, &rp, &op, c);
        let t_coset = c.pow([n_domain as u64]) - Fr::one();
        let t_inv = t_coset.inverse().unwrap();

        for (j, w) in order.iter().enumerate() {
            let x = c * w;
            let expected = (lp.evaluate(&x) * rp.evaluate(&x) - op.evaluate(&x)) * t_inv;
            assert_eq!(evals[j], expected, "h(c·ω^{j}) mismatch");
        }
    }

    #[test]
    fn test_lagrange_commitment_matches_monomial_on_real_circuit() {
        // The Lagrange commitment must equal δ⁻¹·T(τ)·h(τ) built from the
        // *monomial* quotient h — two fully independent computations.
        let n_constraints = 5usize;
        let n_domain = 8usize;
        let domain = GeneralEvaluationDomain::<Fr>::new(n_domain).unwrap();
        let tau = Fr::from(3u64);
        let delta = Fr::from(13u64);

        let mut rng = XorShiftRng(0xC0FFEE);
        let circuit = random_sparse_r1cs_circuit(&mut rng, n_constraints, 3);

        let (l_poly, r_poly, o_poly) = build_witness_polys_sparse(
            &domain,
            n_domain,
            n_constraints,
            &sparse(&circuit.l),
            &sparse(&circuit.r),
            &sparse(&circuit.o),
            &circuit.witness,
        );

        // Monomial reference: h = P / (x^N − 1) by exact division.
        let h_poly = quotient_by_roots_of_unity(&domain, &l_poly, &r_poly, &o_poly);
        let h_tau = h_poly.evaluate(&tau);
        let t_tau = tau.pow([n_domain as u64]) - Fr::one();
        let expected = G1Affine::from(
            G1Projective::from(G1Affine::generator())
                * (delta.inverse().unwrap() * t_tau * h_tau),
        );

        let query = build_lagrange_h_query(n_domain, tau, delta);
        let commit = h_commitment_lagrange(&domain, &query, &l_poly, &r_poly, &o_poly);
        assert_eq!(
            G1Affine::from(commit),
            expected,
            "Lagrange h-commitment must equal the monomial scalar δ⁻¹·T(τ)·h(τ)"
        );
    }

    /// `h = P / (x^N − 1)` from the true product polynomial `P = l·r − o`
    /// (not its root evaluations — those all vanish for a valid witness, so
    /// they'd only recover `P mod (x^N − 1) = 0`).
    fn quotient_by_roots_of_unity(
        domain: &GeneralEvaluationDomain<Fr>,
        l: &DensePolynomial<Fr>,
        r: &DensePolynomial<Fr>,
        o: &DensePolynomial<Fr>,
    ) -> DensePolynomial<Fr> {
        use crate::engine::poly_sub;

        let prod = l.naive_mul(r);
        let numerator = poly_sub(&prod, o);
        let (h, remainder) = numerator
            .divide_by_vanishing_poly(*domain)
            .expect("Division by vanishing polynomial failed");
        assert!(remainder.is_zero(), "P must vanish on the whole domain for a valid witness");
        h
    }
}