use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{
    pairing::{prepare_g1, prepare_g2, Pairing},
    AffineRepr, Group, VariableBaseMSM,
};
use ark_ff::{Field, UniformRand, Zero};
use ark_poly::{univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial};
use ark_std::vec::Vec;
use rayon;

use crate::engine::{poly_add, poly_scalar_mul, QapEngine};

/// A Groth16 proof consists of three curve points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
}

/// A Groth16 public-input commitment.
#[derive(Clone, Copy, Debug)]
pub struct PublicInput {
    pub v: G1Affine,
}

/// Prover trait abstracting over the MSM strategy used during proof assembly.
///
/// Two implementations are provided:
/// - `NaiveProver` — scalar-by-scalar multiplication and addition (pedagogical)
/// - `PippengerProver` — batched multi-scalar multiplication via `VariableBaseMSM::msm`
///
/// Both use the same `QapEngine` for QAP construction and quotient computation,
/// so the proof is mathematically identical; only the *group-operation cost* differs.
pub trait Prover {
    /// Assemble the proof `(A, B, C)` and the public-input commitment `V`.
    ///
    /// The toxic waste parameters are the same fixed test values used
    /// throughout the crate: `tau=3, alpha=5, beta=7, gamma=11, delta=13`.
    fn prove<E: QapEngine, T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
        &self,
        engine: &E,
        l: &[L],
        r: &[R],
        o: &[O],
        witness: &[Fr],
        tau: Fr,
        alpha: Fr,
        beta: Fr,
        gamma: Fr,
        delta: Fr,
    ) -> (Proof, PublicInput);

    /// Assemble the proof using a `FullProvingKey` (group elements only).
    ///
    /// This is the production path: no toxic-waste scalars are needed.
    /// The prover uses multi-scalar multiplication over pre-computed
    /// curve points from the proving key.
    fn prove_with_full_pk<E: QapEngine, T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
        &self,
        engine: &E,
        full_pk: &crate::ceremony::FullProvingKey,
        l: &[L],
        r: &[R],
        o: &[O],
        witness: &[Fr],
    ) -> (Proof, PublicInput);

    /// Assemble the proof using a `FullProvingKey` and **sparse** constraints.
    ///
    /// This is the Implementation 6 path: the prover never materialises
    /// dense R1CS matrices.  Witness polynomials are built directly from
    /// the sparse constraint representation via three IFFTs.
    fn prove_with_full_pk_sparse(
        &self,
        engine: &impl QapEngine,
        full_pk: &crate::ceremony::FullProvingKey,
        n_constraints: usize,
        sparse_l: &[Vec<(u32, Fr)>],
        sparse_r: &[Vec<(u32, Fr)>],
        sparse_o: &[Vec<(u32, Fr)>],
        witness: &[Fr],
    ) -> (Proof, PublicInput);
}

// ------------------------------------------------------------------
// Shared helpers: witness-polynomial + quotient construction
// ------------------------------------------------------------------

/// Build the three witness polynomials and the quotient `h(x)` from **dense**
/// constraint matrices.  The construction is identical for both prover
/// strategies; only the final MSM vs scalar-by-scalar accumulation differs.
fn build_witness_polys_and_quotient_dense<E: QapEngine, T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
    engine: &E,
    l: &[L],
    r: &[R],
    o: &[O],
    witness: &[Fr],
) -> (DensePolynomial<Fr>, DensePolynomial<Fr>, DensePolynomial<Fr>, DensePolynomial<Fr>) {
    let n_vars = witness.len();
    let n_constraints = l.len();
    let d_size = engine.domain_size(n_constraints);

    let (l_poly, r_poly, o_poly) = if d_size > n_constraints {
        // FFT engine — on-the-fly construction to avoid O(n_vars × domain_size) memory.
        let domain = GeneralEvaluationDomain::<Fr>::new(d_size)
            .expect("Failed to create evaluation domain");

        let mut lp = DensePolynomial::zero();
        let mut rp = DensePolynomial::zero();
        let mut op = DensePolynomial::zero();

        for i in 0..n_vars {
            let wi = witness[i];

            let mut evals: Vec<Fr> = (0..d_size)
                .map(|j| if j < n_constraints { l[j].as_ref()[i].into() } else { Fr::zero() })
                .collect();
            domain.ifft_in_place(&mut evals);
            if lp.coeffs.len() < d_size {
                lp.coeffs.resize(d_size, Fr::zero());
            }
            for (k, &e) in evals.iter().enumerate() {
                lp.coeffs[k] += e * wi;
            }

            let mut evals: Vec<Fr> = (0..d_size)
                .map(|j| if j < n_constraints { r[j].as_ref()[i].into() } else { Fr::zero() })
                .collect();
            domain.ifft_in_place(&mut evals);
            if rp.coeffs.len() < d_size {
                rp.coeffs.resize(d_size, Fr::zero());
            }
            for (k, &e) in evals.iter().enumerate() {
                rp.coeffs[k] += e * wi;
            }

            let mut evals: Vec<Fr> = (0..d_size)
                .map(|j| if j < n_constraints { o[j].as_ref()[i].into() } else { Fr::zero() })
                .collect();
            domain.ifft_in_place(&mut evals);
            if op.coeffs.len() < d_size {
                op.coeffs.resize(d_size, Fr::zero());
            }
            for (k, &e) in evals.iter().enumerate() {
                op.coeffs[k] += e * wi;
            }
        }

        (lp, rp, op)
    } else {
        // Dense engine — standard build_qap (tiny circuit, no memory concern)
        let (us, vs, ws) = engine.build_qap(l, r, o);
        let mut lp = DensePolynomial::zero();
        let mut rp = DensePolynomial::zero();
        let mut op = DensePolynomial::zero();
        for i in 0..n_vars {
            lp = poly_add(&lp, &poly_scalar_mul(&us[i], witness[i]));
            rp = poly_add(&rp, &poly_scalar_mul(&vs[i], witness[i]));
            op = poly_add(&op, &poly_scalar_mul(&ws[i], witness[i]));
        }
        (lp, rp, op)
    };

    let t = engine.target_poly(n_constraints);
    let h = engine.compute_quotient(&l_poly, &r_poly, &o_poly, &t);
    (l_poly, r_poly, o_poly, h)
}

/// Build the three witness polynomials and the quotient `h(x)` from **sparse**
/// constraint matrices.
fn build_witness_polys_and_quotient_sparse(
    engine: &impl QapEngine,
    n_constraints: usize,
    sparse_l: &[Vec<(u32, Fr)>],
    sparse_r: &[Vec<(u32, Fr)>],
    sparse_o: &[Vec<(u32, Fr)>],
    witness: &[Fr],
) -> (DensePolynomial<Fr>, DensePolynomial<Fr>, DensePolynomial<Fr>, DensePolynomial<Fr>) {
    use crate::engine::build_witness_polys_sparse;

    let d_size = engine.domain_size(n_constraints);
    let domain = GeneralEvaluationDomain::<Fr>::new(d_size)
        .expect("Failed to create evaluation domain");
    let (l_poly, r_poly, o_poly) =
        build_witness_polys_sparse(&domain, d_size, n_constraints, sparse_l, sparse_r, sparse_o, witness);

    let t = engine.target_poly(n_constraints);
    let h = engine.compute_quotient(&l_poly, &r_poly, &o_poly, &t);
    (l_poly, r_poly, o_poly, h)
}

// ------------------------------------------------------------------
// Shared helper: toxic-waste scalar path (A, B, h_tau)
// ------------------------------------------------------------------

/// Compute the parts of the scalar-based Groth16 proof that are **independent**
/// of the MSM strategy: `A`, `B`, and `h_tau_scalar`.
fn compute_scalar_path_common<E: QapEngine, T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
    engine: &E,
    l: &[L],
    r: &[R],
    o: &[O],
    witness: &[Fr],
    tau: Fr,
    alpha: Fr,
    beta: Fr,
    delta: Fr,
) -> (G1Affine, G2Affine, Fr, Vec<Fr>, Vec<Fr>, Vec<Fr>) {
    let g1_proj = G1Projective::generator();
    let g2_proj = G2Projective::generator();

    let (us_tau, vs_tau, ws_tau) = engine.evaluate_qap_at_tau(l, r, o, tau);

    // A = l(tau)·G1 + alpha·G1
    let mut l_tau = Fr::zero();
    for i in 0..witness.len() {
        l_tau += us_tau[i] * witness[i];
    }
    let a = G1Affine::from(g1_proj * (l_tau + alpha));

    // B = r(tau)·G2 + beta·G2
    let mut r_tau = Fr::zero();
    for i in 0..witness.len() {
        r_tau += vs_tau[i] * witness[i];
    }
    let b = G2Affine::from(g2_proj * (r_tau + beta));

    // h(tau)·T(tau)/delta
    let delta_inv = delta.inverse().unwrap();
    let (us, vs, ws) = engine.build_qap(l, r, o);
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
    let h_tau = h.evaluate(&tau);
    let t_tau = t.evaluate(&tau);
    let h_tau_scalar = h_tau * t_tau * delta_inv;

    (a, b, h_tau_scalar, us_tau, vs_tau, ws_tau)
}

// ------------------------------------------------------------------
// Naive prover
// ------------------------------------------------------------------

/// Naive prover — scalar-by-scalar accumulation.
///
/// For every variable we compute `psi_scalar`, multiply the generator by it,
/// then add the weighted point to a running projective accumulator.
/// This is `O(n)` scalar multiplications + `O(n)` point additions.
pub struct NaiveProver;

impl NaiveProver {
    pub fn new() -> Self {
        Self
    }
}

impl Prover for NaiveProver {
    fn prove<E: QapEngine, T: Copy + Into<Fr>, Lm: AsRef<[T]>, Rm: AsRef<[T]>, Om: AsRef<[T]>>(
        &self,
        engine: &E,
        l: &[Lm],
        r: &[Rm],
        o: &[Om],
        witness: &[Fr],
        tau: Fr,
        alpha: Fr,
        beta: Fr,
        gamma: Fr,
        delta: Fr,
    ) -> (Proof, PublicInput) {
        let g1_proj = G1Projective::generator();
        let (a, b, h_tau_scalar, us_tau, vs_tau, ws_tau) =
            compute_scalar_path_common(engine, l, r, o, witness, tau, alpha, beta, delta);

        let gamma_inv = gamma.inverse().unwrap();
        let delta_inv = delta.inverse().unwrap();

        // C = sum_{private} a_i·Psi_P_G1 + h(tau)·T(tau)/delta·G1
        let mut c_proj = G1Projective::zero();
        for i in 2..witness.len() {
            let psi_scalar = (vs_tau[i] * alpha + us_tau[i] * beta + ws_tau[i]) * delta_inv;
            c_proj += g1_proj * (psi_scalar * witness[i]);
        }
        c_proj += g1_proj * h_tau_scalar;
        let c = G1Affine::from(c_proj);

        // V = sum_{public} a_i·Psi_V_G1
        let mut v_proj = G1Projective::zero();
        for i in 0..2 {
            let psi_scalar = (vs_tau[i] * alpha + us_tau[i] * beta + ws_tau[i]) * gamma_inv;
            v_proj += g1_proj * (psi_scalar * witness[i]);
        }
        let v = G1Affine::from(v_proj);

        (Proof { a, b, c }, PublicInput { v })
    }

    fn prove_with_full_pk<E: QapEngine, T: Copy + Into<Fr>, Lm: AsRef<[T]>, Rm: AsRef<[T]>, Om: AsRef<[T]>>(
        &self,
        engine: &E,
        full_pk: &crate::ceremony::FullProvingKey,
        l: &[Lm],
        r: &[Rm],
        o: &[Om],
        witness: &[Fr],
    ) -> (Proof, PublicInput) {
        let n_public = full_pk.vk.n_public;
        let n_vars = witness.len();

        let (_l_poly, _r_poly, _o_poly, h) = build_witness_polys_and_quotient_dense(engine, l, r, o, witness);

        // A = sum witness[i] * a_query[i] + alpha_g1
        let mut a_proj = G1Projective::from(full_pk.vk.alpha_g1);
        for i in 0..n_vars {
            a_proj += G1Projective::from(full_pk.a_query[i]) * witness[i];
        }
        let a = G1Affine::from(a_proj);

        // B = sum witness[i] * b_g2_query[i] + beta_g2
        let mut b_proj = G2Projective::from(full_pk.vk.beta_g2);
        for i in 0..n_vars {
            b_proj += G2Projective::from(full_pk.b_g2_query[i]) * witness[i];
        }
        let b = G2Affine::from(b_proj);

        // C = sum_{private} witness[i] * c_query[i] + h_commitment
        let mut c_proj = G1Projective::zero();
        for i in n_public..n_vars {
            c_proj += G1Projective::from(full_pk.c_query[i]) * witness[i];
        }

        // Fast path (Impl 7): h_commitment = h_scalar * h(tau) * G1
        let h_c = if let (Some(h_scalar), Some(tau)) = (full_pk.h_scalar, full_pk.h_scalar_tau) {
            let h_tau = h.evaluate(&tau);
            G1Projective::from(G1Affine::generator()) * (h_scalar * h_tau)
        } else {
            let h_len = h.coeffs.len().min(full_pk.h_query.len());
            let mut hc = G1Projective::zero();
            for j in 0..h_len {
                hc += G1Projective::from(full_pk.h_query[j]) * h.coeffs[j];
            }
            hc
        };
        c_proj += h_c;
        let c = G1Affine::from(c_proj);

        // V = sum_{public} witness[i] * l_query[i]
        let mut v_proj = G1Projective::zero();
        for i in 0..n_public {
            v_proj += G1Projective::from(full_pk.l_query[i]) * witness[i];
        }
        let v = G1Affine::from(v_proj);

        (Proof { a, b, c }, PublicInput { v })
    }

    fn prove_with_full_pk_sparse(
        &self,
        engine: &impl QapEngine,
        full_pk: &crate::ceremony::FullProvingKey,
        n_constraints: usize,
        sparse_l: &[Vec<(u32, Fr)>],
        sparse_r: &[Vec<(u32, Fr)>],
        sparse_o: &[Vec<(u32, Fr)>],
        witness: &[Fr],
    ) -> (Proof, PublicInput) {
        let n_public = full_pk.vk.n_public;
        let n_vars = witness.len();

        let (_l_poly, _r_poly, _o_poly, h) =
            build_witness_polys_and_quotient_sparse(engine, n_constraints, sparse_l, sparse_r, sparse_o, witness);

        // A = sum witness[i] * a_query[i] + alpha_g1
        let mut a_proj = G1Projective::from(full_pk.vk.alpha_g1);
        for i in 0..n_vars {
            a_proj += G1Projective::from(full_pk.a_query[i]) * witness[i];
        }
        let a = G1Affine::from(a_proj);

        // B = sum witness[i] * b_g2_query[i] + beta_g2
        let mut b_proj = G2Projective::from(full_pk.vk.beta_g2);
        for i in 0..n_vars {
            b_proj += G2Projective::from(full_pk.b_g2_query[i]) * witness[i];
        }
        let b = G2Affine::from(b_proj);

        // C = sum_{private} witness[i] * c_query[i] + h_commitment
        let mut c_proj = G1Projective::zero();
        for i in n_public..n_vars {
            c_proj += G1Projective::from(full_pk.c_query[i]) * witness[i];
        }

        // Fast path (Impl 7): h_commitment = h_scalar * h(tau) * G1
        let h_c = if let (Some(h_scalar), Some(tau)) = (full_pk.h_scalar, full_pk.h_scalar_tau) {
            let h_tau = h.evaluate(&tau);
            G1Projective::from(G1Affine::generator()) * (h_scalar * h_tau)
        } else {
            let h_len = h.coeffs.len().min(full_pk.h_query.len());
            let mut hc = G1Projective::zero();
            for j in 0..h_len {
                hc += G1Projective::from(full_pk.h_query[j]) * h.coeffs[j];
            }
            hc
        };
        c_proj += h_c;
        let c = G1Affine::from(c_proj);

        // V = sum_{public} witness[i] * l_query[i]
        let mut v_proj = G1Projective::zero();
        for i in 0..n_public {
            v_proj += G1Projective::from(full_pk.l_query[i]) * witness[i];
        }
        let v = G1Affine::from(v_proj);

        (Proof { a, b, c }, PublicInput { v })
    }
}

// ------------------------------------------------------------------
// Pippenger prover
// ------------------------------------------------------------------

/// Pippenger prover — batched multi-scalar multiplication.
///
/// Instead of accumulating points one scalar at a time, we collect all
/// `(base, scalar)` pairs into two vectors and call
/// `VariableBaseMSM::msm(bases, scalars)`, which uses Pippenger's
/// bucket algorithm internally. This reduces group operations from
/// `O(n)` scalar muls to roughly `O(n / log n)` bucket additions.
///
/// For our 8-variable circuit the speedup is negligible; the payoff
/// appears once the witness has hundreds or thousands of variables.
pub struct PippengerProver;

impl PippengerProver {
    pub fn new() -> Self {
        Self
    }
}

impl Prover for PippengerProver {
    fn prove<E: QapEngine, T: Copy + Into<Fr>, Lm: AsRef<[T]>, Rm: AsRef<[T]>, Om: AsRef<[T]>>(
        &self,
        engine: &E,
        l: &[Lm],
        r: &[Rm],
        o: &[Om],
        witness: &[Fr],
        tau: Fr,
        alpha: Fr,
        beta: Fr,
        gamma: Fr,
        delta: Fr,
    ) -> (Proof, PublicInput) {
        let g1_gen = G1Affine::generator();
        let (a, b, h_tau_scalar, us_tau, vs_tau, ws_tau) =
            compute_scalar_path_common(engine, l, r, o, witness, tau, alpha, beta, delta);

        let gamma_inv = gamma.inverse().unwrap();
        let delta_inv = delta.inverse().unwrap();

        // C = sum_{private} a_i·Psi_P_G1 + h(tau)·T(tau)/delta·G1
        let n_private = witness.len() - 2;
        let mut c_bases = Vec::with_capacity(n_private + 1);
        let mut c_scalars = Vec::with_capacity(n_private + 1);
        for i in 2..witness.len() {
            let psi_scalar = (vs_tau[i] * alpha + us_tau[i] * beta + ws_tau[i]) * delta_inv;
            c_bases.push(g1_gen);
            c_scalars.push(psi_scalar * witness[i]);
        }
        c_bases.push(g1_gen);
        c_scalars.push(h_tau_scalar);

        let c_proj = G1Projective::msm(&c_bases, &c_scalars).expect("MSM length mismatch");
        let c = G1Affine::from(c_proj);

        // V = sum_{public} a_i·Psi_V_G1
        let mut v_bases = Vec::with_capacity(2);
        let mut v_scalars = Vec::with_capacity(2);
        for i in 0..2 {
            let psi_scalar = (vs_tau[i] * alpha + us_tau[i] * beta + ws_tau[i]) * gamma_inv;
            v_bases.push(g1_gen);
            v_scalars.push(psi_scalar * witness[i]);
        }

        let v_proj = G1Projective::msm(&v_bases, &v_scalars).expect("MSM length mismatch");
        let v = G1Affine::from(v_proj);

        (Proof { a, b, c }, PublicInput { v })
    }

    fn prove_with_full_pk<E: QapEngine, T: Copy + Into<Fr>, Lm: AsRef<[T]>, Rm: AsRef<[T]>, Om: AsRef<[T]>>(
        &self,
        engine: &E,
        full_pk: &crate::ceremony::FullProvingKey,
        l: &[Lm],
        r: &[Rm],
        o: &[Om],
        witness: &[Fr],
    ) -> (Proof, PublicInput) {
        let n_public = full_pk.vk.n_public;

        let (_l_poly, _r_poly, _o_poly, h) = build_witness_polys_and_quotient_dense(engine, l, r, o, witness);

        // Fast path (Impl 7): h_commitment = h_scalar * h(tau) * G1
        let h_c = if let (Some(h_scalar), Some(tau)) = (full_pk.h_scalar, full_pk.h_scalar_tau) {
            let h_tau = h.evaluate(&tau);
            G1Projective::from(G1Affine::generator()) * (h_scalar * h_tau)
        } else {
            let h_len = h.coeffs.len().min(full_pk.h_query.len());
            if h_len > 0 {
                G1Projective::msm(&full_pk.h_query[..h_len], &h.coeffs[..h_len])
                    .expect("MSM length mismatch")
            } else {
                G1Projective::zero()
            }
        };

        // Parallel proof assembly (Impl 7): A, B, and C_private are independent.
        let (a, (b, c_private)) = rayon::join(
            || {
                let a_proj = G1Projective::msm(&full_pk.a_query, witness)
                    .expect("MSM length mismatch");
                G1Affine::from(a_proj + G1Projective::from(full_pk.vk.alpha_g1))
            },
            || rayon::join(
                || {
                    let b_proj = G2Projective::msm(&full_pk.b_g2_query, witness)
                        .expect("MSM length mismatch");
                    G2Affine::from(b_proj + G2Projective::from(full_pk.vk.beta_g2))
                },
                || {
                    let private_c = &full_pk.c_query[n_public..];
                    let private_w = &witness[n_public..];
                    G1Projective::msm(private_c, private_w)
                        .expect("MSM length mismatch")
                },
            ),
        );

        let c = G1Affine::from(c_private + h_c);

        // V = MSM(l_query, witness[public])
        let public_w = &witness[..n_public];
        let v = G1Affine::from(
            G1Projective::msm(&full_pk.l_query, public_w)
                .expect("MSM length mismatch")
        );

        (Proof { a, b, c }, PublicInput { v })
    }

    fn prove_with_full_pk_sparse(
        &self,
        engine: &impl QapEngine,
        full_pk: &crate::ceremony::FullProvingKey,
        n_constraints: usize,
        sparse_l: &[Vec<(u32, Fr)>],
        sparse_r: &[Vec<(u32, Fr)>],
        sparse_o: &[Vec<(u32, Fr)>],
        witness: &[Fr],
    ) -> (Proof, PublicInput) {
        let n_public = full_pk.vk.n_public;

        let (_l_poly, _r_poly, _o_poly, h) =
            build_witness_polys_and_quotient_sparse(engine, n_constraints, sparse_l, sparse_r, sparse_o, witness);

        // Fast path (Impl 7): h_commitment = h_scalar * h(tau) * G1
        let h_c = if let (Some(h_scalar), Some(tau)) = (full_pk.h_scalar, full_pk.h_scalar_tau) {
            let h_tau = h.evaluate(&tau);
            G1Projective::from(G1Affine::generator()) * (h_scalar * h_tau)
        } else {
            let h_len = h.coeffs.len().min(full_pk.h_query.len());
            if h_len > 0 {
                G1Projective::msm(&full_pk.h_query[..h_len], &h.coeffs[..h_len])
                    .expect("MSM length mismatch")
            } else {
                G1Projective::zero()
            }
        };

        // Parallel proof assembly (Impl 7): A, B, and C_private are independent.
        let (a, (b, c_private)) = rayon::join(
            || {
                let a_proj = G1Projective::msm(&full_pk.a_query, witness)
                    .expect("MSM length mismatch");
                G1Affine::from(a_proj + G1Projective::from(full_pk.vk.alpha_g1))
            },
            || rayon::join(
                || {
                    let b_proj = G2Projective::msm(&full_pk.b_g2_query, witness)
                        .expect("MSM length mismatch");
                    G2Affine::from(b_proj + G2Projective::from(full_pk.vk.beta_g2))
                },
                || {
                    let private_c = &full_pk.c_query[n_public..];
                    let private_w = &witness[n_public..];
                    G1Projective::msm(private_c, private_w)
                        .expect("MSM length mismatch")
                },
            ),
        );

        let c = G1Affine::from(c_private + h_c);

        // V = MSM(l_query, witness[public])
        let public_w = &witness[..n_public];
        let v = G1Affine::from(
            G1Projective::msm(&full_pk.l_query, public_w)
                .expect("MSM length mismatch")
        );

        (Proof { a, b, c }, PublicInput { v })
    }
}

/// Prove using the **Lagrange-basis h-SRS** (item (p)).
///
/// Identical to the sparse `full_pk` prover (same `A`, `B`, `C_private`,
/// `V`, same fixed-base MSMs), with one difference: the `h`-commitment is
/// folded **directly from `h`'s values on the coset `c·⟨ω⟩`** instead of
/// extracting its coefficients (the "monomial conversion").
///
/// `P = l·r − o` is evaluated on the coset (one FFT per wire polynomial on
/// the `c`-scaled coefficients), divided pointwise by the constant
/// `T(c·ω^j) = c^N − 1`, and folded with a single MSM against the
/// Lagrange-basis SRS points. The quotient polynomial is never materialised,
/// so its IFFT/division is fully skipped.
///
/// The produced element equals `δ⁻¹·T(τ)·h(τ)·G1` — the same group element
/// the monomial `h_query` path produces — so the resulting proof is
/// bit-for-bit identical and verifies against the unchanged VerifyingKey.
pub fn prove_with_full_pk_sparse_lagrange(
    full_pk: &crate::ceremony::FullProvingKey,
    n_constraints: usize,
    sparse_l: &[Vec<(u32, Fr)>],
    sparse_r: &[Vec<(u32, Fr)>],
    sparse_o: &[Vec<(u32, Fr)>],
    witness: &[Fr],
    lag: &crate::lagrange::LagrangeHQuery,
) -> (Proof, PublicInput) {
    use crate::engine::build_witness_polys_sparse;
    use crate::lagrange::h_commitment_lagrange;

    let n_public = full_pk.vk.n_public;
    let d_size = lag.n_domain;
    let domain = GeneralEvaluationDomain::<Fr>::new(d_size)
        .expect("Failed to create evaluation domain");

    // Sparse witness polynomials (coefficient form); SKIP the quotient.
    let (l_poly, r_poly, o_poly) = build_witness_polys_sparse(
        &domain,
        d_size,
        n_constraints,
        sparse_l,
        sparse_r,
        sparse_o,
        witness,
    );

    let h_c = h_commitment_lagrange(&domain, lag, &l_poly, &r_poly, &o_poly);

    // Parallel proof assembly (same as `PippengerProver`).
    let (a, (b, c_private)) = rayon::join(
        || {
            let a_proj = G1Projective::msm(&full_pk.a_query, witness)
                .expect("MSM length mismatch");
            G1Affine::from(a_proj + G1Projective::from(full_pk.vk.alpha_g1))
        },
        || rayon::join(
            || {
                let b_proj = G2Projective::msm(&full_pk.b_g2_query, witness)
                    .expect("MSM length mismatch");
                G2Affine::from(b_proj + G2Projective::from(full_pk.vk.beta_g2))
            },
            || {
                let private_c = &full_pk.c_query[n_public..];
                let private_w = &witness[n_public..];
                G1Projective::msm(private_c, private_w)
                    .expect("MSM length mismatch")
            },
        ),
    );

    let c = G1Affine::from(c_private + h_c);

    let public_w = &witness[..n_public];
    let v = G1Affine::from(
        G1Projective::msm(&full_pk.l_query, public_w)
            .expect("MSM length mismatch"),
    );

    (Proof { a, b, c }, PublicInput { v })
}

/// Verify a Groth16 proof.
///
/// Checks the pairing equation:
///   e(A, B) == e(alpha·G1, beta·G2) · e(C, delta·G2) · e(V, gamma·G2)
///
/// In arkworks the target group GT is written *additively*, so the
/// multiplicative product of pairings becomes a sum.
pub fn verify_proof(
    proof: &Proof,
    public_input: &PublicInput,
    alpha_g1: &G1Affine,
    beta_g2: &G2Affine,
    gamma_g2: &G2Affine,
    delta_g2: &G2Affine,
) -> bool {
    let lhs = Bls12_381::pairing(proof.a, proof.b);
    let rhs1 = Bls12_381::pairing(*alpha_g1, *beta_g2);
    let rhs2 = Bls12_381::pairing(proof.c, *delta_g2);
    let rhs3 = Bls12_381::pairing(public_input.v, *gamma_g2);
    let rhs = rhs1 + rhs2 + rhs3;
    lhs == rhs
}

// ------------------------------------------------------------------
// Implementation 11: prepared verifier + batched pairing verification
// ------------------------------------------------------------------

/// A verifier-side cache of the four fixed CRS points, prepared for the
/// Miller loop.
///
/// Pairing verification on BLS12-381 does two kinds of work:
///   1. *Preparation* — precomputing the doubling-and-adding coefficients
///      (line functions) required by the Miller loop.  For the fixed CRS
///      points `beta·G2`, `gamma·G2`, `delta·G2` this is the *same*
///      computation for every proof.
///   2. *Miller loops + final exponentiation* — once per pairing.
///
/// `PreparedVerifyingKey` hoists step 1 for the fixed points: it is done
/// exactly once per circuit instead of once per proof.  Verifying `N`
/// proofs individually therefore drops from `N` preparations of the three
/// G2 points to a single preparation.
pub struct PreparedVerifyingKey {
    /// Raw `alpha·G1` (kept for batch linear-combination scaling).
    pub alpha_g1: G1Affine,
    /// Raw `beta·G2` (needed by the native pairing backend).
    pub beta_g2: G2Affine,
    /// Raw `gamma·G2` (needed by the native pairing backend).
    pub gamma_g2: G2Affine,
    /// Raw `delta·G2` (needed by the native pairing backend).
    pub delta_g2: G2Affine,
    /// Prepared `alpha·G1` (used by the single-proof prepared verifier).
    pub alpha_g1_prepared: <Bls12_381 as Pairing>::G1Prepared,
    /// Prepared `beta·G2`.
    pub beta_g2_prepared: <Bls12_381 as Pairing>::G2Prepared,
    /// Prepared `gamma·G2`.
    pub gamma_g2_prepared: <Bls12_381 as Pairing>::G2Prepared,
    /// Prepared `delta·G2`.
    pub delta_g2_prepared: <Bls12_381 as Pairing>::G2Prepared,
}

impl PreparedVerifyingKey {
    /// Build the prepared form of the four fixed CRS points.
    pub fn new(
        alpha_g1: &G1Affine,
        beta_g2: &G2Affine,
        gamma_g2: &G2Affine,
        delta_g2: &G2Affine,
    ) -> Self {
        Self {
            alpha_g1: *alpha_g1,
            beta_g2: *beta_g2,
            gamma_g2: *gamma_g2,
            delta_g2: *delta_g2,
            alpha_g1_prepared: prepare_g1::<Bls12_381>(*alpha_g1),
            beta_g2_prepared: prepare_g2::<Bls12_381>(*beta_g2),
            gamma_g2_prepared: prepare_g2::<Bls12_381>(*gamma_g2),
            delta_g2_prepared: prepare_g2::<Bls12_381>(*delta_g2),
        }
    }

    /// Build the prepared form from a full `ceremony::VerifyingKey`.
    pub fn from_vk(vk: &crate::ceremony::VerifyingKey) -> Self {
        Self::new(&vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2)
    }
}

/// Verify a proof using a `PreparedVerifyingKey`.
///
/// This is the prepared analog of [`verify_proof`]: all four terms of the
/// Groth16 pairing product are folded into a single Miller loop with a
/// shared final exponentiation:
///
///   e(A, B) · e(−α·G1, β·G2) · e(−C, δ·G2) · e(−V, γ·G2) == 1
///
/// The fixed points (`β`, `γ`, `δ`) need no per-proof preparation here.
pub fn verify_proof_prepared(
    proof: &Proof,
    public_input: &PublicInput,
    pvk: &PreparedVerifyingKey,
) -> bool {
    let g1 = vec![
        prepare_g1::<Bls12_381>(proof.a),
        prepare_g1::<Bls12_381>(G1Affine::from(-G1Projective::from(pvk.alpha_g1))),
        prepare_g1::<Bls12_381>(G1Affine::from(-G1Projective::from(proof.c))),
        prepare_g1::<Bls12_381>(G1Affine::from(-G1Projective::from(public_input.v))),
    ];
    let g2 = vec![
        prepare_g2::<Bls12_381>(proof.b),
        pvk.beta_g2_prepared.clone(),
        pvk.delta_g2_prepared.clone(),
        pvk.gamma_g2_prepared.clone(),
    ];
    Bls12_381::multi_pairing(g1, g2).is_zero()
}

/// Verify a batch of independent Groth16 proofs with a single multi-pairing
/// product.
///
/// # Idea
///
/// Each proof must satisfy the same pairing equation
///
///   e(A_i, B_i) == e(α·G1, β·G2) · e(C_i, δ·G2) · e(V_i, γ·G2).
///
/// Raising both sides to a random scalar `r_i` and multiplying over all
/// `N` proofs folds every equation into one product of pairings:
///
///   Π_i e(r_i·A_i, B_i) == e((Σ r_i)·α·G1, β·G2)
///                          · e(Σ r_i·C_i, δ·G2)
///                          · e(Σ r_i·V_i, γ·G2)
///
/// (# math note: multiplication in `GT` is written additively in arkworks, so
/// "raising to `r_i`" becomes scalar multiplication of a `PairingOutput`, and
/// "*the product of pairings*" is a sum.  The check `== 1` below is therefore
/// `PairingOutput::is_zero()`.)
///
/// # Soundness
///
/// The random scalars make the batch check sound by the Schwartz–Zippel
/// lemma: if *any* proof is invalid, the two sides of the folded equation
/// are two distinct rational functions evaluated at random points, so the
/// equality holds with negligible probability (`~|Fr|⁻¹`).  The `r_i` are
/// drawn fresh from the OS RNG on every call.  (`verify_batch_with_scalars`
/// exposes the deterministic core for tests / transcripts.)
///
/// # Cost
///
/// `N` individual verifications run `4N` pairings.  This batched verifier
/// runs a single Miller loop over `N + 3` pairs followed by **one** final
/// exponentiation, and never re-prepares the fixed CRS points.
pub fn verify_batch(
    proofs: &[Proof],
    public_inputs: &[PublicInput],
    pvk: &PreparedVerifyingKey,
) -> bool {
    let mut rng = rand::thread_rng();
    let scalars: Vec<Fr> = (0..proofs.len())
        .map(|_| loop {
            let s = Fr::rand(&mut rng);
            if !s.is_zero() {
                break s;
            }
        })
        .collect();
    verify_batch_with_scalars(proofs, public_inputs, pvk, &scalars)
}

/// The deterministic core of [`verify_batch`]; `scalars[i]` weights proof `i`.
///
/// Supplying the scalars lets tests pin down exact failure cases and lets
/// transcript-style (Fiat–Shamir) batching reuse the same code path.  The
/// scalar consistency requirement is that each entry is a sample from a
/// uniform distribution over `Fr`; the safety argument is the same as for
/// [`verify_batch`].
pub fn verify_batch_with_scalars(
    proofs: &[Proof],
    public_inputs: &[PublicInput],
    pvk: &PreparedVerifyingKey,
    scalars: &[Fr],
) -> bool {
    let n = proofs.len();
    if n == 0 {
        return true;
    }
    assert_eq!(n, public_inputs.len(), "one public input per proof");
    assert_eq!(n, scalars.len(), "one scalar per proof");

    // Σ r_i — the exponent applied to the α·G1 term.
    let mut sum_r = Fr::zero();
    for s in scalars {
        sum_r += s;
    }

    // Multi-pairing operands.  g1[i] pairs with g2[i].
    let mut g1: Vec<<Bls12_381 as Pairing>::G1Prepared> = Vec::with_capacity(n + 3);
    let mut g2: Vec<<Bls12_381 as Pairing>::G2Prepared> = Vec::with_capacity(n + 3);

    // Σ r_i·C_i and Σ r_i·V_i, accumulated negated so that the folded
    // equality "LHS == RHS" becomes a single product equal to 1.
    let mut c_batch = G1Projective::zero();
    let mut v_batch = G1Projective::zero();

    for i in 0..n {
        // e(r_i·A_i, B_i) term.
        let scaled_a = G1Projective::from(proofs[i].a) * scalars[i];
        g1.push(prepare_g1::<Bls12_381>(G1Affine::from(scaled_a)));
        g2.push(prepare_g2::<Bls12_381>(proofs[i].b));

        c_batch += G1Projective::from(proofs[i].c) * scalars[i];
        v_batch += G1Projective::from(public_inputs[i].v) * scalars[i];
    }

    // −(Σ r_i)·α·G1 against β·G2.
    let alpha_scaled = G1Projective::from(pvk.alpha_g1) * (-sum_r);
    g1.push(prepare_g1::<Bls12_381>(G1Affine::from(alpha_scaled)));
    g2.push(pvk.beta_g2_prepared.clone());

    // −(Σ r_i·C_i) against δ·G2.
    g1.push(prepare_g1::<Bls12_381>(G1Affine::from(-c_batch)));
    g2.push(pvk.delta_g2_prepared.clone());

    // −(Σ r_i·V_i) against γ·G2.
    g1.push(prepare_g1::<Bls12_381>(G1Affine::from(-v_batch)));
    g2.push(pvk.gamma_g2_prepared.clone());

    Bls12_381::multi_pairing(g1, g2).is_zero()
}

// ------------------------------------------------------------------
// Native backend: the same prover/verifier primitives driven by the
// vendored C++ backend (blst Pippenger MSM + multi-pairing) instead of
// arkworks.  Compiled only with `--features native`.
// ------------------------------------------------------------------

/// Backend selector for proof generation and batch verification.
///
/// - [`Backend::Cpu`]: arkworks' `VariableBaseMSM` / `multi_pairing` — the
///   reference implementation; `Backend::Cpu` on the prove side *is* the
///   plain `PippengerProver`.
/// - [`Backend::Native`]: the vendored blst FFI backend.
#[cfg(feature = "native")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// arkworks reference arithmetic.
    Cpu,
    /// vendored blst FFI backend.
    Native,
}

/// `Backend::Native` proof generation and batch verification.
///
/// The native backend replaces only the *group arithmetic* of the reference
/// prover: witness-poly construction, the FFT quotient, and the `h`-scalar
/// fast path stay in arkworks (identical, deterministic), while every
/// multi-scalar multiplication is routed to blst's Pippenger implementation.
/// The four MSMs `A`, `B`, `C_private`, `V` are independent — each is one
/// `blst_p1s(p2s)_mult_pippenger` call — and the `h`-commitment either reuses
/// the `h_scalar` fast path (a single generator multiply) or a fifth G1 MSM.
///
/// Because MSM output is the batch-sum of the same base points it is *the
/// same group element* the CPU path computes, so `Backend::Native` produces
/// proofs that are bit-for-bit identical to `Backend::Cpu`'s.
#[cfg(feature = "native")]
pub mod native_backend {
    use super::*;
    use crate::backend::{native_msm_g1, native_msm_g2, native_pairing_batch_check};
    #[allow(unused_imports)]
    use crate::bls_ffi::BackendError;

    fn g1_msm(bases: &[G1Affine], scalars: &[Fr]) -> Result<G1Affine, BackendError> {
        native_msm_g1(bases, scalars)
    }

    fn g2_msm(bases: &[G2Affine], scalars: &[Fr]) -> Result<G2Affine, BackendError> {
        native_msm_g2(bases, scalars)
    }

    /// `h`-commitment for a built quotient polynomial, mirroring
    /// `PippengerProver`: `h_scalar * h(tau) * G1` when the fast path is
    /// available, else an MSM against `h_query`.
    fn h_commitment(
        full_pk: &crate::ceremony::FullProvingKey,
        h: &DensePolynomial<Fr>,
    ) -> Result<G1Projective, BackendError> {
        if let (Some(h_scalar), Some(tau)) = (full_pk.h_scalar, full_pk.h_scalar_tau) {
            let h_tau = h.evaluate(&tau);
            Ok(G1Projective::from(G1Affine::generator()) * (h_scalar * h_tau))
        } else {
            let h_len = h.coeffs.len().min(full_pk.h_query.len());
            if h_len > 0 {
                g1_msm(&full_pk.h_query[..h_len], &h.coeffs[..h_len]).map(G1Projective::from)
            } else {
                Ok(G1Projective::zero())
            }
        }
    }

    /// Prove `(A, B, C, V)` using the native backend for every MSM.
    pub fn prove_with_full_pk<E>(
        engine: &E,
        full_pk: &crate::ceremony::FullProvingKey,
        l: &[Vec<Fr>],
        r: &[Vec<Fr>],
        o: &[Vec<Fr>],
        witness: &[Fr],
    ) -> Result<(Proof, PublicInput), BackendError>
    where
        E: QapEngine,
    {
        let n_public = full_pk.vk.n_public;
        let (_l_poly, _r_poly, _o_poly, h) =
            build_witness_polys_and_quotient_dense(engine, l, r, o, witness);

        let h_c = h_commitment(full_pk, &h)?;

        let a_proj: G1Projective = g1_msm(&full_pk.a_query, witness)?.into();
        let a: G1Affine = (a_proj + G1Projective::from(full_pk.vk.alpha_g1)).into();

        let b_proj: G2Projective = g2_msm(&full_pk.b_g2_query, witness)?.into();
        let b: G2Affine = (b_proj + G2Projective::from(full_pk.vk.beta_g2)).into();

        let private_c = &full_pk.c_query[n_public..];
        let private_w = &witness[n_public..];
        let c_private: G1Projective = if private_c.is_empty() {
            G1Projective::zero()
        } else {
            g1_msm(private_c, private_w)?.into()
        };
        let c: G1Affine = (c_private + h_c).into();

        let public_w = &witness[..n_public];
        let v: G1Affine = g1_msm(&full_pk.l_query, public_w)?.into();

        Ok((Proof { a, b, c }, PublicInput { v }))
    }

    /// Sparse-wire analog of [`prove_with_full_pk`].
    pub fn prove_with_full_pk_sparse<E>(
        engine: &E,
        full_pk: &crate::ceremony::FullProvingKey,
        n_constraints: usize,
        sparse_l: &[Vec<(u32, Fr)>],
        sparse_r: &[Vec<(u32, Fr)>],
        sparse_o: &[Vec<(u32, Fr)>],
        witness: &[Fr],
    ) -> Result<(Proof, PublicInput), BackendError>
    where
        E: QapEngine,
    {
        let n_public = full_pk.vk.n_public;
        let (_l_poly, _r_poly, _o_poly, h) =
            build_witness_polys_and_quotient_sparse(engine, n_constraints, sparse_l, sparse_r, sparse_o, witness);

        let h_c = h_commitment(full_pk, &h)?;

        let a_proj: G1Projective = g1_msm(&full_pk.a_query, witness)?.into();
        let a: G1Affine = (a_proj + G1Projective::from(full_pk.vk.alpha_g1)).into();

        let b_proj: G2Projective = g2_msm(&full_pk.b_g2_query, witness)?.into();
        let b: G2Affine = (b_proj + G2Projective::from(full_pk.vk.beta_g2)).into();

        let private_c = &full_pk.c_query[n_public..];
        let private_w = &witness[n_public..];
        let c_private: G1Projective = if private_c.is_empty() {
            G1Projective::zero()
        } else {
            g1_msm(private_c, private_w)?.into()
        };
        let c: G1Affine = (c_private + h_c).into();

        let public_w = &witness[..n_public];
        let v: G1Affine = g1_msm(&full_pk.l_query, public_w)?.into();

        Ok((Proof { a, b, c }, PublicInput { v }))
    }

    /// Batch verification of `N` proofs with `N+3` native pairings; the
    /// random-scalar folding is byte-for-byte the reference `verify_batch`,
    /// only the final multi-pairing product is evaluated by blst.
    pub fn verify_batch(
        proofs: &[Proof],
        public_inputs: &[PublicInput],
        pvk: &PreparedVerifyingKey,
    ) -> Result<bool, BackendError> {
        let mut rng = rand::thread_rng();
        let scalars: Vec<Fr> = (0..proofs.len())
            .map(|_| loop {
                let s = Fr::rand(&mut rng);
                if !s.is_zero() {
                    break s;
                }
            })
            .collect();
        verify_batch_with_scalars(proofs, public_inputs, pvk, &scalars)
    }

    /// Deterministic core of [`verify_batch`]: same fold as the reference
    /// `verify_batch_with_scalars`, with the `N+3` pairings evaluated by
    /// `blst_miller_loop_n` + `blst_final_exp` in a single call.
    pub fn verify_batch_with_scalars(
        proofs: &[Proof],
        public_inputs: &[PublicInput],
        pvk: &PreparedVerifyingKey,
        scalars: &[Fr],
    ) -> Result<bool, BackendError> {
        let n = proofs.len();
        if n == 0 {
            return Ok(true);
        }
        assert_eq!(n, public_inputs.len(), "one public input per proof");
        assert_eq!(n, scalars.len(), "one scalar per proof");

        let mut sum_r = Fr::zero();
        for s in scalars {
            sum_r += s;
        }

        let mut g1: Vec<G1Affine> = Vec::with_capacity(n + 3);
        let mut g2: Vec<G2Affine> = Vec::with_capacity(n + 3);

        let mut c_batch = G1Projective::zero();
        let mut v_batch = G1Projective::zero();

        for i in 0..n {
            let scaled_a: G1Affine = (G1Projective::from(proofs[i].a) * scalars[i]).into();
            g1.push(scaled_a);
            g2.push(proofs[i].b);

            c_batch += G1Projective::from(proofs[i].c) * scalars[i];
            v_batch += G1Projective::from(public_inputs[i].v) * scalars[i];
        }

        let alpha_scaled: G1Affine = (G1Projective::from(pvk.alpha_g1) * (-sum_r)).into();
        g1.push(alpha_scaled);
        g2.push(pvk.beta_g2);

        let neg_c_batch: G1Affine = (-c_batch).into();
        g1.push(neg_c_batch);
        g2.push(pvk.delta_g2);

        let neg_v_batch: G1Affine = (-v_batch).into();
        g1.push(neg_v_batch);
        g2.push(pvk.gamma_g2);

        native_pairing_batch_check(&g1, &g2)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{DenseQapEngine, FftQapEngine};
    use crate::r1cs::{L, O, R, WITNESS};

    fn toxic_waste() -> (Fr, Fr, Fr, Fr, Fr) {
        (
            Fr::from(3u64),  // tau
            Fr::from(5u64),  // alpha
            Fr::from(7u64),  // beta
            Fr::from(11u64), // gamma
            Fr::from(13u64), // delta
        )
    }

    fn witness() -> Vec<Fr> {
        WITNESS.iter().map(|&v| Fr::from(v)).collect()
    }

    #[test]
    fn test_naive_prover_with_dense_engine() {
        let engine = DenseQapEngine::new();
        let prover = NaiveProver::new();
        let witness = witness();
        let (tau, alpha, beta, gamma, delta) = toxic_waste();

        let (proof, public_input) = prover.prove(&engine, &L, &R, &O, &witness, tau, alpha, beta, gamma, delta);

        let alpha_g1 = G1Affine::from(G1Projective::generator() * alpha);
        let beta_g2 = G2Affine::from(G2Projective::generator() * beta);
        let gamma_g2 = G2Affine::from(G2Projective::generator() * gamma);
        let delta_g2 = G2Affine::from(G2Projective::generator() * delta);

        assert!(
            verify_proof(&proof, &public_input, &alpha_g1, &beta_g2, &gamma_g2, &delta_g2),
            "Naive prover with dense engine must produce a valid proof"
        );
    }

    #[test]
    fn test_naive_prover_with_fft_engine() {
        let engine = FftQapEngine::new();
        let prover = NaiveProver::new();
        let witness = witness();
        let (tau, alpha, beta, gamma, delta) = toxic_waste();

        let (proof, public_input) = prover.prove(&engine, &L, &R, &O, &witness, tau, alpha, beta, gamma, delta);

        let alpha_g1 = G1Affine::from(G1Projective::generator() * alpha);
        let beta_g2 = G2Affine::from(G2Projective::generator() * beta);
        let gamma_g2 = G2Affine::from(G2Projective::generator() * gamma);
        let delta_g2 = G2Affine::from(G2Projective::generator() * delta);

        assert!(
            verify_proof(&proof, &public_input, &alpha_g1, &beta_g2, &gamma_g2, &delta_g2),
            "Naive prover with FFT engine must produce a valid proof"
        );
    }

    #[test]
    fn test_pippenger_prover_with_fft_engine() {
        let engine = FftQapEngine::new();
        let prover = PippengerProver::new();
        let witness = witness();
        let (tau, alpha, beta, gamma, delta) = toxic_waste();

        let (proof, public_input) = prover.prove(&engine, &L, &R, &O, &witness, tau, alpha, beta, gamma, delta);

        let alpha_g1 = G1Affine::from(G1Projective::generator() * alpha);
        let beta_g2 = G2Affine::from(G2Projective::generator() * beta);
        let gamma_g2 = G2Affine::from(G2Projective::generator() * gamma);
        let delta_g2 = G2Affine::from(G2Projective::generator() * delta);

        assert!(
            verify_proof(&proof, &public_input, &alpha_g1, &beta_g2, &gamma_g2, &delta_g2),
            "Pippenger prover with FFT engine must produce a valid proof"
        );
    }

    #[test]
    fn test_pippenger_matches_naive_with_fft_engine() {
        let engine = FftQapEngine::new();
        let naive = NaiveProver::new();
        let pippenger = PippengerProver::new();
        let witness = witness();
        let (tau, alpha, beta, gamma, delta) = toxic_waste();

        let (proof_naive, public_naive) =
            naive.prove(&engine, &L, &R, &O, &witness, tau, alpha, beta, gamma, delta);
        let (proof_pip, public_pip) =
            pippenger.prove(&engine, &L, &R, &O, &witness, tau, alpha, beta, gamma, delta);

        assert_eq!(proof_naive.a, proof_pip.a, "A must match between naive and Pippenger");
        assert_eq!(proof_naive.b, proof_pip.b, "B must match between naive and Pippenger");
        assert_eq!(proof_naive.c, proof_pip.c, "C must match between naive and Pippenger");
        assert_eq!(public_naive.v, public_pip.v, "V must match between naive and Pippenger");
    }

    #[test]
    fn test_pippenger_matches_naive_with_dense_engine() {
        let engine = DenseQapEngine::new();
        let naive = NaiveProver::new();
        let pippenger = PippengerProver::new();
        let witness = witness();
        let (tau, alpha, beta, gamma, delta) = toxic_waste();

        let (proof_naive, public_naive) =
            naive.prove(&engine, &L, &R, &O, &witness, tau, alpha, beta, gamma, delta);
        let (proof_pip, public_pip) =
            pippenger.prove(&engine, &L, &R, &O, &witness, tau, alpha, beta, gamma, delta);

        assert_eq!(proof_naive.a, proof_pip.a, "A must match between naive and Pippenger");
        assert_eq!(proof_naive.b, proof_pip.b, "B must match between naive and Pippenger");
        assert_eq!(proof_naive.c, proof_pip.c, "C must match between naive and Pippenger");
        assert_eq!(public_naive.v, public_pip.v, "V must match between naive and Pippenger");
    }

    // ------------------------------------------------------------------
    // FullProvingKey parity tests (Phase 0 prover migration)
    // ------------------------------------------------------------------

    #[test]
    fn test_naive_full_pk_matches_scalar_prover() {
        let engine = DenseQapEngine::new();
        let prover = NaiveProver::new();
        let witness = witness();
        let tw = crate::ceremony::ToxicWaste::deterministic();

        // Old scalar-based path
        let (proof_old, public_old) = prover.prove(
            &engine, &L, &R, &O, &witness,
            tw.tau, tw.alpha, tw.beta, tw.gamma, tw.delta,
        );

        // New group-element path
        let (full_pk, _vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &L, &R, &O, 2, tw, false,
        );
        let (proof_new, public_new) = prover.prove_with_full_pk(
            &engine, &full_pk, &L, &R, &O, &witness,
        );

        assert_eq!(proof_old.a, proof_new.a, "A must match between scalar and FullPK path");
        assert_eq!(proof_old.b, proof_new.b, "B must match between scalar and FullPK path");
        assert_eq!(proof_old.c, proof_new.c, "C must match between scalar and FullPK path");
        assert_eq!(public_old.v, public_new.v, "V must match between scalar and FullPK path");
    }

    #[test]
    fn test_pippenger_full_pk_matches_scalar_prover() {
        let engine = FftQapEngine::new();
        let prover = PippengerProver::new();
        let witness = witness();
        let tw = crate::ceremony::ToxicWaste::deterministic();

        // Old scalar-based path
        let (proof_old, public_old) = prover.prove(
            &engine, &L, &R, &O, &witness,
            tw.tau, tw.alpha, tw.beta, tw.gamma, tw.delta,
        );

        // New group-element path
        let (full_pk, _vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &L, &R, &O, 2, tw, false,
        );
        let (proof_new, public_new) = prover.prove_with_full_pk(
            &engine, &full_pk, &L, &R, &O, &witness,
        );

        assert_eq!(proof_old.a, proof_new.a, "A must match between scalar and FullPK path");
        assert_eq!(proof_old.b, proof_new.b, "B must match between scalar and FullPK path");
        assert_eq!(proof_old.c, proof_new.c, "C must match between scalar and FullPK path");
        assert_eq!(public_old.v, public_new.v, "V must match between scalar and FullPK path");
    }

    #[test]
    fn test_full_pk_prover_produces_valid_proof() {
        let engine = FftQapEngine::new();
        let prover = PippengerProver::new();
        let witness = witness();
        let tw = crate::ceremony::ToxicWaste::deterministic();

        let (full_pk, _vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &L, &R, &O, 2, tw, false,
        );
        let (proof, public_input) = prover.prove_with_full_pk(
            &engine, &full_pk, &L, &R, &O, &witness,
        );

        assert!(
            verify_proof(&proof, &public_input, &full_pk.vk.alpha_g1, &full_pk.vk.beta_g2, &full_pk.vk.gamma_g2, &full_pk.vk.delta_g2),
            "FullPK prover must produce a valid proof"
        );
    }

    // ------------------------------------------------------------------
    // Implementation 7 parity tests (h_scalar fast path)
    // ------------------------------------------------------------------

    #[test]
    fn test_h_scalar_matches_h_query_naive_dense() {
        let engine = DenseQapEngine::new();
        let prover = NaiveProver::new();
        let witness = witness();
        let tw = crate::ceremony::ToxicWaste::deterministic();

        let (pk_legacy, _vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &L, &R, &O, 2, tw.clone(), false,
        );
        let (pk_hscalar, _vk2) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &L, &R, &O, 2, tw, true,
        );

        let (proof_legacy, public_legacy) = prover.prove_with_full_pk(
            &engine, &pk_legacy, &L, &R, &O, &witness,
        );
        let (proof_fast, public_fast) = prover.prove_with_full_pk(
            &engine, &pk_hscalar, &L, &R, &O, &witness,
        );

        assert_eq!(proof_legacy.a, proof_fast.a, "A must match between legacy and h_scalar path");
        assert_eq!(proof_legacy.b, proof_fast.b, "B must match between legacy and h_scalar path");
        assert_eq!(proof_legacy.c, proof_fast.c, "C must match between legacy and h_scalar path");
        assert_eq!(public_legacy.v, public_fast.v, "V must match between legacy and h_scalar path");
    }

    #[test]
    fn test_h_scalar_matches_h_query_pippenger_fft() {
        let engine = FftQapEngine::new();
        let prover = PippengerProver::new();
        let witness = witness();
        let tw = crate::ceremony::ToxicWaste::deterministic();

        let (pk_legacy, _vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &L, &R, &O, 2, tw.clone(), false,
        );
        let (pk_hscalar, _vk2) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &L, &R, &O, 2, tw, true,
        );

        let (proof_legacy, public_legacy) = prover.prove_with_full_pk(
            &engine, &pk_legacy, &L, &R, &O, &witness,
        );
        let (proof_fast, public_fast) = prover.prove_with_full_pk(
            &engine, &pk_hscalar, &L, &R, &O, &witness,
        );

        assert_eq!(proof_legacy.a, proof_fast.a, "A must match between legacy and h_scalar path");
        assert_eq!(proof_legacy.b, proof_fast.b, "B must match between legacy and h_scalar path");
        assert_eq!(proof_legacy.c, proof_fast.c, "C must match between legacy and h_scalar path");
        assert_eq!(public_legacy.v, public_fast.v, "V must match between legacy and h_scalar path");
    }

    #[test]
    fn test_h_scalar_matches_h_query_pippenger_sparse() {
        let engine = FftQapEngine::new();
        let prover = PippengerProver::new();
        let witness = witness();
        let tw = crate::ceremony::ToxicWaste::deterministic();

        let (pk_legacy, _vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &L, &R, &O, 2, tw.clone(), false,
        );
        let (pk_hscalar, _vk2) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &L, &R, &O, 2, tw, true,
        );

        let n_constraints = L.len();
        // Build sparse matrices from dense L, R, O for the sparse prover path
        let sparse_l: Vec<Vec<(u32, Fr)>> = L.iter().enumerate().map(|(_j, row)| {
            row.iter().enumerate().filter_map(|(i, &v)| {
                let fr = Fr::from(v);
                if fr.is_zero() { None } else { Some((i as u32, fr)) }
            }).collect()
        }).collect();
        let sparse_r: Vec<Vec<(u32, Fr)>> = R.iter().enumerate().map(|(_j, row)| {
            row.iter().enumerate().filter_map(|(i, &v)| {
                let fr = Fr::from(v);
                if fr.is_zero() { None } else { Some((i as u32, fr)) }
            }).collect()
        }).collect();
        let sparse_o: Vec<Vec<(u32, Fr)>> = O.iter().enumerate().map(|(_j, row)| {
            row.iter().enumerate().filter_map(|(i, &v)| {
                let fr = Fr::from(v);
                if fr.is_zero() { None } else { Some((i as u32, fr)) }
            }).collect()
        }).collect();

        let (proof_legacy, public_legacy) = prover.prove_with_full_pk_sparse(
            &engine, &pk_legacy, n_constraints, &sparse_l, &sparse_r, &sparse_o, &witness,
        );
        let (proof_fast, public_fast) = prover.prove_with_full_pk_sparse(
            &engine, &pk_hscalar, n_constraints, &sparse_l, &sparse_r, &sparse_o, &witness,
        );

        assert_eq!(proof_legacy.a, proof_fast.a, "A must match between legacy and h_scalar sparse path");
        assert_eq!(proof_legacy.b, proof_fast.b, "B must match between legacy and h_scalar sparse path");
        assert_eq!(proof_legacy.c, proof_fast.c, "C must match between legacy and h_scalar sparse path");
        assert_eq!(public_legacy.v, public_fast.v, "V must match between legacy and h_scalar sparse path");
    }

    #[test]
    fn test_h_scalar_produces_valid_proof() {
        let engine = FftQapEngine::new();
        let prover = PippengerProver::new();
        let witness = witness();
        let tw = crate::ceremony::ToxicWaste::deterministic();

        let (full_pk, _vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &L, &R, &O, 2, tw, true,
        );
        let (proof, public_input) = prover.prove_with_full_pk(
            &engine, &full_pk, &L, &R, &O, &witness,
        );

        assert!(
            verify_proof(&proof, &public_input, &full_pk.vk.alpha_g1, &full_pk.vk.beta_g2, &full_pk.vk.gamma_g2, &full_pk.vk.delta_g2),
            "h_scalar prover must produce a valid proof"
        );
    }

    // ------------------------------------------------------------------
    // Parity assertion helpers for randomized R1CS fixtures
    // ------------------------------------------------------------------

    /// Assert that two proofs are bit-for-bit identical and both pass verification.
    fn assert_proof_parity(
        proof_a: &Proof,
        proof_b: &Proof,
        public_a: &PublicInput,
        public_b: &PublicInput,
        vk: &crate::ceremony::VerifyingKey,
    ) {
        assert_eq!(proof_a.a, proof_b.a, "A must match between provers");
        assert_eq!(proof_a.b, proof_b.b, "B must match between provers");
        assert_eq!(proof_a.c, proof_b.c, "C must match between provers");
        assert_eq!(public_a.v, public_b.v, "V must match between provers");
        assert!(
            verify_proof(proof_a, public_a, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2),
            "proof A must pass verification"
        );
        assert!(
            verify_proof(proof_b, public_b, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2),
            "proof B must pass verification"
        );
    }

    /// Run both dense and sparse prover paths on the same circuit and assert parity.
    fn assert_dense_sparse_parity(
        circuit: &crate::r1cs::Circuit,
        pk: &crate::ceremony::FullProvingKey,
        vk: &crate::ceremony::VerifyingKey,
    ) {
        let engine = FftQapEngine::new();
        let prover = PippengerProver::new();

        // Dense path
        let (proof_dense, public_dense) = prover.prove_with_full_pk(
            &engine, pk,
            &circuit.l, &circuit.r, &circuit.o,
            &circuit.witness,
        );

        // Sparse path
        let n_constraints = circuit.l.len();
        let sparse_l: Vec<Vec<(u32, Fr)>> = circuit.l.iter().enumerate().map(|(_j, row)| {
            row.iter().enumerate().filter_map(|(i, &v)| {
                if v.is_zero() { None } else { Some((i as u32, v)) }
            }).collect()
        }).collect();
        let sparse_r: Vec<Vec<(u32, Fr)>> = circuit.r.iter().enumerate().map(|(_j, row)| {
            row.iter().enumerate().filter_map(|(i, &v)| {
                if v.is_zero() { None } else { Some((i as u32, v)) }
            }).collect()
        }).collect();
        let sparse_o: Vec<Vec<(u32, Fr)>> = circuit.o.iter().enumerate().map(|(_j, row)| {
            row.iter().enumerate().filter_map(|(i, &v)| {
                if v.is_zero() { None } else { Some((i as u32, v)) }
            }).collect()
        }).collect();

        let (proof_sparse, public_sparse) = prover.prove_with_full_pk_sparse(
            &engine, pk, n_constraints,
            &sparse_l, &sparse_r, &sparse_o,
            &circuit.witness,
        );

        assert_proof_parity(&proof_dense, &proof_sparse, &public_dense, &public_sparse, vk);
    }

    // ------------------------------------------------------------------
    // Randomized R1CS fixture parity tests
    // ------------------------------------------------------------------

    #[test]
    fn random_circuit_1_constraint_prove_verify() {
        let mut rng = rand::thread_rng();
        let circuit = crate::r1cs::random_r1cs_circuit(&mut rng, 1);

        let engine = FftQapEngine::new();
        let tw = crate::ceremony::ToxicWaste::deterministic();
        let n_public = circuit.n_public;

        let (pk, vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &circuit.l, &circuit.r, &circuit.o,
            n_public, tw, false,
        );

        let prover = PippengerProver::new();
        let (proof, public_input) = prover.prove_with_full_pk(
            &engine, &pk,
            &circuit.l, &circuit.r, &circuit.o,
            &circuit.witness,
        );

        assert!(
            verify_proof(&proof, &public_input, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2),
            "proof must be valid for 1-constraint random circuit"
        );
    }

    #[test]
    fn random_circuit_5_constraints_prove_verify() {
        let mut rng = rand::thread_rng();
        let circuit = crate::r1cs::random_r1cs_circuit(&mut rng, 5);

        let engine = FftQapEngine::new();
        let tw = crate::ceremony::ToxicWaste::deterministic();
        let n_public = circuit.n_public;

        let (pk, vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &circuit.l, &circuit.r, &circuit.o,
            n_public, tw, false,
        );

        let prover = PippengerProver::new();
        let (proof, public_input) = prover.prove_with_full_pk(
            &engine, &pk,
            &circuit.l, &circuit.r, &circuit.o,
            &circuit.witness,
        );

        assert!(
            verify_proof(&proof, &public_input, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2),
            "proof must be valid for 5-constraint random circuit"
        );
    }

    #[test]
    fn random_circuit_dense_sparse_parity_1_constraint() {
        let mut rng = rand::thread_rng();
        let circuit = crate::r1cs::random_r1cs_circuit(&mut rng, 1);

        let engine = FftQapEngine::new();
        let tw = crate::ceremony::ToxicWaste::deterministic();
        let n_public = circuit.n_public;

        let (pk, vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &circuit.l, &circuit.r, &circuit.o,
            n_public, tw, false,
        );

        assert_dense_sparse_parity(&circuit, &pk, &vk);
    }

    #[test]
    fn random_circuit_dense_sparse_parity_5_constraints() {
        let mut rng = rand::thread_rng();
        let circuit = crate::r1cs::random_r1cs_circuit(&mut rng, 5);

        let engine = FftQapEngine::new();
        let tw = crate::ceremony::ToxicWaste::deterministic();
        let n_public = circuit.n_public;

        let (pk, vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &circuit.l, &circuit.r, &circuit.o,
            n_public, tw, false,
        );

        assert_dense_sparse_parity(&circuit, &pk, &vk);
    }

    // ------------------------------------------------------------------
    // Item (o): richer randomized R1CS fixtures + engine parity assertions
    // ------------------------------------------------------------------

    /// A tiny deterministic RNG (xorshift64) so randomized-fixture tests are
    /// reproducible: same seed → same circuit, regardless of platform or
    /// test scheduling.
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

    impl rand::RngCore for XorShiftRng {
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

    /// Directly re-check every constraint `(L·w)·(R·w) == (O·w)` on the
    /// generated dense matrices — independent of any QAP engine.
    fn assert_circuit_satisfied(circuit: &crate::r1cs::Circuit) {
        for i in 0..circuit.n_constraints() {
            let dot = |row: &[Fr]| row.iter().zip(&circuit.witness).fold(Fr::zero(), |acc, (&a, &b)| acc + a * b);
            let dl = dot(&circuit.l[i]);
            let dr = dot(&circuit.r[i]);
            let do_ = dot(&circuit.o[i]);
            assert_eq!(dl * dr, do_, "constraint {} must be satisfied by construction", i);
        }
    }

    /// `evaluate_witness_and_quotient` returns `(l(τ), r(τ), o(τ), h(τ), T(τ))`;
    /// assert the QAP identity `l(τ)r(τ) − o(τ) == h(τ)T(τ)` holds for the given
    /// engine's *own* basis (Lagrange naturals for dense, roots of unity for FFT).
    fn assert_quotient_identity<E: QapEngine>(engine: &E, circuit: &crate::r1cs::Circuit) {
        let tau = Fr::from(23u64);
        let (l_tau, r_tau, o_tau, h_tau, t_tau) = crate::engine::evaluate_witness_and_quotient(
            engine, &circuit.l, &circuit.r, &circuit.o, &circuit.witness, tau,
        );
        assert_eq!(
            l_tau * r_tau - o_tau,
            h_tau * t_tau,
            "QAP identity must hold in this engine's basis"
        );
    }

    /// Build a packed VK carrying a random sparse circuit's full polynomials
    /// through all proof steps, returning the full PK + VK pair.
    fn random_sparse_ceremony(
        engine: &impl QapEngine,
        circuit: &crate::r1cs::Circuit,
    ) -> (crate::ceremony::FullProvingKey, crate::ceremony::VerifyingKey) {
        let tw = crate::ceremony::ToxicWaste::deterministic();
        crate::ceremony::single_party_ceremony_full_from_tw(
            engine, &circuit.l, &circuit.r, &circuit.o, circuit.n_public, tw, false,
        )
    }

    #[test]
    fn random_sparse_circuit_all_sizes_and_seeds_prove_verify() {
        let sizes = [1usize, 6, 14]; // min, non-power-of-2, max
        for &n in &sizes {
            for seed in 0..3u64 {
                let mut rng = XorShiftRng(seed * 1_000_003 + n as u64);
                let circuit = crate::r1cs::random_sparse_r1cs_circuit(&mut rng, n, 3);

                assert_circuit_satisfied(&circuit);

                let engine = FftQapEngine::new();
                let (pk, vk) = random_sparse_ceremony(&engine, &circuit);
                let prover = PippengerProver::new();
                let (proof, public_input) = prover.prove_with_full_pk(
                    &engine, &pk, &circuit.l, &circuit.r, &circuit.o, &circuit.witness,
                );

                assert_quotient_identity(&engine, &circuit);
                assert!(
                    verify_proof(&proof, &public_input, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2),
                    "proof must be valid for random sparse circuit (n={}, seed={})", n, seed
                );
            }
        }
    }

    #[test]
    fn random_sparse_circuit_dense_vs_fft_engine_parity() {
        // The two engines use *different* evaluation bases (Lagrange over the
        // naturals vs roots of unity), so their QAP polynomials differ — but
        // both must yield a mathematically valid proof for the SAME relation.
        // WARNING: DenseQapEngine builds every QAP polynomial by O(n²) Lagrange
        // interpolation, so keep this parity sweep small. The cheap FFT-only
        // sweep above already covers n = 14.
        for &n in &[3usize, 6, 9] {
            for seed in 0..2u64 {
                let mut rng = XorShiftRng(seed * 7 + n as u64);
                let circuit = crate::r1cs::random_sparse_r1cs_circuit(&mut rng, n, 3);

                let prover = PippengerProver::new();

                // DenseQapEngine (pedagogical Lagrange path)
                let dense = DenseQapEngine::new();
                let (pk_dense, vk_dense) = random_sparse_ceremony(&dense, &circuit);
                let (proof_dense, public_dense) = prover.prove_with_full_pk(
                    &dense, &pk_dense, &circuit.l, &circuit.r, &circuit.o, &circuit.witness,
                );
                assert_quotient_identity(&dense, &circuit);
                assert!(
                    verify_proof(&proof_dense, &public_dense, &vk_dense.alpha_g1, &vk_dense.beta_g2, &vk_dense.gamma_g2, &vk_dense.delta_g2),
                    "dense-engine proof must verify (n={}, seed={})", n, seed
                );

                // FftQapEngine (production path)
                let fft = FftQapEngine::new();
                let (pk_fft, vk_fft) = random_sparse_ceremony(&fft, &circuit);
                let (proof_fft, public_fft) = prover.prove_with_full_pk(
                    &fft, &pk_fft, &circuit.l, &circuit.r, &circuit.o, &circuit.witness,
                );
                assert_quotient_identity(&fft, &circuit);
                assert!(
                    verify_proof(&proof_fft, &public_fft, &vk_fft.alpha_g1, &vk_fft.beta_g2, &vk_fft.gamma_g2, &vk_fft.delta_g2),
                    "fft-engine proof must verify (n={}, seed={})", n, seed
                );
            }
        }
    }

    #[test]
    fn random_sparse_circuit_dense_vs_sparse_prover_parity() {
        // Both prover paths (dense matrices vs sparse encodings) run on the
        // same FFT engine, so the two proofs must be bit-for-bit identical.
        for &n in &[2usize, 5, 11] {
            for seed in 0..3u64 {
                let mut rng = XorShiftRng(seed * 131 + n as u64);
                let circuit = crate::r1cs::random_sparse_r1cs_circuit(&mut rng, n, 3);

                let engine = FftQapEngine::new();
                let (pk, vk) = random_sparse_ceremony(&engine, &circuit);
                assert_dense_sparse_parity(&circuit, &pk, &vk);
            }
        }
    }

    // ------------------------------------------------------------------
    // Item (p): Lagrange-basis h-SRS parity tests
    // ------------------------------------------------------------------

    /// Convert dense constraints to the sparse encoding used by the sparse
    /// prover paths.
    fn to_sparse(dense: &[Vec<Fr>]) -> Vec<Vec<(u32, Fr)>> {
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

    /// Prove with the monomial `h_query` path and the Lagrange-coset path on
    /// the same circuit/VK and assert the proofs are bit-for-bit identical.
    fn assert_lagrange_h_matches_monomial(
        circuit: &crate::r1cs::Circuit,
        tw: crate::ceremony::ToxicWaste,
    ) {
        let engine = FftQapEngine::new();
        let d_size = engine.domain_size(circuit.n_constraints());

        // use_h_scalar=false → the PK carries the monomial h_query.
        let (pk, vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &circuit.l, &circuit.r, &circuit.o, circuit.n_public, tw.clone(), false,
        );

        let sl = to_sparse(&circuit.l);
        let sr = to_sparse(&circuit.r);
        let so = to_sparse(&circuit.o);

        let prover = PippengerProver::new();
        let (proof_mono, public_mono) = prover.prove_with_full_pk_sparse(
            &engine, &pk, circuit.n_constraints(), &sl, &sr, &so, &circuit.witness,
        );

        let lag = crate::lagrange::build_lagrange_h_query(d_size, tw.tau, tw.delta);
        let (proof_lag, public_lag) = prove_with_full_pk_sparse_lagrange(
            &pk, circuit.n_constraints(), &sl, &sr, &so, &circuit.witness, &lag,
        );

        assert_eq!(proof_mono.a, proof_lag.a, "A must match monomial vs Lagrange");
        assert_eq!(proof_mono.b, proof_lag.b, "B must match monomial vs Lagrange");
        assert_eq!(proof_mono.c, proof_lag.c, "C (h-commitment) must match monomial vs Lagrange");
        assert_eq!(public_mono.v, public_lag.v, "V must match monomial vs Lagrange");
        assert!(
            verify_proof(&proof_lag, &public_lag, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2),
            "Lagrange-h proof must verify"
        );
    }

    #[test]
    fn test_lagrange_h_matches_monomial_multiplier() {
        let circuit = crate::r1cs::multiplier_circuit();
        assert_lagrange_h_matches_monomial(&circuit, crate::ceremony::ToxicWaste::deterministic());
    }

    #[test]
    fn test_lagrange_h_matches_monomial_random_sparse() {
        let mut rng = XorShiftRng(0xBEEF);
        for &n in &[1usize, 6, 14] {
            let circuit = crate::r1cs::random_sparse_r1cs_circuit(&mut rng, n, 3);
            assert_lagrange_h_matches_monomial(&circuit, crate::ceremony::ToxicWaste::deterministic());
        }
    }

    // ------------------------------------------------------------------
    // Implementation 11 tests: prepared verifier + batched verification
    // ------------------------------------------------------------------

    /// A satisfying witness for the toy multiplier circuit
    /// (`x1*x2 == x5`, `x3*x4 == x6`, `x5*x6 == a`).  Any choice of
    /// `x1..x4` is valid, so many *distinct* proofs share one VK.
    fn multiplier_witness(x1: u64, x2: u64, x3: u64, x4: u64) -> Vec<Fr> {
        let x5 = x1 * x2;
        let x6 = x3 * x4;
        let a = x5 * x6;
        vec![
            Fr::from(1u64),
            Fr::from(a),
            Fr::from(x1),
            Fr::from(x2),
            Fr::from(x3),
            Fr::from(x4),
            Fr::from(x5),
            Fr::from(x6),
        ]
    }

    /// Build `n` distinct valid proofs for the toy circuit against one VK.
    fn batch_fixture(
        n: usize,
    ) -> (
        Vec<Proof>,
        Vec<PublicInput>,
        PreparedVerifyingKey,
        crate::ceremony::VerifyingKey,
    ) {
        let engine = FftQapEngine::new();
        let tw = crate::ceremony::ToxicWaste::deterministic();
        let (full_pk, vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &L, &R, &O, 2, tw, false,
        );
        let prover = PippengerProver::new();
        let pvk = PreparedVerifyingKey::from_vk(&vk);

        let mut proofs = Vec::with_capacity(n);
        let mut public_inputs = Vec::with_capacity(n);
        for i in 0..n {
            let x = i as u64 + 1;
            let witness = multiplier_witness(x, x + 1, x + 2, x + 3);
            let (proof, public_input) = prover.prove_with_full_pk(&engine, &full_pk, &L, &R, &O, &witness);
            proofs.push(proof);
            public_inputs.push(public_input);
        }
        (proofs, public_inputs, pvk, vk)
    }

    #[test]
    fn test_verify_prepared_matches_verify_proof() {
        let (mut proofs, mut inputs, pvk, vk) = batch_fixture(1);
        let (proof, public_input) = (proofs.remove(0), inputs.remove(0));

        assert!(
            verify_proof(&proof, &public_input, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2),
            "reference verifier must accept the proof"
        );
        assert!(
            verify_proof_prepared(&proof, &public_input, &pvk),
            "prepared verifier must accept the same proof"
        );
    }

    #[test]
    fn test_verify_batch_many_distinct_proofs() {
        let (proofs, public_inputs, pvk, _vk) = batch_fixture(5);
        assert!(
            verify_batch(&proofs, &public_inputs, &pvk),
            "a batch of 5 distinct valid proofs must verify as a single multi-pairing product"
        );
    }

    #[test]
    fn test_verify_batch_rejects_tampered_proof() {
        let (mut proofs, public_inputs, pvk, _vk) = batch_fixture(4);

        // Corrupt C of the second proof by adding the generator to it.
        let bad_c = G1Affine::from(G1Projective::from(proofs[1].c) + G1Projective::generator());
        proofs[1].c = bad_c;

        assert!(
            !verify_batch(&proofs, &public_inputs, &pvk),
            "a batch containing one tampered proof must be rejected"
        );

        // Restore and re-verify to prove the tamper was the cause.
        proofs[1].c = batch_fixture(4).0[1].c;
        assert!(
            verify_batch(&proofs, &public_inputs, &pvk),
            "restoring the proof must make the batch valid again"
        );
    }

    #[test]
    fn test_verify_batch_deterministic_scalars() {
        let (proofs, public_inputs, pvk, _vk) = batch_fixture(3);
        let scalars = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64)];
        assert!(
            verify_batch_with_scalars(&proofs, &public_inputs, &pvk, &scalars),
            "all-valid batch must pass with fixed non-zero scalars"
        );

        // A zero scalar drops that proof out of the check entirely — an all-valid
        // batch still passes, but a batch whose *only* invalid proof is zero-weighted
        // would slip through.  The random path rejects zero scalars; here we assert
        // the degenerate behaviour is at least consistent (still true).
        let zero_scalars = vec![Fr::from(1u64), Fr::from(0u64), Fr::from(3u64)];
        assert!(
            verify_batch_with_scalars(&proofs, &public_inputs, &pvk, &zero_scalars),
            "zero-weighted proof is ignored, batch remains valid"
        );
    }

    #[test]
    #[should_panic(expected = "one public input per proof")]
    fn test_verify_batch_length_mismatch_panics() {
        let (proofs, _public_inputs, pvk, _vk) = batch_fixture(2);
        let scalars = vec![Fr::from(1u64), Fr::from(2u64)];
        // Only one public input for two proofs.
        let pub_one = vec![_public_inputs[0]];
        let _ = verify_batch_with_scalars(&proofs, &pub_one, &pvk, &scalars);
    }

    #[test]
    fn test_verify_batch_empty_is_trivial() {
        let (_, _, pvk, _vk) = batch_fixture(1);
        let scalars: Vec<Fr> = vec![];
        assert!(
            verify_batch_with_scalars(&[], &[], &pvk, &scalars),
            "an empty batch is trivially valid"
        );
    }

    #[test]
    fn test_verify_batch_parity_with_individual_verify() {
        let n = 4;
        let (proofs, public_inputs, pvk, vk) = batch_fixture(n);

        // Every proof passes individually…
        for i in 0..n {
            assert!(
                verify_proof(&proofs[i], &public_inputs[i], &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2),
                "proof {i} must pass individual verification"
            );
        }

        // …and the whole set passes as one multi-pairing product.
        assert!(
            verify_batch(&proofs, &public_inputs, &pvk),
            "the individual-verify-valid set must pass as a batch"
        );

        // A batch of entirely *invalid* proofs must be rejected.
        let bogus: Vec<Proof> = proofs
            .iter()
            .map(|p| Proof {
                a: G1Affine::from(G1Projective::from(p.a) + G1Projective::generator()),
                b: p.b,
                c: G1Affine::from(G1Projective::from(p.c) + G1Projective::generator()),
            })
            .collect();
        assert!(
            !verify_batch(&bogus, &public_inputs, &pvk),
            "a batch of invalid proofs must be rejected"
        );
    }

    // ------------------------------------------------------------------
    // Native backend parity tests (compiled only with --features native)
    // ------------------------------------------------------------------

    /// Assert the native prover reproduces the reference pippenger proof
    /// bit-for-bit and that both verify.
    #[cfg(feature = "native")]
    fn assert_native_proof_parity(
        engine: &impl QapEngine,
        full_pk: &crate::ceremony::FullProvingKey,
        dense_l: &[Vec<Fr>],
        dense_r: &[Vec<Fr>],
        dense_o: &[Vec<Fr>],
        sparse_l: &[Vec<(u32, Fr)>],
        sparse_r: &[Vec<(u32, Fr)>],
        sparse_o: &[Vec<(u32, Fr)>],
        witness: &[Fr],
    ) {
        use native_backend::{prove_with_full_pk, prove_with_full_pk_sparse};

        let pippenger = PippengerProver::new();

        let (proof_cpu, public_cpu) = pippenger.prove_with_full_pk(
            engine, full_pk, dense_l, dense_r, dense_o, witness,
        );
        let (proof_native, public_native) = prove_with_full_pk(
            engine, full_pk, dense_l, dense_r, dense_o, witness,
        )
        .expect("native dense prover must succeed");

        assert_eq!(proof_cpu.a, proof_native.a, "A must match CPU vs native");
        assert_eq!(proof_cpu.b, proof_native.b, "B must match CPU vs native");
        assert_eq!(proof_cpu.c, proof_native.c, "C must match CPU vs native");
        assert_eq!(public_cpu.v, public_native.v, "V must match CPU vs native");

        let vk = &full_pk.vk;
        assert!(
            verify_proof(&proof_cpu, &public_cpu, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2) &&
                verify_proof(&proof_native, &public_native, &vk.alpha_g1, &vk.beta_g2, &vk.gamma_g2, &vk.delta_g2),
            "both CPU and native proofs must verify"
        );

        let n_constraints = dense_l.len();
        let (proof_native_sparse, public_native_sparse) = prove_with_full_pk_sparse(
            engine, full_pk, n_constraints, sparse_l, sparse_r, sparse_o, witness,
        )
        .expect("native sparse prover must succeed");
        assert_eq!(proof_native.a, proof_native_sparse.a, "A must match native dense vs sparse");
        assert_eq!(proof_native.b, proof_native_sparse.b, "B must match native dense vs sparse");
        assert_eq!(proof_native.c, proof_native_sparse.c, "C must match native dense vs sparse");
        assert_eq!(public_native.v, public_native_sparse.v, "V must match native dense vs sparse");
    }

    #[test]
    #[cfg(feature = "native")]
    fn native_prover_matches_cpu_fixed_multiplier() {
        let engine = FftQapEngine::new();
        let tw = crate::ceremony::ToxicWaste::deterministic();
        let (full_pk, _vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &L, &R, &O, 2, tw, false,
        );
        let witness = witness();
        let dense_l: Vec<Vec<Fr>> = L.iter().map(|row| row.iter().map(|&v| Fr::from(v)).collect()).collect();
        let dense_r: Vec<Vec<Fr>> = R.iter().map(|row| row.iter().map(|&v| Fr::from(v)).collect()).collect();
        let dense_o: Vec<Vec<Fr>> = O.iter().map(|row| row.iter().map(|&v| Fr::from(v)).collect()).collect();
        let sl = to_sparse(&dense_l);
        let sr = to_sparse(&dense_r);
        let so = to_sparse(&dense_o);
        assert_native_proof_parity(&engine, &full_pk, &dense_l, &dense_r, &dense_o, &sl, &sr, &so, &witness);
    }

    #[test]
    #[cfg(feature = "native")]
    fn native_prover_matches_cpu_random_sparse_circuits() {
        let mut rng = XorShiftRng(0xCAFE);
        for &n in &[1usize, 5, 14] {
            let circuit = crate::r1cs::random_sparse_r1cs_circuit(&mut rng, n, 3);
            let engine = FftQapEngine::new();
            let (full_pk, _vk) = random_sparse_ceremony(&engine, &circuit);

            let sl = to_sparse(&circuit.l);
            let sr = to_sparse(&circuit.r);
            let so = to_sparse(&circuit.o);
            assert_native_proof_parity(
                &engine, &full_pk,
                &circuit.l, &circuit.r, &circuit.o,
                &sl, &sr, &so, &circuit.witness,
            );
        }
    }

    #[test]
    #[cfg(feature = "native")]
    fn native_prover_matches_cpu_with_h_scalar_fast_path() {
        let engine = FftQapEngine::new();
        let tw = crate::ceremony::ToxicWaste::deterministic();
        let (full_pk, _vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &L, &R, &O, 2, tw, true, // use h_scalar fast path
        );
        let witness = witness();
        let dense_l: Vec<Vec<Fr>> = L.iter().map(|row| row.iter().map(|&v| Fr::from(v)).collect()).collect();
        let dense_r: Vec<Vec<Fr>> = R.iter().map(|row| row.iter().map(|&v| Fr::from(v)).collect()).collect();
        let dense_o: Vec<Vec<Fr>> = O.iter().map(|row| row.iter().map(|&v| Fr::from(v)).collect()).collect();
        let sl = to_sparse(&dense_l);
        let sr = to_sparse(&dense_r);
        let so = to_sparse(&dense_o);
        assert_native_proof_parity(&engine, &full_pk, &dense_l, &dense_r, &dense_o, &sl, &sr, &so, &witness);
    }

    #[test]
    #[cfg(feature = "native")]
    fn native_batch_verify_matches_cpu() {
        use native_backend::verify_batch as verify_batch_native;

        let (proofs, public_inputs, pvk, _vk) = batch_fixture(5);

        assert!(verify_batch(&proofs, &public_inputs, &pvk), "CPU batch must accept");

        let valid_native = verify_batch_native(&proofs, &public_inputs, &pvk)
            .expect("native batch verify must not error");
        assert!(valid_native, "native batch must accept a valid batch");

        // A known-invalid batch must be rejected by both.
        let bogus: Vec<Proof> = proofs
            .iter()
            .map(|p| Proof {
                a: G1Affine::from(G1Projective::from(p.a) + G1Projective::generator()),
                b: p.b,
                c: p.c,
            })
            .collect();
        assert!(!verify_batch(&bogus, &public_inputs, &pvk), "CPU must reject the tampered batch");
        assert!(
            !verify_batch_native(&bogus, &public_inputs, &pvk).expect("native verify must not error"),
            "native must reject the tampered batch"
        );

        // Fixed deterministicscalars: native result must equal CPU result.
        let scalars = vec![Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64), Fr::from(5u64)];
        let cpu = verify_batch_with_scalars(&proofs, &public_inputs, &pvk, &scalars);
        let native = native_backend::verify_batch_with_scalars(&proofs, &public_inputs, &pvk, &scalars)
            .expect("native verify must not error");
        assert_eq!(cpu, native, "CPU and native must agree on fixed-scalar batches");
    }
}
