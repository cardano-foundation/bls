use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, Group, VariableBaseMSM};
use ark_ff::{Field, Zero};
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
}
