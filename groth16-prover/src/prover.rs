use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{pairing::Pairing, AffineRepr, Group, VariableBaseMSM};
use ark_ff::{Field, Zero};
use ark_poly::{univariate::DensePolynomial, Polynomial};
use ark_std::vec::Vec;

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
    fn prove<E: QapEngine, L: AsRef<[u64]>, R: AsRef<[u64]>, O: AsRef<[u64]>>(
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
    ///
    /// Default implementation panics — concrete provers must override.
    fn prove_with_full_pk<E: QapEngine, L: AsRef<[u64]>, R: AsRef<[u64]>, O: AsRef<[u64]>>(
        &self,
        engine: &E,
        full_pk: &crate::ceremony::FullProvingKey,
        l: &[L],
        r: &[R],
        o: &[O],
        witness: &[Fr],
    ) -> (Proof, PublicInput) {
        let _ = (engine, full_pk, l, r, o, witness);
        unimplemented!("prove_with_full_pk must be implemented for this prover")
    }
}

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
    fn prove<E: QapEngine, Lm: AsRef<[u64]>, Rm: AsRef<[u64]>, Om: AsRef<[u64]>>(
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
        let g2_proj = G2Projective::generator();

        let (us_tau, vs_tau, ws_tau) = engine.evaluate_qap_at_tau(l, r, o, tau);

        // ------------------------------------------------------------------
        // A = l(tau)·G1 + alpha·G1
        // ------------------------------------------------------------------
        let mut l_tau = Fr::zero();
        for i in 0..witness.len() {
            l_tau += us_tau[i] * witness[i];
        }
        let a_pt = g1_proj * (l_tau + alpha);
        let a = G1Affine::from(a_pt);

        // ------------------------------------------------------------------
        // B = r(tau)·G2 + beta·G2
        // ------------------------------------------------------------------
        let mut r_tau = Fr::zero();
        for i in 0..witness.len() {
            r_tau += vs_tau[i] * witness[i];
        }
        let b_pt = g2_proj * (r_tau + beta);
        let b = G2Affine::from(b_pt);

        // ------------------------------------------------------------------
        // C = sum_{private} a_i·Psi_P_G1 + h(tau)·T(tau)/delta·G1
        // ------------------------------------------------------------------
        let gamma_inv = gamma.inverse().unwrap();
        let delta_inv = delta.inverse().unwrap();

        // Compute h(tau) from the quotient polynomial
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

        let mut c_proj = G1Projective::zero();
        for i in 2..witness.len() {
            let psi_scalar = (vs_tau[i] * alpha + us_tau[i] * beta + ws_tau[i]) * delta_inv;
            let weighted = g1_proj * (psi_scalar * witness[i]);
            c_proj += weighted;
        }
        c_proj += g1_proj * h_tau_scalar;
        let c = G1Affine::from(c_proj);

        // ------------------------------------------------------------------
        // V = sum_{public} a_i·Psi_V_G1
        // ------------------------------------------------------------------
        let mut v_proj = G1Projective::zero();
        for i in 0..2 {
            let psi_scalar = (vs_tau[i] * alpha + us_tau[i] * beta + ws_tau[i]) * gamma_inv;
            let weighted = g1_proj * (psi_scalar * witness[i]);
            v_proj += weighted;
        }
        let v = G1Affine::from(v_proj);

        (Proof { a, b, c }, PublicInput { v })
    }

    fn prove_with_full_pk<E: QapEngine, Lm: AsRef<[u64]>, Rm: AsRef<[u64]>, Om: AsRef<[u64]>>(
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

        // 1. Build witness polynomials and quotient h(x)
        let (us, vs, ws) = engine.build_qap(l, r, o);
        let mut l_poly = DensePolynomial::zero();
        let mut r_poly = DensePolynomial::zero();
        let mut o_poly = DensePolynomial::zero();
        for i in 0..n_vars {
            l_poly = poly_add(&l_poly, &poly_scalar_mul(&us[i], witness[i]));
            r_poly = poly_add(&r_poly, &poly_scalar_mul(&vs[i], witness[i]));
            o_poly = poly_add(&o_poly, &poly_scalar_mul(&ws[i], witness[i]));
        }
        let t = engine.target_poly(l.len());
        let h = engine.compute_quotient(&l_poly, &r_poly, &o_poly, &t);

        // 2. A = sum witness[i] * a_query[i] + alpha_g1
        let mut a_proj = G1Projective::from(full_pk.vk.alpha_g1);
        for i in 0..n_vars {
            a_proj += G1Projective::from(full_pk.a_query[i]) * witness[i];
        }
        let a = G1Affine::from(a_proj);

        // 3. B = sum witness[i] * b_g2_query[i] + beta_g2
        let mut b_proj = G2Projective::from(full_pk.vk.beta_g2);
        for i in 0..n_vars {
            b_proj += G2Projective::from(full_pk.b_g2_query[i]) * witness[i];
        }
        let b = G2Affine::from(b_proj);

        // 4. C = sum_{private} witness[i] * c_query[i] + sum_j h_j * h_query[j]
        let mut c_proj = G1Projective::zero();
        for i in n_public..n_vars {
            c_proj += G1Projective::from(full_pk.c_query[i]) * witness[i];
        }
        let h_len = h.coeffs.len().min(full_pk.h_query.len());
        for j in 0..h_len {
            c_proj += G1Projective::from(full_pk.h_query[j]) * h.coeffs[j];
        }
        let c = G1Affine::from(c_proj);

        // 5. V = sum_{public} witness[i] * l_query[i]
        let mut v_proj = G1Projective::zero();
        for i in 0..n_public {
            v_proj += G1Projective::from(full_pk.l_query[i]) * witness[i];
        }
        let v = G1Affine::from(v_proj);

        (Proof { a, b, c }, PublicInput { v })
    }
}

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
    fn prove<E: QapEngine, Lm: AsRef<[u64]>, Rm: AsRef<[u64]>, Om: AsRef<[u64]>>(
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
        let g2_proj = G2Projective::generator();
        let g1_gen = G1Affine::generator();

        let (us_tau, vs_tau, ws_tau) = engine.evaluate_qap_at_tau(l, r, o, tau);

        // ------------------------------------------------------------------
        // A = l(tau)·G1 + alpha·G1
        // ------------------------------------------------------------------
        let mut l_tau = Fr::zero();
        for i in 0..witness.len() {
            l_tau += us_tau[i] * witness[i];
        }
        let a_pt = g1_proj * (l_tau + alpha);
        let a = G1Affine::from(a_pt);

        // ------------------------------------------------------------------
        // B = r(tau)·G2 + beta·G2
        // ------------------------------------------------------------------
        let mut r_tau = Fr::zero();
        for i in 0..witness.len() {
            r_tau += vs_tau[i] * witness[i];
        }
        let b_pt = g2_proj * (r_tau + beta);
        let b = G2Affine::from(b_pt);

        // ------------------------------------------------------------------
        // C = sum_{private} a_i·Psi_P_G1 + h(tau)·T(tau)/delta·G1
        // ------------------------------------------------------------------
        let gamma_inv = gamma.inverse().unwrap();
        let delta_inv = delta.inverse().unwrap();

        // Compute h(tau) from the quotient polynomial
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

        // Collect bases (all G1 generator) and scalars for private-input MSM
        let n_private = witness.len() - 2;
        let mut c_bases = Vec::with_capacity(n_private + 1);
        let mut c_scalars = Vec::with_capacity(n_private + 1);
        for i in 2..witness.len() {
            let psi_scalar = (vs_tau[i] * alpha + us_tau[i] * beta + ws_tau[i]) * delta_inv;
            c_bases.push(g1_gen);
            c_scalars.push(psi_scalar * witness[i]);
        }
        // Add h_tau term
        c_bases.push(g1_gen);
        c_scalars.push(h_tau_scalar);

        let c_proj = G1Projective::msm(&c_bases, &c_scalars).expect("MSM length mismatch");
        let c = G1Affine::from(c_proj);

        // ------------------------------------------------------------------
        // V = sum_{public} a_i·Psi_V_G1
        // ------------------------------------------------------------------
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

    fn prove_with_full_pk<E: QapEngine, Lm: AsRef<[u64]>, Rm: AsRef<[u64]>, Om: AsRef<[u64]>>(
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

        // 1. Build witness polynomials and quotient h(x)
        let (us, vs, ws) = engine.build_qap(l, r, o);
        let mut l_poly = DensePolynomial::zero();
        let mut r_poly = DensePolynomial::zero();
        let mut o_poly = DensePolynomial::zero();
        for i in 0..n_vars {
            l_poly = poly_add(&l_poly, &poly_scalar_mul(&us[i], witness[i]));
            r_poly = poly_add(&r_poly, &poly_scalar_mul(&vs[i], witness[i]));
            o_poly = poly_add(&o_poly, &poly_scalar_mul(&ws[i], witness[i]));
        }
        let t = engine.target_poly(l.len());
        let h = engine.compute_quotient(&l_poly, &r_poly, &o_poly, &t);

        // 2. A = MSM(a_query, witness) + alpha_g1
        let a_proj = G1Projective::msm(&full_pk.a_query, witness)
            .expect("MSM length mismatch");
        let a = G1Affine::from(a_proj + G1Projective::from(full_pk.vk.alpha_g1));

        // 3. B = MSM(b_g2_query, witness) + beta_g2
        let b_proj = G2Projective::msm(&full_pk.b_g2_query, witness)
            .expect("MSM length mismatch");
        let b = G2Affine::from(b_proj + G2Projective::from(full_pk.vk.beta_g2));

        // 4. C = MSM(c_query[private], witness[private]) + MSM(h_query, h_coeffs)
        let private_c = &full_pk.c_query[n_public..];
        let private_w = &witness[n_public..];
        let c_private = G1Projective::msm(private_c, private_w)
            .expect("MSM length mismatch");

        let h_len = h.coeffs.len().min(full_pk.h_query.len());
        let h_c = if h_len > 0 {
            G1Projective::msm(&full_pk.h_query[..h_len], &h.coeffs[..h_len])
                .expect("MSM length mismatch")
        } else {
            G1Projective::zero()
        };

        let c = G1Affine::from(c_private + h_c);

        // 5. V = MSM(l_query, witness[public])
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

        let l_ref: Vec<&[u64]> = L.iter().map(|v| v.as_slice()).collect();
        let r_ref: Vec<&[u64]> = R.iter().map(|v| v.as_slice()).collect();
        let o_ref: Vec<&[u64]> = O.iter().map(|v| v.as_slice()).collect();

        // Old scalar-based path
        let (proof_old, public_old) = prover.prove(
            &engine, &l_ref, &r_ref, &o_ref, &witness,
            tw.tau, tw.alpha, tw.beta, tw.gamma, tw.delta,
        );

        // New group-element path
        let (full_pk, _vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &l_ref, &r_ref, &o_ref, 2, tw,
        );
        let (proof_new, public_new) = prover.prove_with_full_pk(
            &engine, &full_pk, &l_ref, &r_ref, &o_ref, &witness,
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

        let l_ref: Vec<&[u64]> = L.iter().map(|v| v.as_slice()).collect();
        let r_ref: Vec<&[u64]> = R.iter().map(|v| v.as_slice()).collect();
        let o_ref: Vec<&[u64]> = O.iter().map(|v| v.as_slice()).collect();

        // Old scalar-based path
        let (proof_old, public_old) = prover.prove(
            &engine, &l_ref, &r_ref, &o_ref, &witness,
            tw.tau, tw.alpha, tw.beta, tw.gamma, tw.delta,
        );

        // New group-element path
        let (full_pk, _vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &l_ref, &r_ref, &o_ref, 2, tw,
        );
        let (proof_new, public_new) = prover.prove_with_full_pk(
            &engine, &full_pk, &l_ref, &r_ref, &o_ref, &witness,
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

        let l_ref: Vec<&[u64]> = L.iter().map(|v| v.as_slice()).collect();
        let r_ref: Vec<&[u64]> = R.iter().map(|v| v.as_slice()).collect();
        let o_ref: Vec<&[u64]> = O.iter().map(|v| v.as_slice()).collect();

        let (full_pk, _vk) = crate::ceremony::single_party_ceremony_full_from_tw(
            &engine, &l_ref, &r_ref, &o_ref, 2, tw,
        );
        let (proof, public_input) = prover.prove_with_full_pk(
            &engine, &full_pk, &l_ref, &r_ref, &o_ref, &witness,
        );

        assert!(
            verify_proof(&proof, &public_input, &full_pk.vk.alpha_g1, &full_pk.vk.beta_g2, &full_pk.vk.gamma_g2, &full_pk.vk.delta_g2),
            "FullPK prover must produce a valid proof"
        );
    }
}
