//! Trusted-setup ceremony for Groth16.
//!
//! Generates random toxic-waste scalars (`tau`, `alpha`, `beta`, `gamma`, `delta`)
//! using a cryptographically secure RNG, then computes the proving key and
//! verification key for a given circuit.
//!
//! # Warning
//!
//! The `ProvingKey` produced here contains the raw toxic-waste scalars because
//! our current prover computes proof elements on-the-fly from them.  In a
//! production deployment the scalars would be destroyed after the ceremony
//! and only the pre-computed group elements (the "proving key" in the
//! snarkjs/ark-groth16 sense) would be retained.  Use this only for
//! development, testing, and benchmarking.

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::Group;
use ark_ff::Field;
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{vec::Vec, One, Zero};
use rand::RngCore;

use crate::engine::QapEngine;

/// The five secret scalars generated during the trusted-setup ceremony.
/// In a real deployment these would be created inside an MPC and
/// immediately destroyed.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ToxicWaste {
    pub tau: Fr,
    pub alpha: Fr,
    pub beta: Fr,
    pub gamma: Fr,
    pub delta: Fr,
}

impl ToxicWaste {
    /// Generate random toxic waste from a cryptographically secure RNG.
    pub fn random<R: RngCore>(rng: &mut R) -> Self {
        // rejection-sample until we get non-zero values that are pairwise distinct
        let mut scalars = [Fr::zero(); 5];
        loop {
            let mut ok = true;
            let mut bytes = [0u8; 32];
            for s in &mut scalars {
                rng.fill_bytes(&mut bytes);
                *s = Fr::from_random_bytes(&bytes).unwrap_or(Fr::zero());
                if s.is_zero() {
                    ok = false;
                }
            }
            if !ok {
                continue;
            }
            // check pairwise distinct
            for i in 0..5 {
                for j in (i + 1)..5 {
                    if scalars[i] == scalars[j] {
                        ok = false;
                    }
                }
            }
            if ok {
                break;
            }
        }
        Self {
            tau: scalars[0],
            alpha: scalars[1],
            beta: scalars[2],
            gamma: scalars[3],
            delta: scalars[4],
        }
    }

    /// The deterministic test values used throughout the crate.
    /// `tau=3, alpha=5, beta=7, gamma=11, delta=13`.
    pub fn deterministic() -> Self {
        Self {
            tau: Fr::from(3u64),
            alpha: Fr::from(5u64),
            beta: Fr::from(7u64),
            gamma: Fr::from(11u64),
            delta: Fr::from(13u64),
        }
    }
}

/// Verification key — everything the on-chain verifier needs.
///
/// Contains the four CRS fixed points plus the `ic` (input commitment)
/// points `Psi_V_G1` for every variable.  Only the first `n_public`
/// entries of `ic` are used when computing `V`.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifyingKey {
    pub alpha_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,
    /// `ic[i] = Psi_V_G1[i]` for variable i.
    pub ic: Vec<G1Affine>,
    /// Number of public variables (including the constant wire).
    pub n_public: usize,
}

/// Proving key — everything the off-chain prover needs.
///
/// # Warning
///
/// This structure contains the raw toxic-waste scalars.  In production
/// these would be destroyed after the ceremony.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProvingKey {
    pub vk: VerifyingKey,
    pub toxic_waste: ToxicWaste,
}

/// Full proving key — group elements only, no toxic-waste scalars.
///
/// This is the production-grade proving-key format.  It contains
/// pre-computed curve points that the prover uses directly via
/// multi-scalar multiplication.  It is compatible with the
/// `ark_groth16::ProvingKey` layout.
///
/// # Lifecycle
///
/// 1. **Single-party dev path** — `single_party_ceremony_full()` generates
///    this from random scalars that are immediately dropped.
/// 2. **MPC production path** — Phase 2 contributions produce the same
///    structure; no participant ever reconstructs the scalars.
///
/// In both cases the artifact that ends up on disk contains **no secrets**.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct FullProvingKey {
    pub vk: VerifyingKey,
    /// `beta·G1` — used in the C-term MSM
    pub beta_g1: G1Affine,
    /// `delta·G1` — optional, kept for arkworks compatibility
    pub delta_g1: G1Affine,
    /// `u_i(tau)·G1` per variable — basis for `A = MSM(a_query, witness) + alpha_g1`
    pub a_query: Vec<G1Affine>,
    /// `v_i(tau)·G1` per variable — basis for cross-terms in C
    pub b_g1_query: Vec<G1Affine>,
    /// `v_i(tau)·G2` per variable — basis for `B = MSM(b_g2_query, witness) + beta_g2`
    pub b_g2_query: Vec<G2Affine>,
    /// `delta_inv·(beta·u_i + alpha·v_i + w_i)(tau)·G1` for private variables
    pub c_query: Vec<G1Affine>,
    /// `delta_inv·tau^j·T(tau)·G1` for j = 0..deg(h) — basis for the quotient commitment
    pub h_query: Vec<G1Affine>,
    /// Public-input subset of `c_query` (same content as `vk.ic` but stored here for arkworks parity)
    pub l_query: Vec<G1Affine>,
}

/// Run the trusted-setup ceremony for a given circuit.
///
/// * `engine`   — QAP engine (dense or FFT).
/// * `l, r, o`  — R1CS matrices.
/// * `n_public` — number of public variables (including the constant wire).
/// * `rng`      — cryptographically secure RNG.
///
/// Returns `(ProvingKey, VerifyingKey)`.
pub fn ceremony<E: QapEngine, L: AsRef<[u64]>, R: AsRef<[u64]>, O: AsRef<[u64]>>(
    engine: &E,
    l: &[L],
    r: &[R],
    o: &[O],
    n_public: usize,
    rng: &mut impl RngCore,
) -> (ProvingKey, VerifyingKey) {
    // 1. Generate random toxic waste
    let tw = ToxicWaste::random(rng);

    // 2. Evaluate QAP at tau
    let (us_tau, vs_tau, ws_tau) = engine.evaluate_qap_at_tau(l, r, o, tw.tau);

    let n_vars = us_tau.len();
    assert!(
        n_public <= n_vars,
        "n_public ({}) cannot exceed n_vars ({})",
        n_public,
        n_vars
    );

    // 3. Compute CRS fixed points
    let g1_proj = G1Projective::generator();
    let g2_proj = G2Projective::generator();

    let alpha_g1 = G1Affine::from(g1_proj * tw.alpha);
    let beta_g2 = G2Affine::from(g2_proj * tw.beta);
    let gamma_g2 = G2Affine::from(g2_proj * tw.gamma);
    let delta_g2 = G2Affine::from(g2_proj * tw.delta);

    // 4. Compute per-variable Psi points (both public and private)
    let gamma_inv = tw.gamma.inverse().unwrap();
    let _delta_inv = tw.delta.inverse().unwrap(); // kept for symmetry; prover uses it later

    let mut ic = Vec::with_capacity(n_vars);
    for i in 0..n_vars {
        let psi_scalar = vs_tau[i] * tw.alpha + us_tau[i] * tw.beta + ws_tau[i];
        // Store the "full" psi scalar; division by gamma vs delta is handled by the prover/verifier
        // For the VK we only need the public points (divided by gamma).
        let psi_v = psi_scalar * gamma_inv;
        ic.push(G1Affine::from(g1_proj * psi_v));
    }

    let vk = VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        ic,
        n_public,
    };

    let pk = ProvingKey {
        vk: vk.clone(),
        toxic_waste: tw,
    };

    (pk, vk)
}

/// Verify a Groth16 proof using a `VerifyingKey`.
///
/// This is the same pairing check as `crate::prover::verify_proof`, but it
/// loads the CRS points from a `VerifyingKey` instead of re-deriving them
/// from hard-coded scalars.
pub fn verify_with_vk(
    proof: &crate::prover::Proof,
    public_input: &crate::prover::PublicInput,
    vk: &VerifyingKey,
) -> bool {
    crate::prover::verify_proof(
        proof,
        public_input,
        &vk.alpha_g1,
        &vk.beta_g2,
        &vk.gamma_g2,
        &vk.delta_g2,
    )
}

/// Run a single-party ceremony that produces a `FullProvingKey` (group elements only).
///
/// This is the **dev-mode** path: randomness is generated locally, all group
/// elements are computed from it, and the scalars are dropped before the
/// function returns.  The resulting `FullProvingKey` contains **no secrets**.
///
/// The output format is identical to what a Phase-2 MPC would produce, so
/// the downstream `prove` / `verify` code is agnostic.
pub fn single_party_ceremony_full<E: QapEngine, L: AsRef<[u64]>, R: AsRef<[u64]>, O: AsRef<[u64]>>(
    engine: &E,
    l: &[L],
    r: &[R],
    o: &[O],
    n_public: usize,
    rng: &mut impl RngCore,
) -> (FullProvingKey, VerifyingKey) {
    // 1. Generate random toxic waste (destroyed before we return)
    let tw = ToxicWaste::random(rng);

    // 2. Evaluate QAP at tau
    let (us_tau, vs_tau, ws_tau) = engine.evaluate_qap_at_tau(l, r, o, tw.tau);
    let n_vars = us_tau.len();
    assert!(
        n_public <= n_vars,
        "n_public ({}) cannot exceed n_vars ({})",
        n_public,
        n_vars
    );

    // 3. CRS fixed points
    let g1_proj = G1Projective::generator();
    let g2_proj = G2Projective::generator();

    let alpha_g1 = G1Affine::from(g1_proj * tw.alpha);
    let beta_g1 = G1Affine::from(g1_proj * tw.beta);
    let beta_g2 = G2Affine::from(g2_proj * tw.beta);
    let gamma_g2 = G2Affine::from(g2_proj * tw.gamma);
    let delta_g1 = G1Affine::from(g1_proj * tw.delta);
    let delta_g2 = G2Affine::from(g2_proj * tw.delta);

    // 4. Inverses (consumed immediately, never stored)
    let gamma_inv = tw.gamma.inverse().unwrap();
    let delta_inv = tw.delta.inverse().unwrap();

    // 5. Per-variable queries
    let mut a_query = Vec::with_capacity(n_vars);
    let mut b_g1_query = Vec::with_capacity(n_vars);
    let mut b_g2_query = Vec::with_capacity(n_vars);
    let mut c_query = Vec::with_capacity(n_vars);
    let mut ic = Vec::with_capacity(n_vars);

    for i in 0..n_vars {
        let u_i = us_tau[i];
        let v_i = vs_tau[i];
        let w_i = ws_tau[i];

        // a_query[i] = u_i(tau) * G1
        a_query.push(G1Affine::from(g1_proj * u_i));

        // b_g1_query[i] = v_i(tau) * G1
        b_g1_query.push(G1Affine::from(g1_proj * v_i));

        // b_g2_query[i] = v_i(tau) * G2
        b_g2_query.push(G2Affine::from(g2_proj * v_i));

        // psi_scalar = beta*u_i(tau) + alpha*v_i(tau) + w_i(tau)
        let psi_scalar = v_i * tw.alpha + u_i * tw.beta + w_i;

        // c_query[i] = delta_inv * psi_scalar * G1  (for private variables)
        c_query.push(G1Affine::from(g1_proj * (psi_scalar * delta_inv)));

        // ic[i] = gamma_inv * psi_scalar * G1  (public-input commitment points)
        ic.push(G1Affine::from(g1_proj * (psi_scalar * gamma_inv)));
    }

    // 6. l_query = public-input subset of c_query (same as ic, for arkworks parity)
    let l_query = ic[..n_public].to_vec();

    // 7. h_query[j] = delta_inv * tau^j * T(tau) * G1
    let t = engine.target_poly(l.len());
    let t_tau = t.evaluate(&tw.tau);
    let h_scalar_base = t_tau * delta_inv;
    let h_query_len = t.degree(); // safe upper bound on deg(h) + 1
    let mut h_query = Vec::with_capacity(h_query_len);
    let mut tau_pow = Fr::one();
    for _ in 0..h_query_len {
        h_query.push(G1Affine::from(g1_proj * (tau_pow * h_scalar_base)));
        tau_pow *= tw.tau;
    }

    // 8. Build VK (same as old ceremony)
    let vk = VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        ic,
        n_public,
    };

    // 9. Build FullProvingKey (scalars are dropped here — tw goes out of scope)
    let full_pk = FullProvingKey {
        vk: vk.clone(),
        beta_g1,
        delta_g1,
        a_query,
        b_g1_query,
        b_g2_query,
        c_query,
        h_query,
        l_query,
    };

    (full_pk, vk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{DenseQapEngine, FftQapEngine};
    use crate::prover::{NaiveProver, PippengerProver, Prover};
    use crate::r1cs::{L, O, R, WITNESS};
    use ark_bls12_381::Fr;

    #[test]
    fn test_ceremony_deterministic_matches_hardcoded() {
        // Run the ceremony with deterministic toxic waste and verify
        // the proof is accepted by the generated VK.
        let engine = DenseQapEngine::new();
        let tw = ToxicWaste::deterministic();

        let (us_tau, vs_tau, ws_tau) = engine.evaluate_qap_at_tau(&L, &R, &O, tw.tau);
        let n_vars = us_tau.len();

        let g1_proj = G1Projective::generator();
        let g2_proj = G2Projective::generator();

        let alpha_g1 = G1Affine::from(g1_proj * tw.alpha);
        let beta_g2 = G2Affine::from(g2_proj * tw.beta);
        let gamma_g2 = G2Affine::from(g2_proj * tw.gamma);
        let delta_g2 = G2Affine::from(g2_proj * tw.delta);

        let gamma_inv = tw.gamma.inverse().unwrap();
        let delta_inv = tw.delta.inverse().unwrap();

        let mut ic = Vec::with_capacity(n_vars);
        for i in 0..n_vars {
            let psi_scalar = vs_tau[i] * tw.alpha + us_tau[i] * tw.beta + ws_tau[i];
            let psi_v = psi_scalar * gamma_inv;
            ic.push(G1Affine::from(g1_proj * psi_v));
        }

        let vk = VerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
            n_public: 2,
        };

        let pk = ProvingKey {
            vk: vk.clone(),
            toxic_waste: tw,
        };

        // Prove
        let prover = NaiveProver::new();
        let witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();
        let (proof, public_input) = prover.prove(
            &engine,
            &L,
            &R,
            &O,
            &witness,
            pk.toxic_waste.tau,
            pk.toxic_waste.alpha,
            pk.toxic_waste.beta,
            pk.toxic_waste.gamma,
            pk.toxic_waste.delta,
        );

        assert!(
            verify_with_vk(&proof, &public_input, &vk),
            "Proof generated with deterministic ceremony must verify"
        );
    }

    #[test]
    fn test_ceremony_random_produces_valid_proof() {
        // Run a random ceremony and prove/verify end-to-end.
        let mut rng = rand::thread_rng();
        let engine = FftQapEngine::new();

        let l_ref: Vec<&[u64]> = L.iter().map(|v| v.as_slice()).collect();
        let r_ref: Vec<&[u64]> = R.iter().map(|v| v.as_slice()).collect();
        let o_ref: Vec<&[u64]> = O.iter().map(|v| v.as_slice()).collect();

        let (pk, vk) = ceremony(&engine, &l_ref, &r_ref, &o_ref, 2, &mut rng);

        // Prove
        let prover = PippengerProver::new();
        let witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();
        let (proof, public_input) = prover.prove(
            &engine,
            &l_ref,
            &r_ref,
            &o_ref,
            &witness,
            pk.toxic_waste.tau,
            pk.toxic_waste.alpha,
            pk.toxic_waste.beta,
            pk.toxic_waste.gamma,
            pk.toxic_waste.delta,
        );

        assert!(
            verify_with_vk(&proof, &public_input, &vk),
            "Proof generated after random ceremony must verify"
        );
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut rng = rand::thread_rng();
        let engine = FftQapEngine::new();

        let l_ref: Vec<&[u64]> = L.iter().map(|v| v.as_slice()).collect();
        let r_ref: Vec<&[u64]> = R.iter().map(|v| v.as_slice()).collect();
        let o_ref: Vec<&[u64]> = O.iter().map(|v| v.as_slice()).collect();

        let (pk, _vk) = ceremony(&engine, &l_ref, &r_ref, &o_ref, 2, &mut rng);

        // Serialize
        let mut pk_bytes = Vec::new();
        pk.serialize_compressed(&mut pk_bytes).unwrap();

        // Deserialize
        let pk2 = ProvingKey::deserialize_compressed(&pk_bytes[..]).unwrap();

        assert_eq!(pk.toxic_waste.tau, pk2.toxic_waste.tau);
        assert_eq!(pk.toxic_waste.alpha, pk2.toxic_waste.alpha);
        assert_eq!(pk.toxic_waste.beta, pk2.toxic_waste.beta);
        assert_eq!(pk.toxic_waste.gamma, pk2.toxic_waste.gamma);
        assert_eq!(pk.toxic_waste.delta, pk2.toxic_waste.delta);
        assert_eq!(pk.vk.n_public, pk2.vk.n_public);
        assert_eq!(pk.vk.ic.len(), pk2.vk.ic.len());
        for i in 0..pk.vk.ic.len() {
            assert_eq!(pk.vk.ic[i], pk2.vk.ic[i]);
        }
    }
}
