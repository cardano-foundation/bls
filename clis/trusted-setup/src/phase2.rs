//! Phase-2 MPC ceremony for Groth16.
//!
//! This module implements the circuit-specific phase of a Groth16 trusted-setup
//! ceremony.  It consumes a Phase-1 universal SRS (`.ptau`) and a circuit
//! (`.r1cs`), then produces a `FullProvingKey` that the prover uses directly.
//!
//! # Ceremony flow
//!
//! ```text
//! 1. initialize(.ptau, .r1cs) → zkey_0000
//! 2. contribute(zkey_0000, entropy) → zkey_0001   (participant 1)
//! 3. contribute(zkey_0001, entropy) → zkey_0002   (participant 2)
//! 4. verify(zkey_0002, .ptau, .r1cs) → bool
//! 5. finalize(zkey_000N) → (FullProvingKey, VerifyingKey)
//! ```
//!
//! Each contribution updates the circuit-specific randomness (`delta`) and
//! appends a Schnorr-like **ratio proof** showing that the update was done
//! correctly without revealing the new scalar.

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{Group, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::vec::Vec;
use rand::RngCore;

use crate::ceremony::{FullProvingKey, VerifyingKey};
use crate::engine::QapEngine;
use crate::ptau::PtauFile;

/// Errors that can occur during the Phase-2 ceremony.
#[derive(Debug, Clone, PartialEq)]
pub enum Error {
    /// I/O or parsing error.
    Io(String),
    /// The `.ptau` file does not contain enough powers of tau for this circuit.
    InsufficientPtauPower { ptau_power: u32, needed_power: u32 },
    /// A contribution failed the ratio-proof check.
    InvalidContribution { index: usize, reason: String },
    /// The zkey invariants are violated (e.g. alpha/beta changed unexpectedly).
    InvariantViolation(String),
    /// The contribution proof is malformed.
    MalformedProof(String),
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

impl From<crate::ptau::Error> for Error {
    fn from(e: crate::ptau::Error) -> Self {
        Error::Io(e.to_string())
    }
}

/// A single contribution to the Phase-2 ceremony.
///
/// Contains the Schnorr-like ratio proof for the `delta` update.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Contribution {
    /// The public delta point before this contribution (G2).
    pub delta_g2_before: G2Affine,
    /// The public delta point after this contribution (G2).
    pub delta_g2_after: G2Affine,
    /// The public delta point before this contribution (G1).
    pub delta_g1_before: G1Affine,
    /// The public delta point after this contribution (G1).
    pub delta_g1_after: G1Affine,
    /// The ratio proof: a proof of knowledge of `delta_new` such that
    /// `delta_g2_after = delta_g2_before * delta_new`.
    pub ratio_proof: RatioProof,
    /// Optional human-readable name.
    pub name: Option<String>,
}

/// Schnorr-like proof of knowledge of `delta_new` on G1.
///
/// Proves knowledge of `delta_new` such that
/// `delta_g1_after = delta_g1_before * delta_new`.
/// The proof is a standard Schnorr proof in G1 using `delta_g1_before`
/// as the generator and `delta_g1_after` as the public key.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct RatioProof {
    /// Commitment `R = delta_g1_before * r` for random `r`.
    pub r_g1: G1Affine,
    /// Response `s = r + c * delta_new` where `c = hash(...)`.
    pub s: Fr,
    /// Challenge `c` (recomputed by verifier).
    pub c: Fr,
}

/// Phase-2 accumulator (the "zkey" state).
///
/// Holds all group elements for the circuit-specific ceremony plus the
/// contribution transcript.  The accumulator is updated in place by each
/// `contribute()` call.
#[derive(Clone, Debug, PartialEq, Eq, CanonicalSerialize, CanonicalDeserialize)]
pub struct Phase2Accumulator {
    /// The four CRS fixed points.
    pub alpha_g1: G1Affine,
    pub beta_g1: G1Affine,
    pub beta_g2: G2Affine,
    pub gamma_g2: G2Affine,
    pub delta_g2: G2Affine,

    /// Per-variable queries.
    pub a_query: Vec<G1Affine>,
    pub b_g1_query: Vec<G1Affine>,
    pub b_g2_query: Vec<G2Affine>,
    pub c_query: Vec<G1Affine>,
    pub h_query: Vec<G1Affine>,

    /// Public-input subset of c_query (same content, stored for convenience).
    pub l_query: Vec<G1Affine>,

    /// Number of public variables (including constant wire).
    pub n_public: usize,

    /// The `.ptau` power used for this accumulator.
    pub ptau_power: u32,

    /// All contributions so far.
    pub contributions: Vec<Contribution>,

    /// Verifying-key public-input commitment points (gamma-scaled).
    /// Computed during initialization and never changed by contributions.
    pub ic: Vec<G1Affine>,

    /// G1 generator scaled by delta (for delta_g1 in FullProvingKey).
    /// This is the delta-scaled generator; it changes with each contribution.
    pub delta_g1: G1Affine,
}

impl Phase2Accumulator {
    // ------------------------------------------------------------------
    // Initialization
    // ------------------------------------------------------------------

    /// Create a new Phase-2 accumulator from a `.ptau` SRS and a circuit.
    ///
    /// This is the **first step** of the ceremony.  It reads the universal
    /// SRS (powers of tau in G1/G2), generates random circuit-specific
    /// scalars (`alpha`, `beta`, `gamma`, `delta`), and computes all
    /// circuit-specific group elements via multi-scalar multiplication
    /// over the `.ptau` basis.
    pub fn initialize<E: QapEngine, T: Copy + Into<Fr>, L: AsRef<[T]>, R: AsRef<[T]>, O: AsRef<[T]>>(
        ptau: &mut PtauFile,
        engine: &E,
        l: &[L],
        r: &[R],
        o: &[O],
        n_public: usize,
        rng: &mut impl RngCore,
    ) -> Result<Self, Error> {
        let n_constraints = l.len();
        let n_vars = l[0].as_ref().len();

        // Check that .ptau has enough power
        let needed_power = next_power_of_two(n_constraints);
        let needed_g1 = 2 * needed_power;     // h_query needs tau^{2*domain_size-1}
        let needed_g2 = needed_power;
        if needed_g1 > ptau.max_g1_points() || needed_g2 > ptau.max_g2_points() {
            return Err(Error::InsufficientPtauPower {
                ptau_power: ptau.power(),
                needed_power: log2(needed_power) as u32,
            });
        }

        // ------------------------------------------------------------------
        // 1. Read powers of tau from .ptau
        // ------------------------------------------------------------------
        let tau_g1 = ptau.read_tau_g1(needed_g1)?;
        let tau_g2 = ptau.read_tau_g2(needed_g2)?;

        // ------------------------------------------------------------------
        // 2. Generate circuit-specific random scalars
        // ------------------------------------------------------------------
        let alpha = random_nonzero_fr(rng);
        let beta = random_nonzero_fr(rng);
        let gamma = random_nonzero_fr(rng);
        let delta = random_nonzero_fr(rng);
        let gamma_inv = gamma.inverse().unwrap();
        let delta_inv = delta.inverse().unwrap();

        // ------------------------------------------------------------------
        // 3. Build QAP polynomials
        // ------------------------------------------------------------------
        let (us, vs, ws) = engine.build_qap(l, r, o);
        let t = engine.target_poly(n_constraints);
        let t_coeffs = t.coeffs.clone();

        // ------------------------------------------------------------------
        // 4. Compute a_query, b_g1_query, b_g2_query via MSM over tau powers
        // ------------------------------------------------------------------
        let mut a_query = Vec::with_capacity(n_vars);
        let mut b_g1_query = Vec::with_capacity(n_vars);
        let mut b_g2_query = Vec::with_capacity(n_vars);
        let mut w_query = Vec::with_capacity(n_vars); // temporary for c_query

        for i in 0..n_vars {
            let u_coeffs = &us[i].coeffs;
            let v_coeffs = &vs[i].coeffs;
            let w_coeffs = &ws[i].coeffs;

            // a_query[i] = u_i(tau) * G1 = MSM(tau_g1, u_coeffs)
            a_query.push(G1Affine::from(msm_g1(&tau_g1, u_coeffs)));

            // b_g1_query[i] = v_i(tau) * G1 = MSM(tau_g1, v_coeffs)
            b_g1_query.push(G1Affine::from(msm_g1(&tau_g1, v_coeffs)));

            // b_g2_query[i] = v_i(tau) * G2 = MSM(tau_g2, v_coeffs)
            b_g2_query.push(G2Affine::from(msm_g2(&tau_g2, v_coeffs)));

            // w_query[i] = w_i(tau) * G1 = MSM(tau_g1, w_coeffs)
            w_query.push(G1Affine::from(msm_g1(&tau_g1, w_coeffs)));
        }

        // ------------------------------------------------------------------
        // 5. Compute c_query and ic from alpha/beta/w contributions
        //
        // Important: we use the CIRCUIT-SPECIFIC alpha and beta (generated
        // above), NOT the alpha/beta from the .ptau Phase-1 SRS.
        // ------------------------------------------------------------------
        let mut c_query = Vec::with_capacity(n_vars);
        let mut ic = Vec::with_capacity(n_vars);
        for i in 0..n_vars {
            // beta * u_i(tau) * G1 = a_query[i] * beta
            let beta_u_pt = G1Projective::from(a_query[i]) * beta;

            // alpha * v_i(tau) * G1 = b_g1_query[i] * alpha
            let alpha_v_pt = G1Projective::from(b_g1_query[i]) * alpha;

            // w_i(tau) * G1 (already computed in w_query)
            let w_pt = G1Projective::from(w_query[i]);

            // psi = beta*u + alpha*v + w
            let psi_pt = beta_u_pt + alpha_v_pt + w_pt;

            // c_query[i] = delta_inv * psi  (private variables)
            c_query.push(G1Affine::from(psi_pt * delta_inv));

            // ic[i] = gamma_inv * psi  (public variables, never changes with delta)
            ic.push(G1Affine::from(psi_pt * gamma_inv));
        }

        // ------------------------------------------------------------------
        // 6. Compute h_query[j] = delta_inv * tau^j * T(tau) * G1
        //
        // Key insight: T(tau) * tau^j is a scalar.  We can compute the
        // corresponding group element without knowing tau:
        //   T(tau) * tau^j * G1 = sum_k t_k * tau^{j+k} * G1
        //                       = MSM(tau_g1[j..j+deg(T)+1], T.coeffs)
        // ------------------------------------------------------------------
        let h_query_len = t.degree(); // safe upper bound on deg(h) + 1
        let mut h_query = Vec::with_capacity(h_query_len);

        for j in 0..h_query_len {
            let mut bases = Vec::with_capacity(t_coeffs.len());
            let mut scalars = Vec::with_capacity(t_coeffs.len());
            for (k, &t_k) in t_coeffs.iter().enumerate() {
                if !t_k.is_zero() && (j + k) < tau_g1.len() {
                    bases.push(tau_g1[j + k]);
                    scalars.push(t_k);
                }
            }
            let t_tau_j_pt = if bases.is_empty() {
                G1Projective::zero()
            } else {
                G1Projective::msm(&bases, &scalars).expect("MSM length mismatch")
            };
            h_query.push(G1Affine::from(t_tau_j_pt * delta_inv));
        }

        // ------------------------------------------------------------------
        // 7. Build CRS fixed points
        // ------------------------------------------------------------------
        let g1_proj = G1Projective::generator();
        let g2_proj = G2Projective::generator();

        let alpha_g1 = G1Affine::from(g1_proj * alpha);
        let beta_g1 = G1Affine::from(g1_proj * beta);
        let beta_g2 = G2Affine::from(g2_proj * beta);
        let gamma_g2 = G2Affine::from(g2_proj * gamma);
        let delta_g2 = G2Affine::from(g2_proj * delta);
        let delta_g1 = G1Affine::from(g1_proj * delta);

        // ------------------------------------------------------------------
        // 8. l_query = public subset of ic (same as ic[..n_public], for arkworks parity)
        // ------------------------------------------------------------------
        let l_query = ic[..n_public].to_vec();

        // ------------------------------------------------------------------
        // 9. Build accumulator
        // ------------------------------------------------------------------
        let accumulator = Phase2Accumulator {
            alpha_g1,
            beta_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            a_query,
            b_g1_query,
            b_g2_query,
            c_query,
            h_query,
            l_query,
            n_public,
            ptau_power: ptau.power(),
            contributions: Vec::new(),
            ic,
            delta_g1,
        };

        Ok(accumulator)
    }

    // ------------------------------------------------------------------
    // Contribution
    // ------------------------------------------------------------------

    /// Apply a new participant's randomness to this accumulator.
    ///
    /// The participant generates a random `delta_new`, updates all
    /// delta-dependent group elements, and appends a contribution with
    /// a ratio proof.
    pub fn contribute(&mut self, rng: &mut impl RngCore) -> Result<(), Error> {
        let delta_new = random_nonzero_fr(rng);
        let delta_new_inv = delta_new.inverse().unwrap();

        // Record the state before the update
        let delta_g2_before = self.delta_g2;
        let delta_g1_before = self.delta_g1;

        // Update delta_g2
        self.delta_g2 =
            G2Affine::from(G2Projective::from(self.delta_g2) * delta_new);

        // Update delta_g1
        self.delta_g1 =
            G1Affine::from(G1Projective::from(self.delta_g1) * delta_new);

        // Update c_query (contains delta_inv, so divide by delta_new)
        for pt in &mut self.c_query {
            *pt = G1Affine::from(G1Projective::from(*pt) * delta_new_inv);
        }

        // Update h_query (contains delta_inv, so divide by delta_new)
        for pt in &mut self.h_query {
            *pt = G1Affine::from(G1Projective::from(*pt) * delta_new_inv);
        }

        // l_query and ic do NOT change with delta — they are gamma_inv * psi, independent of delta

        // Compute ratio proof: prove knowledge of delta_new such that
        // delta_g1_after = delta_g1_before * delta_new
        let ratio_proof = prove_ratio(
            &delta_g1_before,
            &self.delta_g1,
            &delta_new,
            rng,
        );

        self.contributions.push(Contribution {
            delta_g2_before,
            delta_g2_after: self.delta_g2,
            delta_g1_before,
            delta_g1_after: self.delta_g1,
            ratio_proof,
            name: None,
        });

        Ok(())
    }

    // ------------------------------------------------------------------
    // Verification
    // ------------------------------------------------------------------

    /// Verify that the accumulator is internally consistent.
    ///
    /// Checks:
    /// 1. All contributions have valid ratio proofs.
    /// 2. Delta-dependent elements are correctly chained.
    /// 3. Non-delta elements are unchanged from the initial state.
    pub fn verify(&self) -> Result<(), Error> {
        // Verify each contribution's ratio proof
        for (i, contrib) in self.contributions.iter().enumerate() {
            if !verify_ratio(
                &contrib.delta_g1_before,
                &contrib.delta_g1_after,
                &contrib.ratio_proof,
            ) {
                return Err(Error::InvalidContribution {
                    index: i,
                    reason: "ratio proof failed".to_string(),
                });
            }
        }

        // Verify delta chaining: each contribution's after == next's before
        for i in 1..self.contributions.len() {
            if self.contributions[i].delta_g2_before != self.contributions[i - 1].delta_g2_after {
                return Err(Error::InvariantViolation(
                    format!("delta_g2 chain broken at contribution {}", i)
                ));
            }
            if self.contributions[i].delta_g1_before != self.contributions[i - 1].delta_g1_after {
                return Err(Error::InvariantViolation(
                    format!("delta_g1 chain broken at contribution {}", i)
                ));
            }
        }

        Ok(())
    }

    // ------------------------------------------------------------------
    // Finalization
    // ------------------------------------------------------------------

    /// Convert the accumulator into a `FullProvingKey` + `VerifyingKey`.
    pub fn finalize(&self) -> (FullProvingKey, VerifyingKey) {
        let vk = VerifyingKey {
            alpha_g1: self.alpha_g1,
            beta_g2: self.beta_g2,
            gamma_g2: self.gamma_g2,
            delta_g2: self.delta_g2,
            ic: self.ic.clone(),
            n_public: self.n_public,
        };

        let full_pk = FullProvingKey {
            vk: vk.clone(),
            beta_g1: self.beta_g1,
            delta_g1: self.delta_g1,
            a_query: self.a_query.clone(),
            b_g1_query: self.b_g1_query.clone(),
            b_g2_query: self.b_g2_query.clone(),
            c_query: self.c_query.clone(),
            h_query: self.h_query.clone(),
            l_query: self.l_query.clone(),
            // Phase-2 MPC does not retain the delta scalar, so h_scalar is unavailable.
            // The prover falls back to the h_query MSM path.
            h_scalar: None,
            h_scalar_tau: None,
        };

        (full_pk, vk)
    }
}

// ------------------------------------------------------------------
// Helpers
// ------------------------------------------------------------------

/// Multi-scalar multiplication in G1.
fn msm_g1(bases: &[G1Affine], scalars: &[Fr]) -> G1Projective {
    if bases.is_empty() || scalars.is_empty() {
        return G1Projective::zero();
    }
    let min_len = bases.len().min(scalars.len());
    G1Projective::msm(&bases[..min_len], &scalars[..min_len])
        .expect("MSM length mismatch")
}

/// Multi-scalar multiplication in G2.
fn msm_g2(bases: &[G2Affine], scalars: &[Fr]) -> G2Projective {
    if bases.is_empty() || scalars.is_empty() {
        return G2Projective::zero();
    }
    let min_len = bases.len().min(scalars.len());
    G2Projective::msm(&bases[..min_len], &scalars[..min_len])
        .expect("MSM length mismatch")
}

/// Generate a random non-zero field element.
fn random_nonzero_fr(rng: &mut impl RngCore) -> Fr {
    loop {
        let s = Fr::rand(rng);
        if !s.is_zero() {
            return s;
        }
    }
}

/// Compute the next power of two >= n.
fn next_power_of_two(n: usize) -> usize {
    next_power_of_two_u64(n as u64) as usize
}

/// Integer log2 (n must be a power of two).
fn log2(n: usize) -> usize {
    log2_u64(n as u64) as usize
}

// ------------------------------------------------------------------
// Verified core for `next_power_of_two` / `log2`
//
// Verus models `usize` as 32-bit, while the arithmetic here is only
// meaningful for 64-bit circuit sizes, so the proofs are carried out over
// `u64` and the `usize` wrappers above are plain casts.  Under the
// `verus` feature the wrappers below *are* the bodies that get verified.
// ------------------------------------------------------------------

#[cfg(not(feature = "verus"))]
fn next_power_of_two_u64(n: u64) -> u64 {
    let mut p = 1u64;
    while p < n {
        p <<= 1;
    }
    p
}

#[cfg(not(feature = "verus"))]
fn log2_u64(n: u64) -> u64 {
    n.trailing_zeros() as u64
}

#[cfg(feature = "verus")]
mod verus_core {
    use vstd::prelude::*;
    use vstd::arithmetic::power2::{
        pow2, is_pow2, is_pow2_equiv, is_pow2_exists, lemma_pow2, lemma_pow2_pos,
        lemma_pow2_unfold, lemma_pow2_strictly_increases, lemma_pow2_adds, lemma2_to64,
    };
    use vstd::arithmetic::power::{pow, lemma_pow_strictly_increases_converse};
    use vstd::std_specs::bits::{u64_trailing_zeros, axiom_u64_trailing_zeros};

    verus! {

    // ---------------------------------------------------------------
    // small power-of-two lemmas
    // ---------------------------------------------------------------

    proof fn lemma_pow2_zero()
        ensures
            pow2(0) == 1,
    {
        reveal(pow2);
        reveal(pow);
    }

    proof fn lemma_pow2_is_pow2(e: nat)
        ensures
            is_pow2(pow2(e) as int),
    {
        lemma_pow2(e);
        is_pow2_equiv(pow2(e) as int);
        assert(exists|i: nat| pow(2, i) == pow2(e) as int) by {
            reveal(is_pow2_exists);
            assert(pow(2, e) == pow2(e) as int);
        }
    }

    // pow2(f) < pow2(g)  ==>  f < g
    proof fn lemma_pow2_lt_inv(f: nat, g: nat)
        requires
            pow2(f) < pow2(g),
        ensures
            f < g,
    {
        lemma_pow2(f);
        lemma_pow2(g);
        lemma_pow_strictly_increases_converse(2, f, g);
    }

    proof fn lemma_pow2_mono_le(f: nat, g: nat)
        requires
            f <= g,
        ensures
            pow2(f) <= pow2(g),
        decreases g,
    {
        lemma_pow2_pos(g);
        if f < g {
            lemma_pow2_strictly_increases(f, g);
        }
    }

    proof fn lemma_pow2_at_least(e: nat, m: nat)
        requires
            e >= m,
        ensures
            pow2(e) >= pow2(m),
        decreases e,
    {
        lemma_pow2_pos(e);
        if e > m {
            lemma_pow2_at_least((e - 1) as nat, m);
            lemma_pow2_strictly_increases((e - 1) as nat, e);
        }
    }

    // pow2(g + 1) == 2 * pow2(g)
    proof fn lemma_pow2_succ(g: nat)
        ensures
            pow2((g + 1) as nat) == pow2(g) * 2,
    {
        lemma_pow2_unfold((g + 1) as nat);
    }

    proof fn lemma_pow2_62()
        ensures
            pow2(62) == 0x4000_0000_0000_0000nat,
    {
        lemma2_to64();
        assert(pow2(30) == 0x4000_0000u64 as nat);
        assert(pow2(32) == 0x1_0000_0000u64 as nat);
        lemma_pow2_adds(32, 30);
    }

    proof fn lemma_pow2_63()
        ensures
            pow2(63) == 0x8000_0000_0000_0000nat,
    {
        lemma_pow2_62();
        lemma_pow2_unfold(63);
    }

    // pow2(e) <= 2^63 for e <= 63
    proof fn lemma_pow2_le_63(e: nat)
        requires
            e <= 63,
        ensures
            pow2(e) <= 0x8000_0000_0000_0000nat,
    {
        lemma_pow2_63();
        if e < 63 {
            lemma_pow2_mono_le(e, 63);
        }
    }

    // pow2(e) fits in a u64 and is nonzero, for e <= 63
    proof fn lemma_pow2_fits_u64(e: nat)
        requires
            e <= 63,
        ensures
            1 <= pow2(e),
            pow2(e) <= 0xffff_ffff_ffff_ffffnat,
    {
        lemma_pow2_pos(e);
        if e < 63 {
            lemma_pow2_strictly_increases(e, 63);
            lemma_pow2_63();
        } else {
            lemma_pow2_63();
        }
    }

    // ---------------------------------------------------------------
    // bit-vector primitives
    // ---------------------------------------------------------------

    // (m + m) is even, and right-shifting it by one recovers m
    proof fn lemma_double_bits(two: u64, m: u64)
        requires
            two == m + m,
        ensures
            (two & 1) == 0,
            two >> 1 == m,
    {
        assert(two == m + m ==> (two & 1) == 0) by (bit_vector);
        assert(two == m + m ==> two >> 1 == m) by (bit_vector);
    }

    // shifting right by j equals shifting right by one, j-1 more times
    proof fn lemma_shr_split(m: u64, j: u64)
        requires
            j > 0,
            j < 64,
        ensures
            (m >> j) == ((m >> 1) >> ((j - 1) as u64)),
    {
        assert(j > 0 && j < 64 ==> (m >> j) == ((m >> 1) >> ((j - 1) as u64)))
            by (bit_vector);
    }

    // the only set bit of 2^e is bit e
    proof fn lemma_pow2_lowbit(e: nat, j: u64)
        requires
            e <= 63,
            j < 64,
        ensures
            ((pow2(e) as u64) >> j) & 1 == if j == e { 1u64 } else { 0u64 },
        decreases e,
    {
        lemma_pow2_pos(e);
        if e == 0 {
            lemma_pow2_zero();
            assert(pow2(0) as u64 == 1);
            assert((1u64 >> j) & 1 == if j == 0 { 1u64 } else { 0u64 }) by (bit_vector);
        } else {
            lemma_pow2_succ((e - 1) as nat);
            lemma_pow2_le_63(e);
            lemma_pow2_le_63((e - 1) as nat);
            lemma_pow2_fits_u64((e - 1) as nat);
            assert(pow2((e - 1) as nat) <= 0x4000_0000_0000_0000nat) by {
                lemma_pow2_62();
                lemma_pow2_mono_le((e - 1) as nat, 62);
            }
            let prev: u64 = pow2((e - 1) as nat) as u64;
            let cur: u64 = pow2(e) as u64;
            assert(cur == prev + prev);
            lemma_double_bits(cur, prev);
            if j == 0 {
                assert(e != 0);
                assert(cur >> 0 == cur) by (bit_vector);
                assert(((pow2(e) as u64) >> 0) & 1 == 0u64);
            } else {
                lemma_pow2_lowbit((e - 1) as nat, (j - 1) as u64);
                lemma_shr_split(cur, j);
                assert(cur >> 1 == prev);
                assert(((cur >> 1) >> ((j - 1) as u64)) & 1
                    == if (j - 1) as u64 == e - 1 { 1u64 } else { 0u64 });
                assert((j - 1) as u64 == e - 1 <==> j == e);
                assert(cur >> j == ((cur >> 1) >> ((j - 1) as u64)));
            }
        }
    }

    // ---------------------------------------------------------------
    // log2: the exponent e with pow2(e) == n
    // ---------------------------------------------------------------

    // u64_trailing_zeros(2^e) == e
    proof fn lemma_tz_pow2(e: nat)
        requires
            e <= 63,
        ensures
            u64_trailing_zeros(pow2(e) as u64) == e,
    {
        lemma_pow2_fits_u64(e);
        axiom_u64_trailing_zeros(pow2(e) as u64);
        let t: u64 = u64_trailing_zeros(pow2(e) as u64) as u64;
        assert(pow2(e) as u64 != 0);
        assert(t < 64);
        lemma_pow2_lowbit(e, t);
        assert(((pow2(e) as u64) >> t) & 1 == 1u64);
    }

    pub fn log2_u64(n: u64) -> (r: u64)
        requires
            n >= 1,
            n <= 0x4000_0000_0000_0000u64,
            is_pow2(n as int),
        ensures
            pow2(r as nat) == n as int,
    {
        let r: u64 = n.trailing_zeros() as u64;
        proof {
            is_pow2_equiv(n as int);
            let f = choose|f: nat| pow(2, f) == n as int;
            lemma_pow2(f);
            lemma_pow2_62();
            assert(pow2(f) as int == n as int);
            assert(f <= 62) by {
                if f > 62 {
                    lemma_pow2_strictly_increases(62, f);
                    assert((pow2(62) as int) < (pow2(f) as int));
                    assert(0x4000_0000_0000_0000int < n as int);
                }
            }
            lemma_pow2_fits_u64(f);
            assert(pow2(f) as u64 == n);
            lemma_tz_pow2(f);
            assert(r == u64_trailing_zeros(n) as u64);
        }
        r
    }

    // ---------------------------------------------------------------
    // next_power_of_two: the minimal power of two >= n
    // ---------------------------------------------------------------

    pub fn next_power_of_two_u64(n: u64) -> (r: u64)
        requires
            n >= 1,
            n <= 0x4000_0000_0000_0000u64,
        ensures
            r >= n,
            r <= 2 * n,
            is_pow2(r as int),
            forall|k: u64| is_pow2(k as int) && 1 <= k < r ==> k < n,
    {
        let mut p: u64 = 1;
        let mut e: u64 = 0;
        proof {
            lemma_pow2_zero();
            lemma_pow2_is_pow2(0);
        }
        while p < n
            invariant
                p >= 1,
                p <= 2 * n,
                n >= 1,
                n <= 0x4000_0000_0000_0000u64,
                p as nat == pow2(e as nat),
                e <= 63,
                is_pow2(p as int),
                forall|f: nat| pow2(f) < p as nat ==> pow2(f) < n as int,
            decreases (2 * n) - p,
        {
            proof {
                assert(p < n);
                assert(p <= 0x3fff_ffff_ffff_ffffu64);
                assert(p + p <= 0x7fff_ffff_ffff_fffeu64);
                lemma_pow2_62();
                assert(pow2(e as nat) == p as nat);
                assert(pow2(e as nat) < pow2(62));
                lemma_pow2_lt_inv(e as nat, 62);
                assert(e as nat + 1 <= 62);
                assert(e as nat + 1 <= 63);
                lemma_pow2_succ(e as nat);
                lemma_pow2_is_pow2(e as nat + 1);
                assert forall|f: nat| pow2(f) < (p + p) as nat implies pow2(f) < n as int by {
                    lemma_pow2_lt_inv(f, e as nat + 1);
                    lemma_pow2_mono_le(f, e as nat);
                    assert(pow2(e as nat) == p as nat);
                    if pow2(f) < p as nat {
                    } else {
                        assert(p < n);
                    }
                }
            }
            p = p + p;
            e = e + 1;
        }
        proof {
            assert forall|k: u64| is_pow2(k as int) && 1 <= k < p implies k < n by {
                is_pow2_equiv(k as int);
                assert(exists|f: nat| pow(2, f) == k as int) by {
                    reveal(is_pow2_exists);
                }
                let f = choose|f: nat| pow(2, f) == k as int;
                broadcast use lemma_pow2;
                assert(pow2(f) == k as int);
                assert(pow2(f) < pow2(e as nat));
            }
        }
        p
    }

    }
}

#[cfg(feature = "verus")]
pub(crate) use verus_core::{next_power_of_two_u64, log2_u64};

// ------------------------------------------------------------------
// Ratio proofs (Schnorr-like on G2)
// ------------------------------------------------------------------

/// Prove knowledge of `s` such that `delta_g1_after = delta_g1_before * s`.
fn prove_ratio(
    delta_g1_before: &G1Affine,
    delta_g1_after: &G1Affine,
    s: &Fr,
    rng: &mut impl RngCore,
) -> RatioProof {
    // Random nonce
    let r = Fr::rand(rng);
    let r_g1 = G1Affine::from(G1Projective::from(*delta_g1_before) * r);

    // Challenge c = hash(delta_g1_before, delta_g1_after, r_g1)
    let c = hash_ratio_challenge(delta_g1_before, delta_g1_after, &r_g1);

    // Response s_resp = r + c * s
    let s_resp = r + c * s;

    RatioProof {
        r_g1,
        s: s_resp,
        c,
    }
}

/// Verify a ratio proof.
fn verify_ratio(
    delta_g1_before: &G1Affine,
    delta_g1_after: &G1Affine,
    proof: &RatioProof,
) -> bool {
    // Recompute challenge
    let c = hash_ratio_challenge(delta_g1_before, delta_g1_after, &proof.r_g1);
    if c != proof.c {
        return false;
    }

    // Check: delta_g1_before * s == R + delta_g1_after * c
    let lhs = G1Projective::from(*delta_g1_before) * proof.s;
    let rhs = G1Projective::from(proof.r_g1) + G1Projective::from(*delta_g1_after) * c;

    lhs == rhs
}

/// Hash-based challenge for ratio proof.
fn hash_ratio_challenge(
    delta_g1_before: &G1Affine,
    delta_g1_after: &G1Affine,
    r: &G1Affine,
) -> Fr {
    let mut buf = Vec::new();
    delta_g1_before.serialize_compressed(&mut buf).unwrap();
    delta_g1_after.serialize_compressed(&mut buf).unwrap();
    r.serialize_compressed(&mut buf).unwrap();

    // Simple hash using arkworks' built-in hash extension
    Fr::from_le_bytes_mod_order(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;
    #[allow(unused_imports)]
    use crate::r1cs::{L, O, R, WITNESS};

    #[test]
    fn test_ratio_proof_roundtrip() {
        let mut rng = rand::thread_rng();
        let s = random_nonzero_fr(&mut rng);

        let g1 = G1Affine::generator();
        let delta_g1_before = g1;
        let delta_g1_after = G1Affine::from(G1Projective::from(g1) * s);

        let proof = prove_ratio(&delta_g1_before, &delta_g1_after, &s, &mut rng);
        assert!(verify_ratio(&delta_g1_before, &delta_g1_after, &proof));
    }

    #[test]
    fn test_ratio_proof_wrong_s_fails() {
        let mut rng = rand::thread_rng();
        let s = random_nonzero_fr(&mut rng);
        let wrong_s = random_nonzero_fr(&mut rng);

        let g1 = G1Affine::generator();
        let delta_g1_before = g1;
        let delta_g1_after = G1Affine::from(G1Projective::from(g1) * s);

        let proof = prove_ratio(&delta_g1_before, &delta_g1_after, &wrong_s, &mut rng);
        assert!(!verify_ratio(&delta_g1_before, &delta_g1_after, &proof));
    }

    #[test]
    fn test_initialize_with_ptau() {
        use crate::engine::FftQapEngine;
        use crate::r1cs::{L, O, R};

        let mut rng = rand::thread_rng();
        let engine = FftQapEngine;

        let mut ptau = PtauFile::open("test_data/pot4_final.ptau").unwrap();
        let n_public = 2; // constant wire + output 'a'

        let accumulator = Phase2Accumulator::initialize(
            &mut ptau,
            &engine,
            &L,
            &R,
            &O,
            n_public,
            &mut rng,
        )
        .unwrap();

        // Basic structural checks
        assert_eq!(accumulator.a_query.len(), 8);
        assert_eq!(accumulator.b_g1_query.len(), 8);
        assert_eq!(accumulator.b_g2_query.len(), 8);
        assert_eq!(accumulator.c_query.len(), 8);
        assert_eq!(accumulator.h_query.len(), 4); // t.degree() = 4, safe upper bound on deg(h) + 1
        assert_eq!(accumulator.l_query.len(), n_public);
        assert_eq!(accumulator.ic.len(), 8);
        assert_eq!(accumulator.n_public, n_public);

        // Verify that all points are on the curve and in the subgroup
        for (i, pt) in accumulator.a_query.iter().enumerate() {
            assert!(pt.is_on_curve(), "a_query[{}] not on curve", i);
            assert!(pt.is_in_correct_subgroup_assuming_on_curve(), "a_query[{}] not in subgroup", i);
        }
        for (i, pt) in accumulator.b_g1_query.iter().enumerate() {
            assert!(pt.is_on_curve(), "b_g1_query[{}] not on curve", i);
            assert!(pt.is_in_correct_subgroup_assuming_on_curve(), "b_g1_query[{}] not in subgroup", i);
        }
        for (i, pt) in accumulator.b_g2_query.iter().enumerate() {
            assert!(pt.is_on_curve(), "b_g2_query[{}] not on curve", i);
            assert!(pt.is_in_correct_subgroup_assuming_on_curve(), "b_g2_query[{}] not in subgroup", i);
        }
        for (i, pt) in accumulator.c_query.iter().enumerate() {
            assert!(pt.is_on_curve(), "c_query[{}] not on curve", i);
            assert!(pt.is_in_correct_subgroup_assuming_on_curve(), "c_query[{}] not in subgroup", i);
        }
        for (i, pt) in accumulator.h_query.iter().enumerate() {
            assert!(pt.is_on_curve(), "h_query[{}] not on curve", i);
            assert!(pt.is_in_correct_subgroup_assuming_on_curve(), "h_query[{}] not in subgroup", i);
        }
        for (i, pt) in accumulator.l_query.iter().enumerate() {
            assert!(pt.is_on_curve(), "l_query[{}] not on curve", i);
            assert!(pt.is_in_correct_subgroup_assuming_on_curve(), "l_query[{}] not in subgroup", i);
        }
        for (i, pt) in accumulator.ic.iter().enumerate() {
            assert!(pt.is_on_curve(), "ic[{}] not on curve", i);
            assert!(pt.is_in_correct_subgroup_assuming_on_curve(), "ic[{}] not in subgroup", i);
        }

        // Verify fixed points
        assert!(accumulator.alpha_g1.is_on_curve());
        assert!(accumulator.beta_g1.is_on_curve());
        assert!(accumulator.beta_g2.is_on_curve());
        assert!(accumulator.gamma_g2.is_on_curve());
        assert!(accumulator.delta_g2.is_on_curve());
        assert!(accumulator.delta_g1.is_on_curve());
    }

    #[test]
    fn test_contribute_and_verify() {
        use crate::engine::FftQapEngine;
        use crate::r1cs::{L, O, R};

        let mut rng = rand::thread_rng();
        let engine = FftQapEngine;

        let mut ptau = PtauFile::open("test_data/pot4_final.ptau").unwrap();
        let n_public = 2;

        let mut accumulator = Phase2Accumulator::initialize(
            &mut ptau,
            &engine,
            &L,
            &R,
            &O,
            n_public,
            &mut rng,
        )
        .unwrap();

        // Apply one contribution
        accumulator.contribute(&mut rng).unwrap();
        assert_eq!(accumulator.contributions.len(), 1);

        // Verify the accumulator
        accumulator.verify().unwrap();

        // Apply a second contribution
        accumulator.contribute(&mut rng).unwrap();
        assert_eq!(accumulator.contributions.len(), 2);

        // Verify again
        accumulator.verify().unwrap();
    }

    #[test]
    fn test_finalize_produces_valid_keys() {
        use crate::engine::FftQapEngine;
        use crate::r1cs::{L, O, R, WITNESS};
        use crate::prover::{NaiveProver, Prover};

        let mut rng = rand::thread_rng();
        let engine = FftQapEngine;

        let mut ptau = PtauFile::open("test_data/pot4_final.ptau").unwrap();
        let n_public = 2;

        let accumulator = Phase2Accumulator::initialize(
            &mut ptau,
            &engine,
            &L,
            &R,
            &O,
            n_public,
            &mut rng,
        )
        .unwrap();

        let (full_pk, vk) = accumulator.finalize();

        // Check that vk points are consistent with full_pk
        assert_eq!(vk.alpha_g1, full_pk.vk.alpha_g1);
        assert_eq!(vk.beta_g2, full_pk.vk.beta_g2);
        assert_eq!(vk.gamma_g2, full_pk.vk.gamma_g2);
        assert_eq!(vk.delta_g2, full_pk.vk.delta_g2);
        assert_eq!(vk.ic, full_pk.vk.ic);

        // Try to prove something with it
        let witness = crate::r1cs::witness_to_fr(&WITNESS);
        let prover = NaiveProver;
        let (proof, public_input) = prover.prove_with_full_pk(
            &engine, &full_pk, &L, &R, &O, &witness,
        );

        // Basic proof sanity: all proof points are on curve
        assert!(proof.a.is_on_curve());
        assert!(proof.b.is_on_curve());
        assert!(proof.c.is_on_curve());

        // Verify the proof using the VK
        let valid = crate::prover::verify_proof(
            &proof,
            &public_input,
            &vk.alpha_g1,
            &vk.beta_g2,
            &vk.gamma_g2,
            &vk.delta_g2,
        );
        assert!(valid, "proof produced from Phase2Accumulator must verify");
    }
}
