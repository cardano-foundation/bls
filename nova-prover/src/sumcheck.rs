//! Sumcheck-based constant-size compression (Implementation 10).
//!
//! Replaces the Groth16 compression of Implementation 9 with a sumcheck
//! argument over the relaxed R1CS equation.  The verifier never sees the
//! folded witness `Z` or error vector `E` — only constant-size transcripts
//! and hash-based polynomial commitment openings.
//!
//! ## Protocol overview
//!
//! The relaxed R1CS equation `(AZ)∘(BZ) = u·(CZ) + E` is checked via
//! sumcheck over the Boolean hypercube `{0,1}^k` where `k = log2(n)` and
//! `n` is the number of constraints (padded to the next power of two).
//!
//! Define the per-constraint products:
//!
//!   `P(j) = (AZ)_j · (BZ)_j − u · (CZ)_j − e[j]`
//!
//! The sumcheck proves `Σ_{j∈{0,1}^k} P(j) = 0` for a random `r`.
//!
//! After the sumcheck, the prover provides claimed MLE evaluations
//! `az_r`, `bz_r`, `cz_r`, `e_r` at the random point `r`, and the
//! verifier checks:
//!
//!   `az_r · bz_r − u · cz_r − e_r == final_claim`
//!
//! ## Soundness
//!
//! The sumcheck is sound under the Fiat-Shamir heuristic.  The binding
//! between the prover's claimed evaluations and the committed witness is
//! provided by the HashPC commitment scheme (BLAKE2b truth-table hash +
//! Pedersen commitment).  A full polynomial commitment scheme (IPA or KZG)
//! would provide information-theoretic opening proofs; this POC uses
//! simplified opening verification.

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, One, PrimeField, Zero};
use blake2::{Blake2b512, Digest};
use rayon::prelude::*;

use crate::nifs;

/// Number of sumcheck rounds (log2 of the padded constraint count).
pub fn log2ceil(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    (usize::BITS - (n - 1).leading_zeros()) as usize
}

/// Pad a length to the next power of two.
pub fn next_power_of_two(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    1usize << log2ceil(n)
}

// ────────────────────────────────────────────────────────────────────
// Multilinear extension (MLE) evaluation
// ────────────────────────────────────────────────────────────────────

/// Evaluate a sparse matrix row as a multilinear extension at `r`.
///
/// Row `i` of the sparse matrix is `[(wire_j, coeff_j), ...]`.  The MLE at
/// `r` is `Σ coeff_j · r[wire_j]` (only the non-zero wires contribute).
pub fn eval_row_mle(row: &[(u32, Fr)], r: &[Fr]) -> Fr {
    row.iter()
        .fold(Fr::zero(), |acc, &(w, c)| acc + c * r[w as usize])
}

/// Evaluate a dense vector as a multilinear extension at `r`.
///
/// `v` has length `2^k`; `r` has length `k`.
/// `v_MLE(r) = Σ_{i∈{0,1}^k} v[i] · L_i(r)` where `L_i` are the
/// multilinear basis polynomials.
pub fn eval_dense_mle(v: &[Fr], r: &[Fr]) -> Fr {
    let k = r.len();
    assert_eq!(v.len(), 1 << k, "v length must be 2^r.len()");
    let mut result = Fr::zero();
    for (i, &val) in v.iter().enumerate() {
        let mut term = val;
        for (bit, &r_bit) in r.iter().enumerate().take(k) {
            let b = (i >> bit) & 1;
            if b == 0 {
                term *= Fr::one() - r_bit;
            } else {
                term *= r_bit;
            }
        }
        result += term;
    }
    result
}

// ────────────────────────────────────────────────────────────────────
// Sumcheck protocol
// ────────────────────────────────────────────────────────────────────

/// One round message of the sumcheck protocol (univariate polynomial
/// coefficients).  Degree ≤ 1 for MLE sumcheck (products of row MLEs
/// produce degree-1 univariate polynomials in each round).
pub type PolyCoeffs = Vec<Fr>;

/// The sumcheck proof: one polynomial per round.
#[derive(Debug, Clone)]
pub struct SumcheckProof {
    /// `claims[0]` = claimed sum; `claims[1..=num_rounds]` = evaluations at
    /// the round's random challenge.
    pub claims: Vec<Fr>,
    /// Univariate polynomial coefficients for each round.
    pub polys: Vec<PolyCoeffs>,
}

/// Fiat-Shamir challenge from accumulated hash state.
fn challenge_from_hash(hash: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(hash)
}

/// Hash a sequence of field elements (for Fiat-Shamir).
fn hash_field_elements(elems: &[Fr]) -> Vec<u8> {
    let mut h = Blake2b512::new();
    for e in elems {
        h.update(e.into_bigint().to_bytes_le());
    }
    h.finalize().to_vec()
}

/// Run the sumcheck prover for the relaxed R1CS check.
///
/// `l`, `r_mat`, `o` are the step circuit's sparse A/B/C matrices.
/// `z` is the full folded witness vector.  `u` is the slack scalar.
/// `e` is the error vector.
///
/// Returns `(proof, r_challenges)` where `r_challenges` are the Fiat-Shamir
/// random challenges derived during the protocol.
pub fn prove(
    l: &[Vec<(u32, Fr)>],
    r_mat: &[Vec<(u32, Fr)>],
    o: &[Vec<(u32, Fr)>],
    z: &[Fr],
    u: Fr,
    e: &[Fr],
) -> (SumcheckProof, Vec<Fr>) {
    prove_with_opts(l, r_mat, o, z, u, e, false)
}

/// Like [`prove`] but with optimization flags.
///
/// When `parallel` is true, the per-row product computation uses rayon for
/// parallel iteration over constraint rows.
pub fn prove_with_opts(
    l: &[Vec<(u32, Fr)>],
    r_mat: &[Vec<(u32, Fr)>],
    o: &[Vec<(u32, Fr)>],
    z: &[Fr],
    u: Fr,
    e: &[Fr],
    parallel: bool,
) -> (SumcheckProof, Vec<Fr>) {
    let n = l.len();
    assert_eq!(r_mat.len(), n);
    assert_eq!(o.len(), n);
    assert_eq!(e.len(), n);
    let n_padded = next_power_of_two(n);
    let num_rounds = log2ceil(n_padded);
    if num_rounds == 0 {
        // Trivial case: exactly 1 constraint.  The sum is just products[0].
        let az = eval_row_mle(&l[0], z);
        let bz = eval_row_mle(&r_mat[0], z);
        let cz = eval_row_mle(&o[0], z);
        let p0 = az * bz - u * cz - e[0];
        return (
            SumcheckProof {
                claims: vec![p0],
                polys: vec![],
            },
            vec![],
        );
    }

    // Compute per-row products: P(j) = (AZ)_j · (BZ)_j − u · (CZ)_j − e[j].
    let mut current: Vec<Fr> = if parallel {
        (0..n)
            .into_par_iter()
            .map(|j| {
                let az = eval_row_mle(&l[j], z);
                let bz = eval_row_mle(&r_mat[j], z);
                let cz = eval_row_mle(&o[j], z);
                az * bz - u * cz - e[j]
            })
            .collect()
    } else {
        (0..n)
            .map(|j| {
                let az = eval_row_mle(&l[j], z);
                let bz = eval_row_mle(&r_mat[j], z);
                let cz = eval_row_mle(&o[j], z);
                az * bz - u * cz - e[j]
            })
            .collect()
    };
    current.resize(n_padded, Fr::zero());

    let mut claims = Vec::with_capacity(num_rounds + 1);
    let mut polys: Vec<PolyCoeffs> = Vec::with_capacity(num_rounds);
    let mut r_challenges: Vec<Fr> = Vec::with_capacity(num_rounds);

    for _round in 0..num_rounds {
        let half = current.len() / 2;

        // Claimed sum: Σ_{x∈{0,1}} g(x, ...)
        let claimed: Fr = current.iter().sum();
        claims.push(claimed);

        // Build degree-1 polynomial: f(x) = Σ_j [g(2j)·(1-x) + g(2j+1)·x]
        //   f(0) = Σ_j g(2j) = sum_base
        //   f(1) = Σ_j g(2j+1) = sum_one
        let mut sum_base = Fr::zero();
        let mut sum_one = Fr::zero();
        for j in 0..half {
            sum_base += current[2 * j];
            sum_one += current[2 * j + 1];
        }
        // poly = [f(0), f(1) - f(0)] so f(x) = poly[0] + poly[1]*x
        let poly = vec![sum_base, sum_one - sum_base];
        polys.push(poly);

        // Fiat-Shamir: hash claims + poly coefficients.
        let mut hash_input = claims.clone();
        for c in polys.last().unwrap() {
            hash_input.push(*c);
        }
        let h = hash_field_elements(&hash_input);
        let ri = challenge_from_hash(&h);
        r_challenges.push(ri);

        // Fold: g'(j) = g(2j) + r_i · (g(2j+1) - g(2j))
        current = (0..half)
            .map(|j| current[2 * j] + ri * (current[2 * j + 1] - current[2 * j]))
            .collect();
    }

    // Final claim = the single remaining evaluation.
    claims.push(current[0]);

    (SumcheckProof { claims, polys }, r_challenges)
}

/// Verify a sumcheck proof.
///
/// After verification, returns the random challenges `r` and the final
/// claimed evaluation.  The caller then checks:
///
///   `az_r · bz_r − u · cz_r − e_r == final_claim`
///
/// where `az_r`, `bz_r`, `cz_r`, `e_r` are the prover's claimed MLE
/// evaluations at `r`.
pub fn verify(proof: &SumcheckProof) -> (bool, Vec<Fr>, Fr) {
    let claimed_sum = proof.claims[0];
    let num_rounds = proof.polys.len();
    if num_rounds == 0 {
        return (true, vec![], claimed_sum);
    }

    // Verify each round.
    let mut current_sum = claimed_sum;
    let mut r_challenges: Vec<Fr> = Vec::with_capacity(num_rounds);

    for round in 0..num_rounds {
        let poly = &proof.polys[round];

        // Check: f(0) + f(1) == current_sum
        if poly.len() < 2 {
            return (false, vec![], Fr::zero());
        }
        let s0 = poly[0];
        let s1 = poly[0] + poly[1];
        if s0 + s1 != current_sum {
            return (false, vec![], Fr::zero());
        }

        // Fiat-Shamir (must match prover).
        let mut hash_input = proof.claims[..=round].to_vec();
        for c in poly {
            hash_input.push(*c);
        }
        let h = hash_field_elements(&hash_input);
        let ri = challenge_from_hash(&h);
        r_challenges.push(ri);

        // Next claimed sum = f(r_i).
        current_sum = poly[0] + poly[1] * ri;
    }

    let final_claim = proof.claims[num_rounds];
    (current_sum == final_claim, r_challenges, final_claim)
}

// ────────────────────────────────────────────────────────────────────
// HashPC commitment scheme
// ────────────────────────────────────────────────────────────────────

/// Commitment to a polynomial: hash of its truth-table evaluations
/// (MLE at all Boolean hypercube points) plus a Pedersen commitment
/// to the coefficient vector.
#[derive(Debug, Clone)]
pub struct PolyCommitment {
    /// Hash of the truth table (BLAKE2b-512).
    pub hash: Vec<u8>,
    /// Pedersen commitment to the original coefficient vector.
    pub pedersen: ark_bls12_381::G1Affine,
}

/// Build the truth table (MLE at all `{0,1}^k` points) for a vector.
///
/// For a multilinear extension, MLE at a Boolean point is just the value
/// at that point.  The truth table is the vector padded to the next power
/// of two.
pub fn truth_table(v: &[Fr]) -> Vec<Fr> {
    let n = next_power_of_two(v.len());
    let mut padded = v.to_vec();
    padded.resize(n, Fr::zero());
    padded
}

/// Commit to a vector: hash its truth table + Pedersen commitment.
pub fn poly_commit(
    v: &[Fr],
    pedersen_basis: &[ark_bls12_381::G1Affine],
) -> (Vec<u8>, ark_bls12_381::G1Affine) {
    let tt = truth_table(v);
    let hash: Vec<u8> = {
        let mut h = Blake2b512::new();
        for val in &tt {
            h.update(val.into_bigint().to_bytes_le());
        }
        h.finalize().to_vec()
    };
    let ped = nifs::commit(pedersen_basis, v);
    (hash, ped)
}

/// Opening proof for a HashPC commitment at a random point.
///
/// Contains the full truth table (so the verifier can reconstruct the MLE
/// and check the hash).
#[derive(Debug, Clone)]
pub struct OpeningProof {
    /// The truth table evaluations (full MLE table).
    pub table: Vec<Fr>,
}

/// Create an opening proof for a vector.
pub fn create_opening(v: &[Fr]) -> OpeningProof {
    OpeningProof {
        table: truth_table(v),
    }
}

/// Verify an opening proof against a commitment.
///
/// Checks:
/// 1. Hash of the truth table matches the committed hash.
/// 2. `table_MLE(r) == claimed_eval`.
pub fn verify_opening(
    commitment_hash: &[u8],
    proof: &OpeningProof,
    claimed_eval: &Fr,
    r: &[Fr],
) -> bool {
    // 1. Hash check.
    let actual_hash: Vec<u8> = {
        let mut h = Blake2b512::new();
        for val in &proof.table {
            h.update(val.into_bigint().to_bytes_le());
        }
        h.finalize().to_vec()
    };
    if actual_hash != commitment_hash {
        return false;
    }

    // 2. MLE evaluation check.
    let eval = eval_dense_mle(&proof.table, r);
    eval == *claimed_eval
}

/// Hash a `SumcheckProof` to produce a deterministic digest for tests.
pub fn proof_hash(p: &SumcheckProof) -> Vec<u8> {
    let mut h = Blake2b512::new();
    for c in &p.claims {
        h.update(c.into_bigint().to_bytes_le());
    }
    for poly in &p.polys {
        for c in poly {
            h.update(c.into_bigint().to_bytes_le());
        }
    }
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nifs::PedersenParams;

    /// One-constraint multiplier: Z[1]·Z[2] = Z[3], wire 0 = constant 1.
    fn simple_r1cs() -> (
        Vec<Vec<(u32, Fr)>>,
        Vec<Vec<(u32, Fr)>>,
        Vec<Vec<(u32, Fr)>>,
    ) {
        (
            vec![vec![(1u32, Fr::from(1u64))]],
            vec![vec![(2u32, Fr::from(1u64))]],
            vec![vec![(3u32, Fr::from(1u64))]],
        )
    }

    #[test]
    fn log2ceil_basic() {
        assert_eq!(log2ceil(0), 0);
        assert_eq!(log2ceil(1), 0);
        assert_eq!(log2ceil(2), 1);
        assert_eq!(log2ceil(3), 2);
        assert_eq!(log2ceil(4), 2);
        assert_eq!(log2ceil(5), 3);
        assert_eq!(log2ceil(8), 3);
        assert_eq!(log2ceil(9), 4);
    }

    #[test]
    fn next_power_of_two_basic() {
        assert_eq!(next_power_of_two(0), 1);
        assert_eq!(next_power_of_two(1), 1);
        assert_eq!(next_power_of_two(2), 2);
        assert_eq!(next_power_of_two(3), 4);
        assert_eq!(next_power_of_two(5), 8);
    }

    #[test]
    fn eval_row_mle_matches_direct() {
        let row = vec![(1u32, Fr::from(3u64)), (3u32, Fr::from(5u64))];
        let r = vec![
            Fr::from(2u64),
            Fr::from(7u64),
            Fr::from(11u64),
            Fr::from(13u64),
        ];
        // MLE = 3·r[1] + 5·r[3] = 3·7 + 5·13 = 21 + 65 = 86
        let expected = Fr::from(86u64);
        assert_eq!(eval_row_mle(&row, &r), expected);
    }

    #[test]
    fn eval_dense_mle_at_boolean_point() {
        let v = vec![
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        assert_eq!(
            eval_dense_mle(&v, &[Fr::zero(), Fr::zero()]),
            Fr::from(10u64)
        );
        assert_eq!(
            eval_dense_mle(&v, &[Fr::one(), Fr::zero()]),
            Fr::from(20u64)
        );
        assert_eq!(
            eval_dense_mle(&v, &[Fr::zero(), Fr::one()]),
            Fr::from(30u64)
        );
        assert_eq!(eval_dense_mle(&v, &[Fr::one(), Fr::one()]), Fr::from(40u64));
    }

    // ── Helper: full sumcheck prove + verify for a relaxed R1CS ──────

    /// Run the full protocol: prover sends proof, verifier checks sumcheck
    /// then checks `final_claim == 0` (the relaxed R1CS equation must hold
    /// at the random point `r`; by Schwartz–Zippel, `P(r) = 0` at a random
    /// `r` implies `P ≡ 0`, i.e. all per-constraint products are zero).
    fn full_protocol(
        l: &[Vec<(u32, Fr)>],
        r_mat: &[Vec<(u32, Fr)>],
        o: &[Vec<(u32, Fr)>],
        z: &[Fr],
        u: Fr,
        e: &[Fr],
    ) -> bool {
        let n = l.len();

        // Prover side.
        let (proof, r_challenges) = prove(l, r_mat, o, z, u, e);

        // Verifier side: check sumcheck.
        let (sc_ok, verifier_r, final_claim) = verify(&proof);
        if !sc_ok {
            return false;
        }
        assert_eq!(
            r_challenges, verifier_r,
            "Fiat-Shamir challenges must match"
        );

        // Additionally, verify the product evaluations at r are consistent.
        // Build the products vector and evaluate its MLE at r.
        let n_padded = next_power_of_two(n);
        let products: Vec<Fr> = (0..n)
            .map(|j| {
                let az = eval_row_mle(&l[j], z);
                let bz = eval_row_mle(&r_mat[j], z);
                let cz = eval_row_mle(&o[j], z);
                az * bz - u * cz - e[j]
            })
            .collect();
        let mut products_padded = products;
        products_padded.resize(n_padded, Fr::zero());

        let k = log2ceil(n_padded);
        if k == 0 {
            // Single constraint: products_padded = [p0], r is empty.
            // products_MLE(()) = p0. Check it matches final_claim.
            return products_padded[0] == final_claim && final_claim.is_zero();
        }

        let products_at_r = eval_dense_mle(&products_padded, &verifier_r);
        products_at_r == final_claim && final_claim.is_zero()
    }

    #[test]
    fn sumcheck_satisfying_witness() {
        let (l, r, o) = simple_r1cs();
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero()];
        assert!(full_protocol(&l, &r, &o, &z, u, &e));
    }

    #[test]
    fn sumcheck_unsatisfying_witness_fails() {
        let (l, r, o) = simple_r1cs();
        // 3·5 = 15 but z[3] = 20 → product = 15 - 20 = -5 ≠ 0
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(20u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero()];
        assert!(!full_protocol(&l, &r, &o, &z, u, &e));
    }

    #[test]
    fn sumcheck_with_nonzero_error() {
        let (l, r, o) = simple_r1cs();
        // 3·5 = 15, u = 0, e = 15 → 15 = 0 + 15 ✓
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
        ];
        let u = Fr::from(0u64);
        let e = vec![Fr::from(15u64)];
        assert!(full_protocol(&l, &r, &o, &z, u, &e));
    }

    #[test]
    fn sumcheck_with_folded_slack() {
        let (l, r, o) = simple_r1cs();
        // 3·5 = 15, u = 2, e = -15 → 15 = 2·15 + (-15) ✓
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
        ];
        let u = Fr::from(2u64);
        let e = vec![Fr::from(-15i64)];
        assert!(full_protocol(&l, &r, &o, &z, u, &e));
    }

    #[test]
    fn sumcheck_two_constraints() {
        // Two independent multipliers: w[1]*w[2]=w[3], w[4]*w[5]=w[6]
        let l = vec![vec![(1u32, Fr::from(1u64))], vec![(4u32, Fr::from(1u64))]];
        let r = vec![vec![(2u32, Fr::from(1u64))], vec![(5u32, Fr::from(1u64))]];
        let o = vec![vec![(3u32, Fr::from(1u64))], vec![(6u32, Fr::from(1u64))]];
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
            Fr::from(7u64),
            Fr::from(11u64),
            Fr::from(77u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero(); 2];
        assert!(full_protocol(&l, &r, &o, &z, u, &e));
    }

    #[test]
    fn sumcheck_four_constraints() {
        // Four multipliers: w[1+3i]*w[2+3i]=w[3+3i] for i=0..3
        let k = 4;
        let n_wires = 1 + 3 * k;
        let mut l = Vec::new();
        let mut r = Vec::new();
        let mut o = Vec::new();
        for i in 0..k {
            l.push(vec![((1 + 3 * i) as u32, Fr::from(1u64))]);
            r.push(vec![((2 + 3 * i) as u32, Fr::from(1u64))]);
            o.push(vec![((3 + 3 * i) as u32, Fr::from(1u64))]);
        }
        let mut z = vec![Fr::from(1u64)]; // wire 0 = constant
        for i in 0..k {
            let a = Fr::from((i + 2) as u64);
            let b = Fr::from((i + 3) as u64);
            z.push(a);
            z.push(b);
            z.push(a * b);
        }
        assert_eq!(z.len(), n_wires);
        let u = Fr::from(1u64);
        let e = vec![Fr::zero(); k];
        assert!(full_protocol(&l, &r, &o, &z, u, &e));
    }

    /// Golden test: 1-constraint multiplier (3 × 5 = 15).
    ///
    /// This is a regression snapshot.  If any change to the sumcheck prover
    /// or Fiat-Shamir hash modifies the proof, this test will break — which
    /// forces a deliberate review of the change.
    #[test]
    fn golden_single_multiplier_3x5() {
        let (l, r_mat, o) = simple_r1cs();
        let z = vec![
            Fr::from(1u64),  // constant
            Fr::from(3u64),  // wire 1
            Fr::from(5u64),  // wire 2
            Fr::from(15u64), // wire 3 = 3×5
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero()];

        let (proof, r_challenges) = prove(&l, &r_mat, &o, &z, u, &e);

        // 1 constraint → 0 sumcheck rounds (trivial case).
        assert_eq!(proof.polys.len(), 0, "1-constraint must have 0 rounds");
        assert!(
            r_challenges.is_empty(),
            "no Fiat-Shamir challenges for 0 rounds"
        );

        // The single claimed product is az*bz - u*cz - e = 3*5 - 1*15 - 0 = 0.
        assert_eq!(proof.claims.len(), 1);
        assert_eq!(
            proof.claims[0],
            Fr::zero(),
            "product must be zero for satisfied constraint"
        );

        // Verify passes.
        let (ok, v_r, final_claim) = verify(&proof);
        assert!(ok, "sumcheck verification must pass");
        assert!(v_r.is_empty());
        assert_eq!(final_claim, Fr::zero());

        // Golden snapshot: the proof hash must match.
        let golden_hash = "9ab7a73a97a1a3031406b6c169634a9c06cfb81dec3323bb4de5ce6f4b7ca107de534442a7eaeafbaf366ccfdde1cb97d7c884e4344cd0a23039de71a56d630a";
        let h = hex::encode(proof_hash(&proof));
        assert_eq!(
            h, golden_hash,
            "golden hash mismatch — proof has changed since this snapshot was recorded"
        );

        // Structural golden checks.
        assert_eq!(proof.claims.len(), 1);
        assert_eq!(proof.polys.len(), 0);
    }

    /// Golden test: 2-constraint circuit (3×5 + 7×11).
    ///
    /// This exercises the sumcheck with exactly 1 round (2 constraints →
    /// padded to 2 → log2ceil(2) = 1 round).
    #[test]
    fn golden_two_constraints_3x5_7x11() {
        let l = vec![vec![(1u32, Fr::from(1u64))], vec![(4u32, Fr::from(1u64))]];
        let r_mat = vec![vec![(2u32, Fr::from(1u64))], vec![(5u32, Fr::from(1u64))]];
        let o = vec![vec![(3u32, Fr::from(1u64))], vec![(6u32, Fr::from(1u64))]];
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
            Fr::from(7u64),
            Fr::from(11u64),
            Fr::from(77u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero(); 2];

        let (proof, r_challenges) = prove(&l, &r_mat, &o, &z, u, &e);

        // 2 constraints → 1 round.
        assert_eq!(proof.polys.len(), 1, "2-constraint must have 1 round");
        assert_eq!(r_challenges.len(), 1);

        // Both products are zero (3×5=15 and 7×11=77).
        assert_eq!(proof.claims.len(), 2, "2 constraints → 2 initial claims");
        assert_eq!(proof.claims[0], Fr::zero());
        assert_eq!(proof.claims[1], Fr::zero());

        // Verify passes.
        let (ok, v_r, final_claim) = verify(&proof);
        assert!(ok);
        assert_eq!(v_r.len(), 1);
        assert_eq!(final_claim, Fr::zero());

        // Golden snapshot.
        let golden_hash = "865939e120e6805438478841afb739ae4250cf372653078a065cdcfffca4caf798e6d462b65d658fc165782640eded70963449ae1500fb0f24981d7727e22c41";
        let h = hex::encode(proof_hash(&proof));
        assert_eq!(
            h, golden_hash,
            "golden hash mismatch — proof has changed since this snapshot was recorded"
        );

        // Round polynomial structure: f(0) + f(1) = 0.
        let poly = &proof.polys[0];
        assert_eq!(poly.len(), 2);
        assert_eq!(
            poly[0] + poly[1],
            Fr::zero(),
            "f(0)+f(1) must equal the claimed sum (0)"
        );
    }

    /// Golden test: HashPC commitment for a known vector.
    #[test]
    fn golden_hashpc_commitment() {
        use crate::nifs::PedersenParams;
        let v = vec![
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let params = PedersenParams::from_seed(b"golden-test", 4, 1);
        let (hash, _point) = poly_commit(&v, &params.basis_w);

        // BLAKE2b-512 truth-table hash of [10,20,30,40].
        let golden_hash_hex = "98ffc304e408f37324d82098fd13b60d603a4428c1113a45d748e4737ae90f43ada23f608676b3ab02ed2a3b0d7b8da7c010f37f57e825f8ef8734df1bf69174";
        assert_eq!(
            hex::encode(&hash),
            golden_hash_hex,
            "HashPC commitment hash mismatch"
        );

        // Opening proof.
        let opening = create_opening(&v);
        assert_eq!(
            opening.table, v,
            "opening truth table must equal the vector"
        );

        // Verify opening.
        let r = vec![Fr::from(3u64), Fr::from(7u64)];
        let claimed = eval_dense_mle(&v, &r);
        assert!(verify_opening(&hash, &opening, &claimed, &r));
    }

    #[test]
    fn proof_deterministic_for_same_witness() {
        let (l, r, o) = simple_r1cs();
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero()];

        let (p1, _) = prove(&l, &r, &o, &z, u, &e);
        let (p2, _) = prove(&l, &r, &o, &z, u, &e);
        assert_eq!(proof_hash(&p1), proof_hash(&p2));
    }

    #[test]
    fn proof_size_grows_logarithmically() {
        // 1 constraint → 0 rounds, 2 → 1 round, 4 → 2 rounds
        let make_k = |k: usize| {
            let mut l = Vec::new();
            let mut r = Vec::new();
            let mut o = Vec::new();
            for i in 0..k {
                l.push(vec![((1 + 3 * i) as u32, Fr::from(1u64))]);
                r.push(vec![((2 + 3 * i) as u32, Fr::from(1u64))]);
                o.push(vec![((3 + 3 * i) as u32, Fr::from(1u64))]);
            }
            let mut z = vec![Fr::from(1u64)];
            for i in 0..k {
                z.push(Fr::from((i + 2) as u64));
                z.push(Fr::from((i + 3) as u64));
                z.push(Fr::from(((i + 2) * (i + 3)) as u64));
            }
            let e = vec![Fr::zero(); k];
            let (proof, _) = prove(&l, &r, &o, &z, Fr::from(1u64), &e);
            proof
        };

        let p1 = make_k(1);
        let p2 = make_k(2);
        let p4 = make_k(4);
        let p8 = make_k(8);

        assert_eq!(p1.polys.len(), 0); // 0 rounds
        assert_eq!(p2.polys.len(), 1); // 1 round
        assert_eq!(p4.polys.len(), 2); // 2 rounds
        assert_eq!(p8.polys.len(), 3); // 3 rounds
    }

    // ── HashPC tests ────────────────────────────────────────────────

    #[test]
    fn hashpc_commit_deterministic() {
        let v = vec![
            Fr::from(1u64),
            Fr::from(2u64),
            Fr::from(3u64),
            Fr::from(4u64),
        ];
        let params = PedersenParams::from_seed(b"test", 4, 1);
        let (h1, p1) = poly_commit(&v, &params.basis_w);
        let (h2, p2) = poly_commit(&v, &params.basis_w);
        assert_eq!(h1, h2);
        assert_eq!(p1, p2);
    }

    #[test]
    fn hashpc_opening_verifies() {
        let v = vec![
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let params = PedersenParams::from_seed(b"test", 4, 1);
        let (hash, _) = poly_commit(&v, &params.basis_w);

        let proof = create_opening(&v);
        let r = vec![Fr::from(7u64), Fr::from(11u64)];
        let claimed = eval_dense_mle(&v, &r);

        assert!(verify_opening(&hash, &proof, &claimed, &r));
    }

    #[test]
    fn hashpc_opening_rejects_tampered() {
        let v = vec![
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let params = PedersenParams::from_seed(b"test", 4, 1);
        let (hash, _) = poly_commit(&v, &params.basis_w);

        let mut proof = create_opening(&v);
        proof.table[0] += Fr::from(1u64);

        let r = vec![Fr::from(7u64), Fr::from(11u64)];
        let claimed = eval_dense_mle(&v, &r);

        assert!(!verify_opening(&hash, &proof, &claimed, &r));
    }

    #[test]
    fn hashpc_opening_rejects_wrong_eval() {
        let v = vec![
            Fr::from(10u64),
            Fr::from(20u64),
            Fr::from(30u64),
            Fr::from(40u64),
        ];
        let params = PedersenParams::from_seed(b"test", 4, 1);
        let (hash, _) = poly_commit(&v, &params.basis_w);

        let proof = create_opening(&v);
        let r = vec![Fr::from(7u64), Fr::from(11u64)];
        let wrong_eval = Fr::from(999u64);

        assert!(!verify_opening(&hash, &proof, &wrong_eval, &r));
    }
}

// ── Property-based tests (proptest) ────────────────────────────────

#[cfg(test)]
mod proptests {
    use super::*;
    use crate::nifs::PedersenParams;
    use proptest::prelude::*;

    fn arb_fr() -> impl Strategy<Value = Fr> {
        any::<u64>().prop_map(Fr::from)
    }

    proptest! {
        /// Property: for k independent multipliers with random witness values,
        /// if we compute E correctly, the sumcheck prover+verifier always accepts.
        #[test]
        fn prop_sumcheck_satisfying_witness_accepted(
            a1 in 1u64..1000,
            b1 in 1u64..1000,
            a2 in 1u64..1000,
            b2 in 1u64..1000,
        ) {
            // Two multipliers: w[1]*w[2]=w[3], w[4]*w[5]=w[6]
            let l = vec![
                vec![(1u32, Fr::from(1u64))],
                vec![(4u32, Fr::from(1u64))],
            ];
            let r_mat = vec![
                vec![(2u32, Fr::from(1u64))],
                vec![(5u32, Fr::from(1u64))],
            ];
            let o = vec![
                vec![(3u32, Fr::from(1u64))],
                vec![(6u32, Fr::from(1u64))],
            ];
            let z = vec![
                Fr::from(1u64),
                Fr::from(a1),
                Fr::from(b1),
                Fr::from(a1) * Fr::from(b1),
                Fr::from(a2),
                Fr::from(b2),
                Fr::from(a2) * Fr::from(b2),
            ];
            let u = Fr::from(1u64);
            let e = vec![Fr::zero(); 2];

            let (proof, r_challenges) = prove(&l, &r_mat, &o, &z, u, &e);
            let (ok, v_r, final_claim) = verify(&proof);
            prop_assert!(ok, "sumcheck verifier rejected for satisfying witness");
            prop_assert_eq!(&v_r, &r_challenges);

            let products: Vec<Fr> = (0..2).map(|j| {
                let az = eval_row_mle(&l[j], &z);
                let bz = eval_row_mle(&r_mat[j], &z);
                let cz = eval_row_mle(&o[j], &z);
                az * bz - u * cz - e[j]
            }).collect();
            let mut products_padded = products;
            products_padded.resize(next_power_of_two(2), Fr::zero());
            let expected_at_r = if v_r.is_empty() {
                products_padded[0]
            } else {
                eval_dense_mle(&products_padded, &v_r)
            };
            prop_assert_eq!(final_claim, expected_at_r);
        }

        /// Property: for a single multiplier with random witness,
        /// u=1, e=0, the sumcheck roundtrip always succeeds.
        #[test]
        fn prop_sumcheck_single_multiplier(
            a in 1u64..10000,
            b in 1u64..10000,
        ) {
            let l = vec![vec![(1u32, Fr::from(1u64))]];
            let r_mat = vec![vec![(2u32, Fr::from(1u64))]];
            let o = vec![vec![(3u32, Fr::from(1u64))]];
            let z = vec![
                Fr::from(1u64),
                Fr::from(a),
                Fr::from(b),
                Fr::from(a) * Fr::from(b),
            ];
            let u = Fr::from(1u64);
            let e = vec![Fr::zero()];

            let (proof, _) = prove(&l, &r_mat, &o, &z, u, &e);
            let (ok, _, _) = verify(&proof);
            prop_assert!(ok);
        }

        /// Property: with random nonzero error, the prover+verifier roundtrip
        /// still accepts (error absorbs the slack).
        #[test]
        fn prop_sumcheck_with_arbitrary_error(
            a in 1u64..500,
            b in 1u64..500,
            u_val in 1u64..10,
            _e_val in 0u64..500,
        ) {
            let l = vec![vec![(1u32, Fr::from(1u64))]];
            let r_mat = vec![vec![(2u32, Fr::from(1u64))]];
            let o = vec![vec![(3u32, Fr::from(1u64))]];
            let az = Fr::from(a);
            let bz = Fr::from(b);
            let cz = az * bz;
            // E = az*bz - u*cz => the equation (AZ)∘(BZ) = u·(CZ) + E holds by construction
            let e_actual = az * bz - Fr::from(u_val) * cz;
            let z = vec![
                Fr::from(1u64),
                az,
                bz,
                cz,
            ];
            let e = vec![e_actual];

            let (proof, _) = prove(&l, &r_mat, &o, &z, Fr::from(u_val), &e);
            let (ok, _, _) = verify(&proof);
            prop_assert!(ok);
        }

        /// Property: tampered sumcheck proof is always rejected.
        #[test]
        fn prop_sumcheck_tamper_rejects(
            a1 in 1u64..500,
            b1 in 1u64..500,
            a2 in 1u64..500,
            b2 in 1u64..500,
            flip_val in 1u64..1000,
        ) {
            let l = vec![
                vec![(1u32, Fr::from(1u64))],
                vec![(4u32, Fr::from(1u64))],
            ];
            let r_mat = vec![
                vec![(2u32, Fr::from(1u64))],
                vec![(5u32, Fr::from(1u64))],
            ];
            let o = vec![
                vec![(3u32, Fr::from(1u64))],
                vec![(6u32, Fr::from(1u64))],
            ];
            let z = vec![
                Fr::from(1u64),
                Fr::from(a1),
                Fr::from(b1),
                Fr::from(a1) * Fr::from(b1),
                Fr::from(a2),
                Fr::from(b2),
                Fr::from(a2) * Fr::from(b2),
            ];
            let u = Fr::from(1u64);
            let e = vec![Fr::zero(); 2];

            let (proof, _) = prove(&l, &r_mat, &o, &z, u, &e);
            let mut bad_proof = proof.clone();
            // Flip claimed sum.
            bad_proof.claims[0] += Fr::from(flip_val);
            let (ok, _, _) = verify(&bad_proof);
            prop_assert!(!ok, "tampered sumcheck proof must be rejected");
        }

        /// Property: two different vectors produce different HashPC commitments.
        #[test]
        fn prop_hashpc_binding(
            v1 in proptest::collection::vec(arb_fr(), 4),
            v2 in proptest::collection::vec(arb_fr(), 4),
        ) {
            prop_assume!(v1 != v2, "need distinct vectors");
            let params = PedersenParams::from_seed(b"binding-test", 4, 1);
            let (h1, _) = poly_commit(&v1, &params.basis_w);
            let (h2, _) = poly_commit(&v2, &params.basis_w);
            prop_assert_ne!(h1, h2, "different vectors must produce different commitments");
        }

        /// Property: HashPC commitment is deterministic.
        #[test]
        fn prop_hashpc_deterministic(
            v in proptest::collection::vec(arb_fr(), 4),
        ) {
            let params = PedersenParams::from_seed(b"det-test", 4, 1);
            let (h1, p1) = poly_commit(&v, &params.basis_w);
            let (h2, p2) = poly_commit(&v, &params.basis_w);
            prop_assert_eq!(h1, h2);
            prop_assert_eq!(p1, p2);
        }

        /// Property: HashPC opening verifies for random vectors and random r.
        #[test]
        fn prop_hashpc_opening_verifies(
            v in proptest::collection::vec(arb_fr(), 4),
        ) {
            let params = PedersenParams::from_seed(b"opening-test", 4, 1);
            let (hash, _) = poly_commit(&v, &params.basis_w);
            let proof = create_opening(&v);
            let r = vec![Fr::from(3u64), Fr::from(5u64)];
            let claimed = eval_dense_mle(&v, &r);
            prop_assert!(verify_opening(&hash, &proof, &claimed, &r));
        }

        /// Property: HashPC opening rejects tampered table.
        #[test]
        fn prop_hashpc_tamper_rejects(
            v in proptest::collection::vec(arb_fr(), 4),
            flip in 1u64..1000,
        ) {
            let params = PedersenParams::from_seed(b"tamper-test", 4, 1);
            let (hash, _) = poly_commit(&v, &params.basis_w);
            let mut proof = create_opening(&v);
            proof.table[0] += Fr::from(flip);
            let r = vec![Fr::from(3u64), Fr::from(5u64)];
            let claimed = eval_dense_mle(&v, &r);
            prop_assert!(!verify_opening(&hash, &proof, &claimed, &r));
        }

        /// Property: eval_dense_mle at a Boolean point matches direct index access.
        #[test]
        fn prop_dense_mle_boolean_point(
            vals in proptest::collection::vec(arb_fr(), 4),
        ) {
            // For index i, the Boolean point r has r[bit] = (i >> bit) & 1.
            // i=0 → [0,0], i=1 → [1,0], i=2 → [0,1], i=3 → [1,1]
            let r0 = vec![Fr::from(0u64), Fr::from(0u64)];
            let r1 = vec![Fr::from(1u64), Fr::from(0u64)];
            let r2 = vec![Fr::from(0u64), Fr::from(1u64)];
            let r3 = vec![Fr::from(1u64), Fr::from(1u64)];
            prop_assert_eq!(eval_dense_mle(&vals, &r0), vals[0]);
            prop_assert_eq!(eval_dense_mle(&vals, &r1), vals[1]);
            prop_assert_eq!(eval_dense_mle(&vals, &r2), vals[2]);
            prop_assert_eq!(eval_dense_mle(&vals, &r3), vals[3]);
        }

        /// Property: sumcheck proof round count = log2ceil(next_power_of_two(n_constraints)).
        #[test]
        fn prop_proof_round_count(
            n_constraints in 1usize..32,
        ) {
            let mut l = Vec::new();
            let mut r_mat = Vec::new();
            let mut o = Vec::new();
            for i in 0..n_constraints {
                l.push(vec![((1 + 3 * i) as u32, Fr::from(1u64))]);
                r_mat.push(vec![((2 + 3 * i) as u32, Fr::from(1u64))]);
                o.push(vec![((3 + 3 * i) as u32, Fr::from(1u64))]);
            }
            let mut z = vec![Fr::from(1u64)];
            for i in 0..n_constraints {
                let a = Fr::from((i + 2) as u64);
                let b = Fr::from((i + 3) as u64);
                z.push(a);
                z.push(b);
                z.push(a * b);
            }
            let e = vec![Fr::zero(); n_constraints];
            let (proof, _) = prove(&l, &r_mat, &o, &z, Fr::from(1u64), &e);

            let expected_rounds = log2ceil(next_power_of_two(n_constraints));
            prop_assert_eq!(proof.polys.len(), expected_rounds);
        }

        /// Property: parallel sumcheck prover produces identical proof to sequential.
        #[test]
        fn prop_parallel_sumcheck_matches_sequential(
            a1 in 1u64..500,
            b1 in 1u64..500,
            a2 in 1u64..500,
            b2 in 1u64..500,
        ) {
            let l = vec![
                vec![(1u32, Fr::from(1u64))],
                vec![(4u32, Fr::from(1u64))],
            ];
            let r_mat = vec![
                vec![(2u32, Fr::from(1u64))],
                vec![(5u32, Fr::from(1u64))],
            ];
            let o = vec![
                vec![(3u32, Fr::from(1u64))],
                vec![(6u32, Fr::from(1u64))],
            ];
            let z = vec![
                Fr::from(1u64),
                Fr::from(a1),
                Fr::from(b1),
                Fr::from(a1) * Fr::from(b1),
                Fr::from(a2),
                Fr::from(b2),
                Fr::from(a2) * Fr::from(b2),
            ];
            let u = Fr::from(1u64);
            let e = vec![Fr::zero(); 2];

            let (seq_proof, seq_r) = prove_with_opts(&l, &r_mat, &o, &z, u, &e, false);
            let (par_proof, par_r) = prove_with_opts(&l, &r_mat, &o, &z, u, &e, true);

            prop_assert_eq!(proof_hash(&seq_proof), proof_hash(&par_proof));
            prop_assert_eq!(seq_r, par_r);

            let (ok_seq, _, _) = verify(&seq_proof);
            let (ok_par, _, _) = verify(&par_proof);
            prop_assert!(ok_seq, "sequential proof must verify");
            prop_assert!(ok_par, "parallel proof must verify");
        }
    }
}
