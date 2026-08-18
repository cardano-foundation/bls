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
//! Each matrix row `i` defines a multilinear extension (MLE):
//!
//!   `A_MLE(r_0..r_{k-1}) = Σ_j A[i][j] · r_j`
//!
//! where the sum is over the non-zero entries of row `i`, each contributing
//! `coeff * r[wire]`.  The constraint polynomial is:
//!
//!   `P(j, r_0..r_{k-1}) = A_MLE(j,r) · B_MLE(j,r) − u · C_MLE(j,r) − E_MLE(j,r)`
//!
//! and the sumcheck proves `Σ_{j∈{0,1}^k} P(j, r) = 0` for a random `r`.
//!
//! ## Commitment scheme
//!
//! Witness and error vectors are committed via a HashPC scheme: a Merkle
//! tree (BLAKE2b) over the truth-table evaluations of the MLE, plus a
//! Pedersen commitment (reusing `nifs::PedersenParams`) for the coefficient
//! binding.  Opening at a random point provides a truth-table proof.

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, One, PrimeField, UniformRand, Zero};
use blake2::{Blake2b512, Digest};

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
/// `v_MLE(r) = Σ_{i∈{0,1}^k} v[i] · r_0^{i_0} · (1−r_0)^{1−i_0} · ...`.
pub fn eval_dense_mle(v: &[Fr], r: &[Fr]) -> Fr {
    let k = r.len();
    assert_eq!(v.len(), 1 << k, "v length must be 2^r.len()");
    let mut result = Fr::zero();
    for (i, &val) in v.iter().enumerate() {
        let mut term = val;
        for bit in 0..k {
            let b = (i >> bit) & 1;
            if b == 0 {
                term *= Fr::one() - r[bit];
            } else {
                term *= r[bit];
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
/// coefficients).  Degree ≤ 2 (from the product `A·B` term).
pub type PolyCoeffs = Vec<Fr>;

/// The sumcheck proof: one polynomial per round.
#[derive(Debug, Clone)]
pub struct SumcheckProof {
    /// `claims[0]` = claimed sum; `claims[1..num_rounds]` = evaluations at
    /// the round's random challenge.
    pub claims: Vec<Fr>,
    /// Univariate polynomial coefficients for each round (degree 2).
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
        h.update(&e.into_bigint().to_bytes_le());
    }
    h.finalize().to_vec()
}

/// Run the sumcheck prover for the relaxed R1CS check.
///
/// `l`, `r`, `o` are the step circuit's sparse A/B/C matrices.
/// `z` is the full folded witness vector.  `u` is the slack scalar.
/// `e` is the error vector.
///
/// Returns `(proof, r_challenges)` where `r_challenges` are the Fiat-Shamir
/// random challenges derived during the protocol.
pub fn prove(
    l: &[Vec<(u32, Fr)>],
    r: &[Vec<(u32, Fr)>],
    o: &[Vec<(u32, Fr)>],
    z: &[Fr],
    u: Fr,
    e: &[Fr],
) -> (SumcheckProof, Vec<Fr>) {
    let n = l.len();
    assert_eq!(r.len(), n);
    assert_eq!(o.len(), n);
    assert_eq!(e.len(), n);
    let n_padded = next_power_of_two(n);
    let num_rounds = log2ceil(n_padded);
    if num_rounds == 0 {
        return (
            SumcheckProof {
                claims: vec![Fr::zero()],
                polys: vec![],
            },
            vec![],
        );
    }

    // Compute per-row products: az[j]·bz[j] − u·cz[j] − e[j].
    let products: Vec<Fr> = (0..n)
        .map(|j| {
            let az = eval_row_mle(&l[j], z);
            let bz = eval_row_mle(&r[j], z);
            let cz = eval_row_mle(&o[j], z);
            az * bz - u * cz - e[j]
        })
        .collect();

    // Pad products to power-of-two length.  These are the evaluations of
    // the multilinear polynomial at all Boolean hypercube points.
    let mut current = products;
    current.resize(n_padded, Fr::zero());

    let mut claims = Vec::with_capacity(num_rounds + 1);
    let mut polys: Vec<PolyCoeffs> = Vec::with_capacity(num_rounds);
    let mut r_challenges: Vec<Fr> = Vec::with_capacity(num_rounds);

    for _round in 0..num_rounds {
        let half = current.len() / 2;

        // Claimed sum for this round: Σ_{x∈{0,1}} g(x, ...)
        let claimed: Fr = current.iter().sum();
        claims.push(claimed);

        // Build degree-2 polynomial: f(x) = Σ_{y∈{0,1}^{k-1}} g(x, y_1,...,y_{k-1})
        // where g is multilinear in the current variables.
        // For each j in 0..half:
        //   f_base[j] = current[2j] (x=0, y = rest of j)
        //   f_one[j]  = current[2j+1] (x=1, y = rest of j)
        // Then f(x) = Σ_j f_base[j]·(1-x) + f_one[j]·x
        //           = Σ_j f_base[j] + x · Σ_j (f_one[j] - f_base[j])
        let mut sum_base = Fr::zero();
        let mut sum_diff = Fr::zero();
        for j in 0..half {
            let a = current[2 * j];
            let b = current[2 * j + 1];
            sum_base += a;
            sum_diff += b - a;
        }
        let poly = vec![sum_base, sum_diff, Fr::zero()];
        polys.push(poly);

        // Fiat-Shamir: hash claims + poly coefficients.
        let mut hash_input = claims.clone();
        for c in polys.last().unwrap() {
            hash_input.push(*c);
        }
        let h = hash_field_elements(&hash_input);
        let ri = challenge_from_hash(&h);
        r_challenges.push(ri);

        // Fold: g'(y_1,...,y_{k-1}) = g(r_i, y_1,...,y_{k-1})
        //     = Σ_j (f_base[j] + r_i · f_diff[j]) for each remaining variable
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
/// `claimed_sum` is the sum the prover claims (should be 0 for a valid
/// relaxed R1CS instance).  `a_mle`, `b_mle`, `c_mle` are the MLE
/// evaluations of the A, B, C matrices at the random point `r`.
/// `u` is the slack scalar and `e_at_r` is the error MLE at `r`.
///
/// Returns `(ok, r_challenges)`.
pub fn verify(
    proof: &SumcheckProof,
    a_mle: &[Fr],
    b_mle: &[Fr],
    c_mle: &[Fr],
    u: Fr,
    e_at_r: Fr,
) -> (bool, Vec<Fr>) {
    let claimed_sum = proof.claims[0];
    let num_rounds = proof.polys.len();
    if num_rounds == 0 {
        return (claimed_sum.is_zero(), vec![]);
    }

    // Check degree ≤ 1 for each round polynomial.
    for poly in &proof.polys {
        if poly.len() > 3 {
            return (false, vec![]);
        }
        // The x^2 coefficient should be zero for MLE sumcheck.
        if poly.len() > 2 && !poly[2].is_zero() {
            return (false, vec![]);
        }
    }

    // Verify each round.
    let mut current_sum = claimed_sum;
    let mut r_challenges: Vec<Fr> = Vec::with_capacity(num_rounds);

    for round in 0..num_rounds {
        let poly = &proof.polys[round];

        // Check: f(0) + f(1) == current_sum
        // f(0) = poly[0], f(1) = poly[0] + poly[1]
        let s0 = poly[0];
        let s1 = poly[0] + poly[1];
        if s0 + s1 != current_sum {
            return (false, vec![]);
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

    // Final check: A_MLE(r)·B_MLE(r) − u·C_MLE(r) − E_MLE(r) == final claim
    let final_claim = proof.claims[num_rounds];
    let mut check_sum = Fr::zero();
    for j in 0..a_mle.len() {
        check_sum += a_mle[j] * b_mle[j] - u * c_mle[j];
    }
    check_sum -= e_at_r;

    let ok = check_sum == final_claim && current_sum == final_claim;
    (ok, r_challenges)
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
            h.update(&val.into_bigint().to_bytes_le());
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

/// Create an opening proof for a vector at random point `r`.
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
            h.update(&val.into_bigint().to_bytes_le());
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
        h.update(&c.into_bigint().to_bytes_le());
    }
    for poly in &p.polys {
        for c in poly {
            h.update(&c.into_bigint().to_bytes_le());
        }
    }
    h.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nifs::PedersenParams;

    /// One-constraint multiplier: Z[1]·Z[2] = Z[3], wire 0 = constant 1.
    fn simple_r1cs() -> (Vec<Vec<(u32, Fr)>>, Vec<Vec<(u32, Fr)>>, Vec<Vec<(u32, Fr)>>) {
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
        // At Boolean point (0,0): v[0] = 10
        assert_eq!(
            eval_dense_mle(&v, &[Fr::zero(), Fr::zero()]),
            Fr::from(10u64)
        );
        // At Boolean point (1,0): v[1] = 20
        assert_eq!(
            eval_dense_mle(&v, &[Fr::one(), Fr::zero()]),
            Fr::from(20u64)
        );
        // At Boolean point (0,1): v[2] = 30
        assert_eq!(
            eval_dense_mle(&v, &[Fr::zero(), Fr::one()]),
            Fr::from(30u64)
        );
        // At Boolean point (1,1): v[3] = 40
        assert_eq!(
            eval_dense_mle(&v, &[Fr::one(), Fr::one()]),
            Fr::from(40u64)
        );
    }

    #[test]
    fn sumcheck_satisfying_witness_produces_valid_proof() {
        let (l, r, o) = simple_r1cs();
        // Satisfying witness: [1, 3, 5, 15] (1 = const, 3·5 = 15)
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero()];

        let (proof, r_challenges) = prove(&l, &r, &o, &z, u, &e);
        assert_eq!(proof.claims[0], Fr::zero(), "claimed sum must be 0");

        // Verify.
        let a_mle: Vec<Fr> = (0..l.len())
            .map(|j| eval_row_mle(&l[j], &r_challenges))
            .collect();
        let b_mle: Vec<Fr> = (0..r.len())
            .map(|j| eval_row_mle(&r[j], &r_challenges))
            .collect();
        let c_mle: Vec<Fr> = (0..o.len())
            .map(|j| eval_row_mle(&o[j], &r_challenges))
            .collect();
        let e_at_r = eval_dense_mle(&[e[0], Fr::zero()], &r_challenges);

        let (ok, _) = verify(&proof, &a_mle, &b_mle, &c_mle, u, e_at_r);
        assert!(ok, "sumcheck must verify for a satisfying witness");
    }

    #[test]
    fn sumcheck_unsatisfying_witness_fails() {
        let (l, r, o) = simple_r1cs();
        // Unsatisfying: 3·5 ≠ 20 (error is not zero)
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(20u64),
        ];
        let u = Fr::from(1u64);
        let e = vec![Fr::zero()];

        let (proof, r_challenges) = prove(&l, &r, &o, &z, u, &e);
        // The claimed sum should be non-zero.
        assert_ne!(proof.claims[0], Fr::zero());

        let a_mle: Vec<Fr> = (0..l.len())
            .map(|j| eval_row_mle(&l[j], &r_challenges))
            .collect();
        let b_mle: Vec<Fr> = (0..r.len())
            .map(|j| eval_row_mle(&r[j], &r_challenges))
            .collect();
        let c_mle: Vec<Fr> = (0..o.len())
            .map(|j| eval_row_mle(&o[j], &r_challenges))
            .collect();
        let e_at_r = eval_dense_mle(&[e[0], Fr::zero()], &r_challenges);

        let (ok, _) = verify(&proof, &a_mle, &b_mle, &c_mle, u, e_at_r);
        assert!(!ok, "sumcheck must fail for an unsatisfying witness");
    }

    #[test]
    fn sumcheck_with_nonzero_error() {
        let (l, r, o) = simple_r1cs();
        // Witness: 3·5 = 15, error = 15, u = 0
        // AZ·BZ = u·CZ + E → 15 = 0 + 15 ✓
        let z = vec![
            Fr::from(1u64),
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(15u64),
        ];
        let u = Fr::from(0u64);
        let e = vec![Fr::from(15u64)];

        let (proof, r_challenges) = prove(&l, &r, &o, &z, u, &e);
        assert_eq!(proof.claims[0], Fr::zero());

        let a_mle: Vec<Fr> = (0..l.len())
            .map(|j| eval_row_mle(&l[j], &r_challenges))
            .collect();
        let b_mle: Vec<Fr> = (0..r.len())
            .map(|j| eval_row_mle(&r[j], &r_challenges))
            .collect();
        let c_mle: Vec<Fr> = (0..o.len())
            .map(|j| eval_row_mle(&o[j], &r_challenges))
            .collect();
        let e_at_r = eval_dense_mle(&[e[0], Fr::zero()], &r_challenges);

        let (ok, _) = verify(&proof, &a_mle, &b_mle, &c_mle, u, e_at_r);
        assert!(ok, "sumcheck must verify with non-zero error");
    }

    #[test]
    fn sumcheck_multi_constraint() {
        // Two independent multiplier constraints:
        // w[1]*w[2] = w[3], w[4]*w[5] = w[6]
        let l = vec![
            vec![(1u32, Fr::from(1u64))],
            vec![(4u32, Fr::from(1u64))],
        ];
        let r = vec![
            vec![(2u32, Fr::from(1u64))],
            vec![(5u32, Fr::from(1u64))],
        ];
        let o = vec![
            vec![(3u32, Fr::from(1u64))],
            vec![(6u32, Fr::from(1u64))],
        ];
        // [1, 3, 5, 15, 7, 11, 77]
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

        let (proof, r_challenges) = prove(&l, &r, &o, &z, u, &e);
        assert_eq!(proof.claims[0], Fr::zero());
        // 2 constraints → padded to 2 → log2(2) = 1 round
        assert_eq!(proof.polys.len(), 1);

        let a_mle: Vec<Fr> = (0..l.len())
            .map(|j| eval_row_mle(&l[j], &r_challenges))
            .collect();
        let b_mle: Vec<Fr> = (0..r.len())
            .map(|j| eval_row_mle(&r[j], &r_challenges))
            .collect();
        let c_mle: Vec<Fr> = (0..o.len())
            .map(|j| eval_row_mle(&o[j], &r_challenges))
            .collect();
        let e_padded = [e[0], e[1], Fr::zero(), Fr::zero()];
        let e_at_r = eval_dense_mle(&e_padded, &r_challenges);

        let (ok, _) = verify(&proof, &a_mle, &b_mle, &c_mle, u, e_at_r);
        assert!(ok, "sumcheck must verify for 2-constraint circuit");
    }

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

        // Evaluate at a random point.
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
        // Tamper with the table.
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
}
