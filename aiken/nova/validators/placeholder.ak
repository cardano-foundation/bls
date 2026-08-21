use aiken/crypto
use aiken/primitive/bytearray
use nova/types.{CircuitParams, FinalInstance, SlimProof}
use nova/verifier

/// BLS12-381 scalar field prime (split to avoid compiler line-length bug).
const BLS12_381_Q = 52435875175126190479447740508185965837690552500527637822603658699938581184513

/// Serialize field elements to concatenated 32-byte LE byte arrays.
fn serialize_list(xs: List<Int>, acc: ByteArray) -> ByteArray {
  when xs is {
    [] -> acc
    [x, ..rest] ->
      serialize_list(rest, bytearray.concat(acc, bytearray.from_int_little_endian(x, 32)))
  }
}

/// Derive a Fiat-Shamir challenge from claims and polynomial coefficients.
/// Uses BLAKE2b-256 + mod q to match Rust prover's `challenge_from_hash`.
fn derive_challenge(claims: List<Int>, poly: List<Int>) -> Int {
  let acc = serialize_list(claims, bytearray.empty())
  let acc2 = serialize_list(poly, acc)
  let raw = bytearray.to_int_little_endian(crypto.blake2b_256(acc2))
  raw % BLS12_381_Q
}

/// Take the first n elements of a list.
fn take_prefix(xs: List<a>, n: Int) -> List<a> {
  do_take_prefix(xs, n, [])
}

fn do_take_prefix(xs: List<a>, n: Int, acc: List<a>) -> List<a> {
  if n <= 0 {
    list.reverse(acc)
  } else {
    when xs is {
      [] -> list.reverse(acc)
      [x, ..rest] -> do_take_prefix(rest, n - 1, [x, ..acc])
    }
  }
}

/// Get the i-th element of a list (0-indexed).
fn get_at(idx: Int, xs: List<a>) -> a {
  when xs is {
    [] -> fail @"get_at: index out of bounds"
    [x, ..rest] ->
      if idx == 0 { x } else { get_at(idx - 1, rest) }
  }
}

/// Get the last element of a non-empty list.
fn tail_last(xs: List<a>) -> a {
  when xs is {
    [x] -> x
    [_, ..rest] -> tail_last(rest)
    _ -> fail @"tail_last: empty list"
  }
}

/// Length of a list.
fn list_length(xs: List<a>) -> Int {
  do_list_length(xs, 0)
}

fn do_list_length(xs: List<a>, acc: Int) -> Int {
  when xs is {
    [] -> acc
    [_, ..rest] -> do_list_length(rest, acc + 1)
  }
}

/// Verify slim sumcheck proof with on-chain Fiat-Shamir (no pre-computed challenges).
fn verify_slim_fs(proof: SlimProof) -> Bool {
  let n_rounds = list_length(proof.sumcheck_polys)
  let n_claims = list_length(proof.sumcheck_claims)
  n_claims == n_rounds + 1
    && do_verify_rounds_fs(proof.sumcheck_polys, proof.sumcheck_claims, 0, n_rounds)
    && proof.claimed_product_at_r == tail_last(proof.sumcheck_claims)
}

fn do_verify_rounds_fs(
  polys: List<List<Int>>,
  claims: List<Int>,
  round: Int,
  n_rounds: Int,
) -> Bool {
  if round >= n_rounds {
    True
  } else {
    when polys is {
      [poly, ..rest_polys] ->
        when poly is {
          [f0, delta] ->
            let current_sum = get_at(round, claims)
            if f0 + f0 + delta != current_sum {
              False
            } else {
              let hash_input = take_prefix(claims, round + 1)
              let ri = derive_challenge(hash_input, poly)
              let next_claim = get_at(round + 1, claims)
              let next_sum = f0 + delta * ri
              next_sum == next_claim
                && do_verify_rounds_fs(rest_polys, claims, round + 1, n_rounds)
            }
          _ -> False
        }
      _ -> False
    }
  }
}

/// Plutus V3 spending validator: verifies a Nova slim sumcheck proof.
/// On-chain Fiat-Shamir: challenges derived from claims + polynomials via
/// BLAKE2b-256 hash + mod q — no pre-computed r_challenges needed.
validator nova_slim_verify {
  spend(datum: Option<CircuitParams>, redeemer: SlimProof, _self: Data, _tx: Data) -> Bool {
    expect Some(params) = datum
    redeemer.circuit_params == params
      && verify_slim_fs(redeemer)
  }

  else(_) {
    fail
  }
}

// ── Tests ──────────────────────────────────────────────────────────────────

test test_fs_single_round_zero() {
  let proof = SlimProof {
    circuit_params: CircuitParams { n_wires: 4, n_constraints: 2, n_pub_out: 1, n_pub_in: 1 },
    final_instance: FinalInstance { x: [0], u: 1, w_commit: #"", e_commit: #"" },
    sumcheck_polys: [[0, 0]],
    sumcheck_claims: [0, 0],
    r_challenges: [0],
    claimed_product_at_r: 0,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verify_slim_fs(proof)
}

test test_fs_two_rounds_zero() {
  let proof = SlimProof {
    circuit_params: CircuitParams { n_wires: 8, n_constraints: 4, n_pub_out: 1, n_pub_in: 1 },
    final_instance: FinalInstance { x: [0], u: 1, w_commit: #"", e_commit: #"" },
    sumcheck_polys: [[0, 0], [0, 0]],
    sumcheck_claims: [0, 0, 0],
    r_challenges: [0, 0],
    claimed_product_at_r: 0,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verify_slim_fs(proof)
}

test test_fs_nonzero_poly() {
  let proof = SlimProof {
    circuit_params: CircuitParams { n_wires: 4, n_constraints: 2, n_pub_out: 1, n_pub_in: 1 },
    final_instance: FinalInstance { x: [0], u: 1, w_commit: #"", e_commit: #"" },
    sumcheck_polys: [[3, 7]],
    sumcheck_claims: [13, 24],
    r_challenges: [0],
    claimed_product_at_r: 24,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verify_slim_fs(proof)
}

test test_fs_wrong_initial_sum() {
  let proof = SlimProof {
    circuit_params: CircuitParams { n_wires: 4, n_constraints: 2, n_pub_out: 1, n_pub_in: 1 },
    final_instance: FinalInstance { x: [0], u: 1, w_commit: #"", e_commit: #"" },
    sumcheck_polys: [[0, 0]],
    sumcheck_claims: [1, 0],
    r_challenges: [0],
    claimed_product_at_r: 0,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verify_slim_fs(proof) == False
}

test test_fs_wrong_final_claim() {
  let proof = SlimProof {
    circuit_params: CircuitParams { n_wires: 4, n_constraints: 2, n_pub_out: 1, n_pub_in: 1 },
    final_instance: FinalInstance { x: [0], u: 1, w_commit: #"", e_commit: #"" },
    sumcheck_polys: [[0, 0]],
    sumcheck_claims: [0, 1],
    r_challenges: [0],
    claimed_product_at_r: 0,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verify_slim_fs(proof) == False
}

test test_fs_mismatched_counts() {
  let proof = SlimProof {
    circuit_params: CircuitParams { n_wires: 4, n_constraints: 2, n_pub_out: 1, n_pub_in: 1 },
    final_instance: FinalInstance { x: [0], u: 1, w_commit: #"", e_commit: #"" },
    sumcheck_polys: [[0, 0]],
    sumcheck_claims: [0],
    r_challenges: [0],
    claimed_product_at_r: 0,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verify_slim_fs(proof) == False
}

test test_fs_cko_real_values() {
  let proof = SlimProof {
    circuit_params: CircuitParams {
      n_wires: 7658,
      n_constraints: 7724,
      n_pub_out: 24,
      n_pub_in: 24,
    },
    final_instance: FinalInstance {
      x: [0, 0, 0, 0],
      u: 1,
      w_commit: #"",
      e_commit: #"",
    },
    sumcheck_polys: [[0, 0], [0, 0]],
    sumcheck_claims: [0, 0, 0],
    r_challenges: [0, 0],
    claimed_product_at_r: 0,
    w_commit_hash: #"",
    e_commit_hash: #"",
  }
  verify_slim_fs(proof)
}
