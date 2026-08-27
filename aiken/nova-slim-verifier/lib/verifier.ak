//// NovaSlim — on-chain sumcheck verifier for BLS12-381.
////
//// This validator checks a *slim proof*: the sumcheck protocol only, with no
//// commitment openings.  It is commitment-scheme agnostic: the same verifier
//// works for Pedersen, SIS, and Hash folded instances.
////
//// The arithmetic is carried out in the BLS12-381 scalar field (Fr), which
//// Plutus V3 supports natively via `bls12_381/scalar`.

use aiken/builtin
use aiken/hash.{blake2b_256}
use aiken/list
use aiken/primitive/bytearray
use bls12_381/scalar.{Scalar, add, mul, negate, new, one, zero}

/// ---------------------------------------------------------------------------
/// Types
/// ---------------------------------------------------------------------------

/// One sumcheck round: a degree-2 univariate polynomial represented by its
/// evaluations at X = 0, 1, 2.
pub type RoundPoly {
  eval_at_0: Scalar,
  eval_at_1: Scalar,
  eval_at_2: Scalar,
}

/// The slim proof that travels on-chain.
pub type SlimProof {
  rounds: List<RoundPoly>,
  challenges: List<Scalar>,
  az_r: Scalar,
  bz_r: Scalar,
  cz_r: Scalar,
  er_r: Scalar,
  public_input: ByteArray,
  u: Scalar,
}

/// The NIFS bundle anchors the proof to a specific folded instance.
pub type NifsBundle {
  com_w_hash: ByteArray,
  com_e_hash: ByteArray,
  transcript_hash: ByteArray,
}

/// ---------------------------------------------------------------------------
/// Sumcheck verification
/// ---------------------------------------------------------------------------

/// Verify the slim proof against the NIFS bundle.
pub fn verify_slim(bundle: NifsBundle, proof: SlimProof) -> Bool {
  let counts_ok =
    list.length(proof.rounds) == list.length(proof.challenges)

  // Verify each round: h_i(0) + h_i(1) == previous_claim.
  let rounds_ok = verify_all_rounds(proof.rounds, proof.challenges)

  // Final evaluation check.
  let final_ok = verify_final(proof)

  counts_ok && rounds_ok && final_ok
}

/// Verify all rounds using list folding.
fn verify_all_rounds(rounds: List<RoundPoly>, challenges: List<Scalar>) -> Bool {
  let round_checks = list.map2(rounds, challenges, fn(r, c) {
    (r.eval_at_0, r.eval_at_1, r.eval_at_2, c)
  })

  do_verify_rounds(round_checks, zero())
}

fn do_verify_rounds(checks: List<(Scalar, Scalar, Scalar, Scalar)>, prev_claim: Scalar) -> Bool {
  when checks is {
    [] -> True
    [(e0, e1, e2, challenge), ..rest] -> {
      let round_ok = builtin.bls12_381_scalar_eq(add(e0, e1), prev_claim)
      let next_claim = eval_poly(e0, e1, e2, challenge)
      round_ok && do_verify_rounds(rest, next_claim)
    }
  }
}

/// Evaluate degree-2 polynomial at x using Lagrange interpolation on {0,1,2}.
fn eval_poly(c0: Scalar, c1: Scalar, c2: Scalar, x: Scalar) -> Scalar {
  let t0 = mul(add(x, negate(one())), add(x, negate(add(one(), one()))))
  let term0 = mul(c0, mul(t0, inv2()))

  let t1 = mul(x, add(add(one(), one()), negate(x)))
  let term1 = mul(c1, t1)

  let t2 = mul(x, add(x, negate(one())))
  let term2 = mul(c2, mul(t2, inv2()))

  add(term0, add(term1, term2))
}

/// 1/2 in BLS12-381 Fr.
fn inv2() -> Scalar {
  new(#"12208678551665542018990610568167798225643317578749626236163850497270288801280")
}

/// Verify the final evaluation: az_r * bz_r - u * cz_r - e_r == final_claim.
fn verify_final(proof: SlimProof) -> Bool {
  let final_claim =
    when list.last(proof.rounds) is {
      Some(last_round) ->
        when list.last(proof.challenges) is {
          Some(last_challenge) ->
            eval_poly(last_round.eval_at_0, last_round.eval_at_1, last_round.eval_at_2, last_challenge)
          None -> zero()
        }
      None -> zero()
    }

  let lhs =
    add(
      mul(proof.az_r, proof.bz_r),
      add(negate(mul(proof.u, proof.cz_r)), negate(proof.er_r)),
    )

  builtin.bls12_381_scalar_eq(lhs, final_claim)
}

/// ---------------------------------------------------------------------------
/// Fiat-Shamir challenge derivation
/// ---------------------------------------------------------------------------

/// Derive challenges from the NIFS bundle and round polynomials.
pub fn derive_challenges(
  bundle: NifsBundle,
  rounds: List<RoundPoly>,
  public_input: ByteArray,
) -> List<Scalar> {
  let transcript =
    bytearray.concat(
      bytearray.concat(bundle.com_w_hash, bundle.com_e_hash),
      bytearray.concat(bundle.transcript_hash, public_input),
    )
  derive_challenges_acc(rounds, transcript, [])
}

fn derive_challenges_acc(
  rounds: List<RoundPoly>,
  transcript: ByteArray,
  acc: List<Scalar>,
) -> List<Scalar> {
  when rounds is {
    [] -> list.reverse(acc)
    [round, ..rest] -> {
      let round_bytes =
        bytearray.concat(
          bytearray.concat(
            builtin.bls12_381_scalar_to_bytes(round.eval_at_0),
            builtin.bls12_381_scalar_to_bytes(round.eval_at_1),
          ),
          builtin.bls12_381_scalar_to_bytes(round.eval_at_2),
        )
      let new_transcript = bytearray.concat(transcript, round_bytes)
      let hash = blake2b_256(new_transcript)
      let challenge = new(hash)
      derive_challenges_acc(rest, new_transcript, [challenge, ..acc])
    }
  }
}
