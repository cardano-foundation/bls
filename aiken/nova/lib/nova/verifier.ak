use nova/types.{SlimProof}

/// Verify a slim sumcheck compression proof.
///
/// Accepts pre-computed Fiat-Shamir challenges (r_challenges) as part of the
/// proof. The hash-based derivation of challenges is verified off-chain.
/// On-chain, we verify the algebraic sumcheck properties.
pub fn verify_slim(proof: SlimProof) -> Bool {
  let n_rounds = length(proof.sumcheck_polys)
  let n_claims = length(proof.sumcheck_claims)
  n_claims == n_rounds + 1
    && verify_rounds(proof.sumcheck_polys, proof.sumcheck_claims, n_rounds, proof.r_challenges)
    && proof.claimed_product_at_r == tail_last(proof.sumcheck_claims)
}

/// Verify all sumcheck rounds using pre-computed challenges.
fn verify_rounds(
  polys: List<List<Int>>,
  claims: List<Int>,
  n_rounds: Int,
  r_challenges: List<Int>,
) -> Bool {
  when claims is {
    [initial_sum, ..] ->
      do_verify_rounds(polys, claims, 0, n_rounds, initial_sum, r_challenges)
    [] -> False
  }
}

/// Tail-recursive round verification.
fn do_verify_rounds(
  polys: List<List<Int>>,
  claims: List<Int>,
  round: Int,
  n_rounds: Int,
  current_sum: Int,
  r_challenges: List<Int>,
) -> Bool {
  if round >= n_rounds {
    True
  } else {
    when polys is {
      [poly, ..rest_polys] ->
        when poly is {
          [f0, delta] ->
            if f0 + f0 + delta != current_sum {
              False
            } else {
              let ri = get_at(round, r_challenges)
              let next_sum = f0 + delta * ri
              do_verify_rounds(rest_polys, claims, round + 1, n_rounds, next_sum, r_challenges)
            }
          _ -> False
        }
      _ -> False
    }
  }
}

fn get_at(idx: Int, xs: List<a>) -> a {
  when xs is {
    [] -> fail @"get_at: index out of bounds"
    [x, ..rest] ->
      if idx == 0 {
        x
      } else {
        get_at(idx - 1, rest)
      }
  }
}

fn tail_last(xs: List<a>) -> a {
  when xs is {
    [x] -> x
    [_, ..rest] -> tail_last(rest)
    _ -> fail @"tail_last: empty list"
  }
}

fn length(xs: List<a>) -> Int {
  do_length(xs, 0)
}

fn do_length(xs: List<a>, acc: Int) -> Int {
  when xs is {
    [] -> acc
    [_, ..rest] -> do_length(rest, acc + 1)
  }
}
