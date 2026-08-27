use nova_slim_verifier/verifier.{
  NifsBundle, RoundPoly, SlimProof, derive_challenges, verify_slim,
}
use bls12_381/scalar.{add, new, one, zero}

// ---------------------------------------------------------------------------
// Scalar helper test
// ---------------------------------------------------------------------------

test scalar_addition() {
  let a = one()
  let b = one()
  let c = add(a, b)
  c == new(#"0000000000000000000000000000000000000000000000000000000000000002")
}

// ---------------------------------------------------------------------------
// End-to-end test: a toy 4-round circuit
// ---------------------------------------------------------------------------

test e2e_4_rounds() {
  let bundle = NifsBundle {
    com_w_hash: #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    com_e_hash: #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    transcript_hash: #"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
  }

  let rounds = [
    RoundPoly { eval_at_0: zero(), eval_at_1: zero(), eval_at_2: zero() },
    RoundPoly { eval_at_0: zero(), eval_at_1: zero(), eval_at_2: zero() },
    RoundPoly { eval_at_0: zero(), eval_at_1: zero(), eval_at_2: zero() },
    RoundPoly { eval_at_0: zero(), eval_at_1: zero(), eval_at_2: zero() },
  ]

  let challenges = derive_challenges(bundle, rounds, #"00")

  let proof = SlimProof {
    rounds: rounds,
    challenges: challenges,
    az_r: zero(),
    bz_r: zero(),
    cz_r: zero(),
    er_r: zero(),
    public_input: #"00",
    u: one(),
  }

  verify_slim(bundle, proof)
}

// ---------------------------------------------------------------------------
// Negative test: tampered challenge should fail
// ---------------------------------------------------------------------------

test tampered_challenge_fails() {
  let bundle = NifsBundle {
    com_w_hash: #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    com_e_hash: #"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    transcript_hash: #"abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234",
  }

  let rounds = [
    RoundPoly { eval_at_0: zero(), eval_at_1: zero(), eval_at_2: zero() },
  ]

  let wrong_challenges = [
    new(#"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
  ]

  let proof = SlimProof {
    rounds: rounds,
    challenges: wrong_challenges,
    az_r: zero(),
    bz_r: zero(),
    cz_r: zero(),
    er_r: zero(),
    public_input: #"00",
    u: one(),
  }

  !verify_slim(bundle, proof)
}
