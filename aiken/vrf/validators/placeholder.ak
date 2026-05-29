use vrf/core as vrf

const encode_to_curve_salt = #"45535652455f"

pub fn key_gen(secret: ByteArray) -> (ByteArray, ByteArray) {
  vrf.keys_from_secret(secret)
}

pub fn prove(sk: ByteArray, alpha: ByteArray) -> ByteArray {
  vrf.prove(sk, alpha, encode_to_curve_salt)
}

pub fn verify(pk: ByteArray, alpha: ByteArray, pi: ByteArray) -> Option<ByteArray> {
  vrf.verify(pk, alpha, pi, encode_to_curve_salt, False)
}

test t1() {
  let secret = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
  let (sk, pk) = key_gen(secret)
  let pi = prove(sk, "test input")
  verify(pk, "test input", pi) != None
}

test t2() {
  let (sk, pk) = key_gen("my_secret_password_12345")
  let pi = prove(sk, "my_secret_password_12345")
  verify(pk, "my_secret_password_12345", pi) != None
}

test t3() {
  let (sk, pk) = key_gen("block_12345_hash")
  let pi = prove(sk, "block_12345_hash")
  when verify(pk, "block_12345_hash", pi) is {
    Some(beta) -> vrf.proof_to_hash(pi) == Some(beta)
    None -> False
  }
}

test test_leader_selection() {
  // Shared epoch for a consensus slot
  let epoch = "epoch_12345_slot_42"

  // Alice (30% stake)
  let (sk_alice, pk_alice) = key_gen("alice_stake_secret")
  let pi_alice = prove(sk_alice, epoch)

  // Bob (50% stake)
  let (sk_bob, pk_bob) = key_gen("bob_stake_secret")
  let pi_bob = prove(sk_bob, epoch)

  // Charlie (20% stake)
  let (sk_charlie, pk_charlie) = key_gen("charlie_stake_secret")
  let pi_charlie = prove(sk_charlie, epoch)

  // Network verifies each stakeholder's proof
  let verified_alice = verify(pk_alice, epoch, pi_alice)
  let verified_bob = verify(pk_bob, epoch, pi_bob)
  let verified_charlie = verify(pk_charlie, epoch, pi_charlie)

  let beta_alice = vrf.proof_to_hash(pi_alice)
  let beta_bob = vrf.proof_to_hash(pi_bob)
  let beta_charlie = vrf.proof_to_hash(pi_charlie)

  // All stakeholders produce valid proofs for the same epoch.
  // verify and proof_to_hash agree for each participant.
  verified_alice == beta_alice &&
    verified_bob == beta_bob &&
    verified_charlie == beta_charlie
}

test test_privacy_protected_data() {
  // Prover's secret key
  let secret = "prover_secret_key"
  let (sk, pk) = key_gen(secret)

  // Multiple private records
  let record_1 = "alice_payment_100"
  let record_2 = "bob_escrow_250"
  let record_3 = "charlie_refund_50"

  // Only the prover can compute the "address" for each record
  let pi_1 = prove(sk, record_1)
  let pi_2 = prove(sk, record_2)
  let pi_3 = prove(sk, record_3)

  let beta_1 = vrf.proof_to_hash(pi_1)
  let beta_2 = vrf.proof_to_hash(pi_2)
  let beta_3 = vrf.proof_to_hash(pi_3)

  // Verifier checks membership for each record
  let verified_1 = verify(pk, record_1, pi_1)
  let verified_2 = verify(pk, record_2, pi_2)
  let verified_3 = verify(pk, record_3, pi_3)

  // All records are verified at their VRF-derived addresses.
  // Without sk, an attacker cannot link beta values to record names.
  verified_1 == beta_1 && verified_2 == beta_2 && verified_3 == beta_3
}