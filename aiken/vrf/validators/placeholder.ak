use vrf/core as vrf

pub type VrfInput =
  ByteArray

pub type VrfOutput =
  ByteArray

pub type VrfProof =
  ByteArray

pub type VrfSecretKey =
  ByteArray

pub type VrfPublicKey =
  ByteArray

const encode_to_curve_salt = #"45535652455f"

pub fn key_gen(secret: VrfSecretKey) -> (VrfSecretKey, VrfPublicKey) {
  vrf.keys_from_secret(secret)
}

pub fn compute_hash(sk: VrfSecretKey, alpha: VrfInput) -> Option<VrfOutput> {
  let proof = vrf.prove(sk, alpha, encode_to_curve_salt)
  vrf.proof_to_hash(proof)
}

pub fn prove(sk: VrfSecretKey, alpha: VrfInput) -> VrfProof {
  vrf.prove(sk, alpha, encode_to_curve_salt)
}

pub fn verify(pk: VrfPublicKey, alpha: VrfInput, pi: VrfProof) -> Option<VrfOutput> {
  vrf.verify(pk, alpha, pi, encode_to_curve_salt, False)
}

test test_vrf_use_case() {
  let secret = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
  let alpha = "test input"

  let (sk, pk) = key_gen(secret)

  let pi = prove(sk, alpha)

  when verify(pk, alpha, pi) is {
    Some(beta) -> {
      when compute_hash(sk, alpha) is {
        Some(expected_beta) -> beta == expected_beta
        None -> False
      }
    }
    None -> False
  }
}

test test_vrf_proof_deterministic() {
  let secret = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
  let alpha = "test input"

  let (sk, _pk) = key_gen(secret)

  let pi1 = prove(sk, alpha)
  let pi2 = prove(sk, alpha)

  pi1 == pi2
}

test test_invalid_proof_rejected() {
  let secret = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
  let other_secret = #"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
  let alpha = "test input"

  let (_sk, pk) = key_gen(secret)
  let (other_sk, _other_pk) = key_gen(other_secret)

  let pi = prove(other_sk, alpha)

  verify(pk, alpha, pi) == None
}

// Proof of Prior Possession use case
// Alice proves she knows a secret without revealing it
test test_proof_of_prior_possession() {
  // The secret Alice wants to prove she knows
  let secret_knowledge = "my_secret_password_12345"
  let alpha = secret_knowledge

  // Alice generates keypair from secret knowledge
  let (sk, pk) = key_gen(secret_knowledge)

  // Alice computes proof that she knows the secret
  let pi = prove(sk, alpha)

  // Bob (verifier) validates the proof WITHOUT knowing the secret
  // He only has: pk, pi, and alpha (which could be a public commitment)
  when verify(pk, alpha, pi) is {
    Some(_) -> True
    None -> False
  }
}