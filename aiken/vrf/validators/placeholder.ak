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
    Some(_) -> True
    None -> False
  }
}

test test_proof_of_prior_possession() {
  let secret = "my_secret_password_12345"
  let (sk, pk) = key_gen(secret)
  let pi = prove(sk, secret)
  verify(pk, secret, pi) != None
}

test test_non_interactive_randomness() {
  let input = "block_12345_hash"
  let operator_secret = #"a1b2c3d4e5f6071829384756a7b8c9d0"
  let (sk, pk) = key_gen(operator_secret)
  let pi = prove(sk, input)
  when verify(pk, input, pi) is {
    Some(beta) -> {
      let beta2 = vrf.proof_to_hash(pi)
      beta2 == Some(beta)
    }
    None -> False
  }
}