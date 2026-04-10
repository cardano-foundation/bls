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

test t4() {
  let epoch = "epoch_12345"
  let (sk, pk) = key_gen("stakeholder_key")
  let pi = prove(sk, epoch)
  verify(pk, epoch, pi) != None
}

test t5() {
  let secret = "prover_secret_key"
  let (sk, pk) = key_gen(secret)
  let data = "important_record_123"
  let pi = prove(sk, data)
  when verify(pk, data, pi) is {
    Some(beta) -> {
      let beta2 = vrf.proof_to_hash(pi)
      beta2 == Some(beta)
    }
    None -> False
  }
}