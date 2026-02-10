use bls/g2_basic.{aggregate_signatures, aggregate_verify, skToPk, sign, verify}
use bls/tests/utils.{construct_rogue_key}

test test_bls () {
  let sk = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"

  let pk = skToPk(sk)
  let message = "Hello, Aiken!"

  let signature = sign(sk, message)

  verify(pk, message, signature)
}

test three_party_potentially_unsafe_signature_aggregation_bls () {
  // party1
  let sk1 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9a"
  let pk1 = skToPk(sk1)

  // party2
  let sk2 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9b"
  let pk2 = skToPk(sk2)

  // party3
  let sk3 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
  let pk3 = skToPk(sk3)

  // if each message is unique then the 'aggregate_signatures' with 'aggregate_verify'
  // is safe, but if this condition is not satisfied then it is not
  // as demonstrated in 'three_party_unsafe_signature_aggregation_bls'
  let message1 = "Hello, Aiken from party 1!"
  let message2 = "Hello, Aiken from party 2!"
  let message3 = "Hello, Aiken from party 3!"

  let sig1 = sign(sk1, message1)
  let sig2 = sign(sk2, message2)
  let sig3 = sign(sk3, message3)

  let sig_aggr = aggregate_signatures([sig1, sig2, sig3])

  // full signature aggregation
  let full_aggr_predicate = aggregate_verify([pk1,pk2,pk3], [message1,message2,message3], sig_aggr)

  // partial signature aggregation
  let sig13_aggr = aggregate_signatures([sig1, sig3])  
  full_aggr_predicate && aggregate_verify([pk1,pk3], [message1,message3], sig13_aggr)
}

test three_party_unsafe_signature_aggregation_bls () {
  // party1
  let sk1 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9a"
  let pk1 = skToPk(sk1)

  // party2
  let sk2 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9b"
  let pk2 = skToPk(sk2)

  // party3 - assuming now it is attacker
  let sk3 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
  let pk3 = skToPk(sk3)
  // one creates rogue_pk
  let rogue_pk3 = construct_rogue_key(pk1, pk2, pk3)

  let message = "Hello, Aiken from party!"

  // Although all parties can produce signatures
  // let _sig1 = sign(sk1, message)
  // let _sig2 = sign(sk2, message)
  let sig3 = sign(sk3, message)

  // only sig3 is needed to verify! sig1 and sig2 could be omitted
  aggregate_verify([pk1,pk2,rogue_pk3], [message,message,message], sig3)
}