use bls/g2_basic as basic_bls
use bls/tests/utils.{construct_rogue_key}

test test_basic_bls () {
  let sk = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"

  let pk = basic_bls.skToPk(sk)
  let message = "Hello, Aiken!"

  let signature = basic_bls.sign(sk, message)

  basic_bls.verify(pk, message, signature)
}

test three_party_potentially_unsafe_signature_aggregation_bls () {
  // party1
  let sk1 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9a"
  let pk1 = basic_bls.skToPk(sk1)

  // party2
  let sk2 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9b"
  let pk2 = basic_bls.skToPk(sk2)

  // party3
  let sk3 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
  let pk3 = basic_bls.skToPk(sk3)

  // if each message is unique then the 'aggregate_signatures' with 'aggregate_verify'
  // is safe, but if this condition is not satisfied then it is not
  // as demonstrated in 'three_party_unsafe_signature_aggregation_bls'
  let message1 = "Hello, Aiken from party 1!"
  let message2 = "Hello, Aiken from party 2!"
  let message3 = "Hello, Aiken from party 3!"

  let sig1 = basic_bls.sign(sk1, message1)
  let sig2 = basic_bls.sign(sk2, message2)
  let sig3 = basic_bls.sign(sk3, message3)

  let sig_aggr = basic_bls.aggregate_signatures([sig1, sig2, sig3])

  // full signature aggregation
  let full_aggr_predicate = basic_bls.aggregate_verify([pk1,pk2,pk3], [message1,message2,message3], sig_aggr)

  // partial signature aggregation
  let sig13_aggr = basic_bls.aggregate_signatures([sig1, sig3])  
  full_aggr_predicate && basic_bls.aggregate_verify([pk1,pk3], [message1,message3], sig13_aggr)
}

test three_party_unsafe_signature_aggregation_bls () {
  // party1
  let sk1 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9a"
  let pk1 = basic_bls.skToPk(sk1)

  // party2
  let sk2 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9b"
  let pk2 = basic_bls.skToPk(sk2)

  // party3 - assuming now it is attacker
  let sk3 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
  let pk3 = basic_bls.skToPk(sk3)
  // one creates rogue_pk
  let rogue_pk3 = construct_rogue_key(pk1, pk2, pk3)

  let message = "Hello, Aiken from party!"

  // Although all parties can produce signatures
  // let _sig1 = basic_bls.sign(sk1, message)
  // let _sig2 = basic_bls.sign(sk2, message)
  let sig3 = basic_bls.sign(sk3, message)

  // only sig3 is needed to verify! sig1 and sig2 could be omitted
  let sigs_aggr_predicate = basic_bls.aggregate_verify([pk1,pk2,rogue_pk3], [message,message,message], sig3)

  // the same vulnerability is present when public key aggregation is used
  let pk_aggr = basic_bls.aggregate_publickeys([pk1,pk2,rogue_pk3])  
  sigs_aggr_predicate &&
  basic_bls.aggregate_verify([pk_aggr], [message,message,message], sig3)
}