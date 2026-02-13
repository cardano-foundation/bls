use bls/g2_aug as aug_bls
use bls/g2_basic as basic_bls
use bls/g2_pop as pop_bls
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

test three_party_almost_safe_augmented_signature_aggregation_bls () {
  // party1
  let sk1 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9a"
  let pk1 = aug_bls.skToPk(sk1)

  // party2
  let sk2 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9b"
  let pk2 = aug_bls.skToPk(sk2)

  // party3
  let sk3 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
  let pk3 = aug_bls.skToPk(sk3)

  let message = "Hello, Aiken from all parties!"

  let sig1 = aug_bls.sign(sk1, pk1, message)
  let sig2 = aug_bls.sign(sk2, pk2, message)
  let sig3 = aug_bls.sign(sk3, pk3, message)

  let sig_aggr = aug_bls.aggregate_signatures([sig1, sig2, sig3])

  let rogue_pk3 = construct_rogue_key(pk1, pk2, pk3)

  // sig3 is not anymore enough to verify!
  let rogue_aggr_predicate_fails = aug_bls.aggregate_verify([pk1,pk2,rogue_pk3], [message,message,message], sig3)

  // full signature aggregation works
  let full_aggr_predicate = aug_bls.aggregate_verify([pk1,pk2,pk3], [message,message,message], sig_aggr)

  // partial signature aggregation works also
  let sig13_aggr = aug_bls.aggregate_signatures([sig1, sig3])
  let partial_aggr_predicate = aug_bls.aggregate_verify([pk1,pk3], [message,message], sig13_aggr)  

  // sig3 is still enough to verify when in public key aggregation case
  let pk_aggr = aug_bls.aggregate_publickeys([pk1,pk2,rogue_pk3])  
  let rogue_aggr_pks_predicate_pass = aug_bls.aggregate_verify([pk_aggr], [message,message,message], sig3)

  !rogue_aggr_predicate_fails &&
  full_aggr_predicate &&
  partial_aggr_predicate &&
  rogue_aggr_pks_predicate_pass
}

test three_party_safe_pop_signature_aggregation_bls () {
  // party1
  let sk1 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9a"
  let pk1 = pop_bls.skToPk(sk1)

  // party2
  let sk2 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9b"
  let pk2 = pop_bls.skToPk(sk2)

  // party3
  let sk3 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
  let pk3 = pop_bls.skToPk(sk3)

  // at registration
  let pop1 = pop_bls.pop_prove(sk1)
  let pop2 = pop_bls.pop_prove(sk2)
  let pop3 = pop_bls.pop_prove(sk3)

  expect pop_bls.pop_verify(pk1, pop1)
  expect pop_bls.pop_verify(pk2, pop2)
  expect pop_bls.pop_verify(pk3, pop3)

  let message ="Hello, Aiken from all parties!"

  // now we are sure sks are corresposding to respective pks
  let sig1 = pop_bls.sign(sk1, pk1, message)
  let sig2 = pop_bls.sign(sk2, pk2, message)
  let sig3 = pop_bls.sign(sk3, pk3, message)

  let sig_aggr = pop_bls.aggregate_signatures([sig1, sig2, sig3])

  // full signature aggregation SHOULD work but is not TO_DO
  let full_aggr_predicate = pop_bls.aggregate_verify([pk1,pk2,pk3], [message,message,message], sig_aggr)

  full_aggr_predicate 
}

