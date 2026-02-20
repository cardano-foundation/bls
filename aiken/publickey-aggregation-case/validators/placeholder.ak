use bls/api
use bls/g1/basic as basic_bls
use bls/g1/core as core_bls
use bls/core.{key_gen}
use bls/tests/utils.{construct_rogue_key}

use bls_extra/core as bls_extra_core

//TO VERIFY AGAIN
test two_party_signature_aggregation_basic_bls () {

  let (sk1, pk1, _pk2, _sk2,  sk3, pk3) = get_three_party_keys()

  // if each message is unique then the 'aggregate_signatures' with 'aggregate_verify'
  // is safe
  let message1 = "Hello, Aiken from party 1!"
  let message3 = "Hello, Aiken from party 3!"

  let sig1 = basic_bls.sign(sk1, message1)
  let sig3 = basic_bls.sign(sk3, message3)

  //basic checks
  let sig1_aggr = basic_bls.aggregate([sig1])
  let pk1_aggr = bls_extra_core.aggregate_publickeys([pk1])
  let pubkey1_aggr_sig1_predicate = bls_extra_core.aggregate_publickkeys_verify(pk1_aggr, [message1], sig1, api.Basic)
  let pubkey1_aggr_sig1_aggr_predicate = bls_extra_core.aggregate_publickkeys_verify(pk1_aggr, [message1], sig1_aggr, api.Basic)

  let sig13_aggr = basic_bls.aggregate([sig1, sig3])
  let pk13_aggr = bls_extra_core.aggregate_publickeys([pk1, pk3])
  let pubkey13_aggr_sig13_aggr_predicate = bls_extra_core.aggregate_publickkeys_verify(pk13_aggr, [message1, message3], sig13_aggr, api.Basic)

  pubkey1_aggr_sig1_predicate &&
  pubkey1_aggr_sig1_aggr_predicate &&
  pubkey13_aggr_sig13_aggr_predicate
}

//TO VERIFY AGAIN
test three_party_signature_aggregation_basic_bls () {

  let (sk1, pk1, sk2, pk2, sk3, pk3) = get_three_party_keys()

  // if each message is unique then the 'aggregate_signatures' with 'aggregate_verify'
  // is safe
  let message1 = "Hello, Aiken from party 1!"
  let message2 = "Hello, Aiken from party 2!"
  let message3 = "Hello, Aiken from party 3!"

  let sig1 = basic_bls.sign(sk1, message1)
  let sig2 = basic_bls.sign(sk2, message2)
  let sig3 = basic_bls.sign(sk3, message3)

  let sig_aggr = basic_bls.aggregate([sig1, sig2, sig3])

  // full signature aggregation
  let full_sig_aggr_predicate = basic_bls.aggregate_verify([pk1,pk2,pk3], [message1,message2,message3], sig_aggr)

  // partial signature aggregation
  let sig13_aggr = basic_bls.aggregate([sig1, sig3])  
  let patial_sig_agg_predicate = basic_bls.aggregate_verify([pk1,pk3], [message1,message3], sig13_aggr)

  // full both signature and public keys aggregation
  let pk_aggr = bls_extra_core.aggregate_publickeys([pk1,pk2,pk3])
  //let pubkeys_sig_aggr_predicate = aug_bls.aggregate_verify([pk_aggr, pk_aggr, pk_aggr], [message1,message2,message3], sig_aggr)
  let pubkeys_sig_aggr_predicate = bls_extra_core.aggregate_publickkeys_verify(pk_aggr, [message1,message2,message3], sig_aggr, api.Basic)

  // partial signature aggregation
  full_sig_aggr_predicate &&
  patial_sig_agg_predicate &&
  pubkeys_sig_aggr_predicate
}


test three_party_rogue_publickey_signature_aggregation_bls () {

  let (_sk1, pk1, _sk2, pk2, sk3, pk3) = get_three_party_keys()
  
  // one creates rogue_pk
  let rogue_pk3 = construct_rogue_key(pk1, pk2, pk3)

  let message = "Hello, Aiken from party!"

  // Although all parties can produce signatures
  // let _sig1 = basic_bls.sign(sk1, message)
  // let _sig2 = basic_bls.sign(sk2, message)
  let sig3 = basic_bls.sign(sk3, message)

  // only sig3 is needed to verify! sig1 and sig2 could be omitted
  let sigs_aggr_predicate = core_bls.core_aggregate_verify([pk1,pk2,rogue_pk3], [message,message,message], sig3, api.Basic)

  // basic bls impl has now detection of if not all msgs are distinct
  let sigs_aggr_predicate_fails = basic_bls.aggregate_verify([pk1,pk2,rogue_pk3], [message,message,message], sig3)

  // the same detection is present when public key aggregation is used
  let pk_aggr = bls_extra_core.aggregate_publickeys([pk1,pk2,rogue_pk3])
  let pubkeys_aggr_predicate_fails = bls_extra_core.aggregate_publickkeys_verify(pk_aggr, [message,message,message], sig3, api.Basic)

  sigs_aggr_predicate &&
  !sigs_aggr_predicate_fails &&
  !pubkeys_aggr_predicate_fails
}

fn get_three_party_keys() -> (api.PrivateKey, api.PublicKey, api.PrivateKey, api.PublicKey, api.PrivateKey, api.PublicKey) {
  // party1
  let secret1 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9a"
  let sk1 = key_gen(secret1, "")  
  let pk1 = basic_bls.sk_to_pk(sk1)

  // party2
  let secret2 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9b"
  let sk2 = key_gen(secret2, "")    
  let pk2 = basic_bls.sk_to_pk(sk2)

  // party3
  let secret3 = #"ed69a93f0cf8c9836be3b67c7eeff416612d45ba39a5c099d48fa668bf558c9c"
  let sk3 = key_gen(secret3, "")    
  let pk3 = basic_bls.sk_to_pk(sk3)

  (sk1, pk1, sk2, pk2, sk3, pk3)
}