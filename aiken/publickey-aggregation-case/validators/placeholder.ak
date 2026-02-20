use bls/api
use bls/g1/basic as basic_bls
use bls/g1/core as core_bls
use bls/core.{key_gen}
use bls/tests/utils.{construct_rogue_key}


test three_party_unsafe_signature_aggregation_bls () {

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

  // the same vulnerability is present when public key aggregation is used
  //let pk_aggr = basic_bls.aggregate([pk1,pk2,rogue_pk3])
  //let sigs_aggr_predicate = core_bls.core_aggregate_verify(pk_aggr, [message,message,message], sig3, api.Basic)

  // basic bls impl has now detection of if not all msgs are distinct
  let sigs_aggr_predicate_fails = basic_bls.aggregate_verify([pk1,pk2,rogue_pk3], [message,message,message], sig3)

  sigs_aggr_predicate &&
  !sigs_aggr_predicate_fails
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