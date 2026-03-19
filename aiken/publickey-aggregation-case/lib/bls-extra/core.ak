use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_uncompress, bls12_381_g2_hash_to_group, 
  bls12_381_g2_uncompress, bls12_381_mul_miller_loop_result 
}
use aiken/collection/list.{foldl}
use aiken/crypto/bls12_381/g1
use bls/api.{Aug, Basic, BlsMode, Pop, PublicKey, Signature}
use bls/g2/constants.{dst_aug, dst_basic, dst_pop}
use bls/pairing.{aggregate_g1, group_pairing}


pub type PublicKeyAggregated =
  ByteArray
  
/// Aggregates multiple BLS public keys into a single public key.
/// Uses the **aggregate_g1** function to iteratively uncompress and add the public keys,
/// and then compresses the resulting aggregated public key.
/// The aggregation is in the context of G1 group.
///
/// Arguments:
/// * publickeys: List<PublicKey> - A list of BLS public keys to be aggregated.
///
/// Returns:
/// PublicKey - The compressed aggregated BLS public key.
///
/// ```aiken
/// let agg_pk = aggregate_publickeys([pk1, pk2, pk3])
/// ```
pub fn aggregate_publickeys(publickeys: List<PublicKey>) -> ByteArray {
  aggregate_g1(publickeys)
}

/// Verify an aggregated signature using a pre-aggregated public key.
///
/// This verifies that the aggregate signature is valid for all messages,
/// using the pre-aggregated public key. The pk_agg is used for each message
/// in the verification, which is mathematically valid when:
/// - All signers sign all messages (not just their own), OR
/// - There's only one message
///
/// NOTE: This function only works when all signers sign the SAME message.
/// For different messages, use `aggregate_verify` with individual public keys.
/// This is a mathematical constraint of BLS signatures.
pub fn aggregate_publickey_verify(
  pk_agg: ByteArray,
  messages: List<ByteArray>,
  sig: ByteArray,
) -> Bool {
  internal_aggregate_verify_with_aggregated_pk(pk_agg, messages, sig, Basic)
}

/// Verify an aggregated signature using a pre-aggregated public key.
///
/// This verifies that the aggregate signature is valid for all messages,
/// using the pre-aggregated public key. The pk_agg is used for each message
/// in the verification (treating it as representing all signers).
///
/// Mathematically this computes:
/// Π e(pk_agg, H(msg_i)) == e(G1, sig_agg)
///
/// Note: This is mathematically equivalent to standard aggregate_verify only
/// when there's ONE message, or when all signers sign ALL messages.
fn internal_aggregate_verify_with_aggregated_pk(
  pk_agg: ByteArray,
  messages: List<ByteArray>,
  signature: ByteArray,
  mode: BlsMode,
) -> Bool {
  let p = bls12_381_g1_uncompress(pk_agg)

  expect [msg, ..msgs] = messages

  let q = bls12_381_g2_hash_to_group(msg, select_dst(mode))
  let ml = group_pairing(p, q)
  let c1 =
    foldl(
      msgs,
      ml,
      fn(message, miller_loop) {
        let q = bls12_381_g2_hash_to_group(message, select_dst(mode))
        let pq = group_pairing(p, q)
        bls12_381_mul_miller_loop_result(pq, miller_loop)
      },
    )

  let s = bls12_381_g2_uncompress(signature)
  let c2 = group_pairing(g1.generator, s)

  bls12_381_final_verify(c1, c2)
}

fn select_dst(mode: BlsMode) -> ByteArray {
  when mode is {
    Basic -> dst_basic
    Aug -> dst_aug
    Pop -> dst_pop
    }
}
