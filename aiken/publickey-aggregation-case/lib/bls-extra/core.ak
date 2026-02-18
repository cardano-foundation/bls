use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_uncompress, bls12_381_g2_hash_to_group, 
  bls12_381_g2_uncompress, bls12_381_mul_miller_loop_result 
}
use aiken/crypto/bls12_381/g1
use bls/api.{Aug, Basic, BlsMode, Pop, PublicKey, Signature}
use bls/g1/constants.{signature_len}
use bls/g1/constants.{dst_aug, dst_basic, dst_pop}
use bls/pairing.{aggregate_g1, group_pairing}
use bls/utils.{foldl2}

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
/// let pk_agg = aggregate_publickeys([pk1, pk2, pk3])
/// ```
pub fn aggregate_publickeys(publickeys: List<PublicKey>) -> PublicKeyAggregated {
  aggregate_g1(publickeys)
}

/// Verify an aggregated signature over aggregated public keys and messages.
///
/// Returns `True` if the aggregated signature is valid for the provided
/// `(public_key_i, message_i)` pairs, and `False` otherwise.
///
/// ```aiken
/// aggregate_publickkeys_verify(agg_pk, [msg1, msg2], agg_sig) == True
/// ```
pub fn aggregate_publickkeys_verify(
  agg_pk: PublicKeyAggregated,
  messages: List<ByteArray>,
  signature: Signature,
  mode: BlsMode,
) -> Bool {

  expect [pk, ..xs] = [agg_pk]
  expect [msg, ..ys] = messages
  expect builtin.length_of_bytearray(signature) == constants.signature_len

  let p = bls12_381_g1_uncompress(pk)
  let q = bls12_381_g2_hash_to_group(msg, select_dst(mode))
  let ml = group_pairing(p, q)

  let c1 =
    foldl2(
      xs,
      ys,
      ml,
      fn(pk, message, miller_loop) {
        let p = bls12_381_g1_uncompress(pk)
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