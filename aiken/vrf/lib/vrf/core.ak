use aiken/builtin.{
  bls12_381_final_verify, bls12_381_g1_uncompress, bls12_381_g2_hash_to_group, 
  bls12_381_g2_uncompress, bls12_381_mul_miller_loop_result 
}
use aiken/collection/list.{foldl}
use aiken/crypto/bls12_381/g1
use bls/core.{key_gen}

pub type SecretKey =
  ByteArray

pub type PublicKey =
  ByteArray

/// Uses SecretKey to derive the VRF secret scalar x and the VRF public key Y = x*G2
/// The VRF secret scalar derivation is in the context of G1 group.
/// The public key derivation is in the context of G2 group.
///
/// Arguments:
/// * secret: ByteArray .
///
/// Returns:
/// (secret scalar in G1 and public key in G2)
///
/// ```aiken
/// let (sk, pk) = keys_from_secret(secret)
/// ```
pub fn keys_from_secret(secret: byteArray) -> (SecretKey, PublicKey) {
    let sk = secret_scalar(secret)
    undefined
}

/// Reuses functionality from ilap/bls 
/// The VRF secret scalar derivation is in the context of G1 group.
///
/// Arguments:
/// * secret: ByteArray .
///
/// Returns:
/// Secret scalar in G1
///
/// ```aiken
/// let sk = secret_scalar(secret)
/// ```
pub fn secret_scalar(secret: ByteArray) -> SecretKey {
    key_gen(secret)
}
