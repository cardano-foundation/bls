use aiken/crypto/bls12_381/scalar.{from_bytes}
use aiken/crypto/bls12_381/g2
use bls/core.{key_gen}

pub type SecretKey =
  ByteArray

pub type PublicKey =
  ByteArray

/// Uses SecretKey to derive the VRF secret scalar x and the VRF public key Y = x*G2
/// The VRF secret scalar derivation is in the context of G1 group.
/// The public key derivation is in the context of G2 group.
///
/// The function performs two steps:
/// 1. Derives a secret scalar from the input secret using HKDF (HMAC-based Key Derivation Function)
///    following the RFC v2 specification from ilap/bls. This ensures the resulting key is uniformly
///    distributed in the scalar field and is non-zero.
/// 2. Computes the public key by scaling the G2 generator point with the secret scalar: Y = x*G2
///
/// Arguments:
/// * secret: ByteArray - input keying material (must contain sufficient entropy)
///
/// Returns:
/// (secret scalar in G1 and compressed public key in G2)
///
/// ```aiken
/// let (sk, pk) = keys_from_secret(secret)
/// ```
pub fn keys_from_secret(secret: ByteArray) -> (SecretKey, PublicKey) {
    let sk = secret_scalar(secret, "")
    let pk = g2.compress(g2.scale(g2.generator, from_bytes(sk)))
    (sk, pk)
}

/// Derives a secret scalar from input keying material using HKDF.
/// 
/// This function reuses the `key_gen` functionality from ilap/bls, which follows the
/// RFC v2 specification for BLS signature key generation. The process works as follows:
/// 
/// 1. HKDF-Extract: Combines the input keying material (IKM) with a salt "BLS-SIG-KEYGEN-SALT-"
///    and a null byte (IKM || 0x00) to produce a pseudorandom key (PRK).
/// 
/// 2. HKDF-Expand: Expands the PRK with key_info and length encoding (48 bytes for BLS12-381)
///    to produce output keying material (OKM).
/// 
/// 3. Modular reduction: Converts OKM to an integer modulo the curve order (field_prime)
///    to ensure the scalar is within the valid range [0, field_prime).
/// 
/// The resulting secret key is guaranteed to be:
/// - Uniformly distributed in the scalar field
/// - Non-zero (the probability of generating zero is negligible: ~2^-255)
/// 
/// Arguments:
/// * secret: ByteArray - input keying material (must contain sufficient entropy)
/// * key_info: ByteArray - optional context and application specific information (can be empty)
///
/// Returns:
/// Secret scalar as a 32-byte ByteArray
///
/// ```aiken
/// let sk = secret_scalar(secret, key_info)
/// ```
pub fn secret_scalar(secret: ByteArray, key_info: ByteArray) -> SecretKey {
    key_gen(secret, key_info)
}


/// Hashes a VRF input string to a point on the G2 curve.
///
/// Implements ECVRF-encode-to-curve from [IETF RFC 9380](https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html)
/// using the Simplified SWU (Shallue-Woestijne-Ulas) method.
///
/// Arguments:
/// - encode_to_curve_salt: ByteArray - public salt value (e.g., "ECVRF_")
/// - alpha_string: ByteString - value to hash to a curve point
///
/// Returns:
/// A G2Element point
///
/// ```aiken
/// let salt = "ECVRF_"
/// let input = "test input"
/// let point = encode_to_curve(salt, input)
/// ```
pub fn encode_to_curve(encode_to_curve_salt: ByteArray, alpha_string: ByteString) -> G2Element {
  g2.hash_to_group(alpha_string, encode_to_curve_salt)
}

test encode_to_curve_simple() {
  let salt = "ECVRF_"
  let alpha = "test input"
  let h = encode_to_curve(salt, alpha)
  g2.equal(h, g2.hash_to_group(alpha, salt))
}