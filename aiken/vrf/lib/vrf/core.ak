use aiken/builtin
use aiken/crypto.{sha2_256}
use aiken/crypto/bls12_381/scalar.{from_bytes, add, mul, to_bytes, to_int}
use aiken/crypto/bls12_381/g2
use aiken/crypto/bitwise
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
/// - secret: SecretKey - input keying material (must contain sufficient entropy)
///
/// Returns:
/// (secret scalar in G1 and compressed public key in G2)
///
/// ```aiken
/// let (sk, pk) = keys_from_secret(secret)
/// ```
pub fn keys_from_secret(secret: SecretKey) -> (SecretKey, PublicKey) {
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
/// - secret: SecretKey - input keying material (must contain sufficient entropy)
/// - key_info: ByteArray - optional context and application specific information (can be empty)
///
/// Returns:
/// Secret scalar as a 32-byte ByteArray
///
/// ```aiken
/// let sk = secret_scalar(secret, key_info)
/// ```
pub fn secret_scalar(secret: SecretKey, key_info: ByteArray) -> SecretKey {
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

/// Converts a G2 point to a compressed byte string.
///
/// Implements point_to_string from [IETF RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html)
/// using the compressed encoding from [RFC 9380](https://www.ietf.org/archive/id/draft-irtf-cfrg-hash-to-curve-13.html).
///
/// Arguments:
/// - point: G2Element - a point on the G2 curve
///
/// Returns:
/// A ByteArray with the compressed representation (96 bytes)
///
/// ```aiken
/// let point = g2.generator
/// let encoded = point_to_string(point)
/// ```
pub fn point_to_string(point: G2Element) -> ByteArray {
  g2.compress(point)
}

test point_to_string_1() {
  let h = g2.hash_to_group("test", "salt")
  point_to_string(h) == g2.compress(h)
}

test point_to_string_2() {
  let point = g2.generator
  let compressed = point_to_string(point)
  compressed == #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
}

/// Generates the nonce value k in a deterministic pseudorandom fashion.
///
/// Implements ECVRF_nonce_generation from [IETF RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html) Section 5.4.2.2
/// (derived from RFC 8032 Section 5.1.6):
///
///   1. hashed_sk_string = Hash(SK)
///   2. truncated_hashed_sk_string = hashed_sk_string[32]...hashed_sk_string[63]
///   3. k_string = Hash(truncated_hashed_sk_string || h_string)
///   4. k = string_to_int(k_string) mod q
///
/// Arguments:
/// - secret_key: SecretKey - the VRF secret key (32-byte ByteArray)
/// - h_string: ByteString - the hash string (output of point_to_string(H))
///
/// Returns:
/// A nonce scalar k as a ByteArray (32 bytes, between 1 and q-1)
///
/// ```aiken
/// let (sk, pk) = keys_from_secret(secret)
/// let h = encode_to_curve("ECVRF_", alpha)
/// let h_string = point_to_string(h)
/// let k = nonce_generation(sk, h_string)
/// ```
pub fn nonce_generation(secret_key: SecretKey, h_string: ByteString) -> SecretKey {
  let hashed_sk_string = sha2_256(secret_key)
  let truncated = builtin.slice_bytearray(32, 32, hashed_sk_string)
  let k_string = sha2_256(builtin.append_bytearray(truncated, h_string))
  from_bytes(k_string)
}

test nonce_generation_1() {
  let sk = #"0000000000000000000000000000000000000000000000000000000000000001"
  let h_string = #"9332903123123123123123123123123123123123123123123123123123123123"
  let k = nonce_generation(sk, h_string)
  k != sk
}

/// Generates a challenge value from five G2 points.
///
/// Implements ECVRF_challenge_generation from [IETF RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html) Section 5.4.3:
///
///   1. challenge_generation_domain_separator_front = 0x02
///   2. Initialize str = suite_string || challenge_generation_domain_separator_front
///   3. For PJ in [P1, P2, P3, P4, P5]:
///      str = str || point_to_string(PJ)
///   4. challenge_generation_domain_separator_back = 0x00
///   5. str = str || challenge_generation_domain_separator_back
///   6. c_string = Hash(str)
///   7. truncated_c_string = c_string[0]...c_string[cLen-1]
///   8. c = string_to_int(truncated_c_string)
///   9. Output c
///
/// Arguments:
/// - Y: G2Element - public key (Y = x * G2)
/// - H: G2Element - encoded hash point (H = encode_to_curve(salt, alpha))
/// - Gamma: G2Element - Gamma = k * H
/// - U: G2Element - U = k * G2 (nonce times generator)
/// - V: G2Element - V = k * H (nonce times hash point)
///
/// Returns:
/// c: challenge value as a ByteArray (16 bytes, between 0 and 2^(8*cLen)-1, with cLen = 16)
///
/// ```aiken
/// let (sk, pk) = keys_from_secret(secret)
/// let h = encode_to_curve("ECVRF_", alpha)
/// let gamma = g2.scale(h, k)
/// let u = g2.scale(g2.generator, k)
/// let v = g2.scale(h, k)
/// let c = challenge_generation(pk, h, gamma, u, v)
/// ```
pub fn challenge_generation(
  Y: G2Element,
  H: G2Element,
  Gamma: G2Element,
  U: G2Element,
  V: G2Element,
) -> ByteArray {
  let challenge_generation_domain_separator_front = #"02"
  let suite_string = #"00"
  let str = builtin.append_bytearray(suite_string, challenge_generation_domain_separator_front)
  let str = builtin.append_bytearray(str, point_to_string(Y))
  let str = builtin.append_bytearray(str, point_to_string(H))
  let str = builtin.append_bytearray(str, point_to_string(Gamma))
  let str = builtin.append_bytearray(str, point_to_string(U))
  let str = builtin.append_bytearray(str, point_to_string(V))
  let challenge_generation_domain_separator_back = #"00"
  let str = builtin.append_bytearray(str, challenge_generation_domain_separator_back)
  let c_string = sha2_256(str)
  builtin.slice_bytearray(0, 16, c_string)
}

test challenge_generation_1() {
  let Y = g2.generator
  let H = g2.hash_to_group("test", "salt")
  let Gamma = g2.generator
  let U = g2.generator
  let V = g2.generator
  let c = challenge_generation(Y, H, Gamma, U, V)
  builtin.bytearray_to_integer(True, c) < bitwise.shift_left(2, 128)
}

/// Generates a VRF proof for a given input.
///
/// Implements ECVRF_prove from [IETF RFC 9381](https://www.rfc-editor.org/rfc/rfc9381.html) Section 5.1:
///
///   1. Use SK to derive the VRF secret scalar x and the VRF public key Y = x*G2
///   2. H = ECVRF_encode_to_curve(encode_to_curve_salt, alpha_string)
///   3. h_string = point_to_string(H)
///   4. Gamma = x*H
///   5. k = ECVRF_nonce_generation(SK, h_string)
///   6. c = ECVRF_challenge_generation(Y, H, Gamma, k*G2, k*H)
///   7. s = (k + c*x) mod q
///   8. pi_string = point_to_string(Gamma) || int_to_string(c, cLen) || int_to_string(s, qLen)
///
/// Arguments:
/// - secret: SecretKey - VRF secret key (32-byte ByteArray)
/// - alpha_string: ByteString - input alpha, an octet string
/// - encode_to_curve_salt: ByteArray - a public salt value (e.g., "ECVRF_")
///
/// Returns:
/// pi_string: ByteArray - VRF proof (ptLen + cLen + qLen = 96 + 16 + 32 = 144 bytes)
///
/// ```aiken
/// let (sk, pk) = keys_from_secret(secret)
/// let alpha = "test input"
/// let salt = "ECVRF_"
/// let proof = prove(sk, alpha, salt)
/// ```
pub fn prove(secret: SecretKey, alpha_string: ByteString, encode_to_curve_salt: ByteArray) -> ByteArray {
  let x = from_bytes(secret)
  let Y = g2.scale(g2.generator, x)

  let H = encode_to_curve(encode_to_curve_salt, alpha_string)
  let h_string = point_to_string(H)

  let Gamma = g2.scale(H, x)

  let k = nonce_generation(secret, h_string)

  let kG2 = g2.scale(g2.generator, to_int(k))
  let kH = g2.scale(H, to_int(k))
  let c_bytes = challenge_generation(Y, H, Gamma, kG2, kH)
  let c = from_bytes(c_bytes)

  let s = add(mul(c, x), k)

  let gamma_string = point_to_string(Gamma)
  let c_string = builtin.integer_to_bytearray(True, 16, to_int(c))
  let s_string = to_bytes(s)

  builtin.append_bytearray(builtin.append_bytearray(gamma_string, c_string), s_string)
}

test prove_1() {
  let sk = secret_scalar(#"test_secret_key_123456", "")
  let alpha = "test input"
  let salt = "ECVRF_"
  let proof = prove(sk, alpha, salt)
  builtin.length_of_bytearray(proof) == 144
}