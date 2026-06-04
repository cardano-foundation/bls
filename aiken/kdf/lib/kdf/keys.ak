//// A key interface for deriving private and public keys across
//// supported cryptographic schemes. Currently includes BLS12-381
//// bindings built on top of the G1 prime-field.

use aiken/builtin.{
  bls12_381_g1_compress, bls12_381_g1_scalar_mul, bytearray_to_integer
}
use aiken/crypto/bls12_381/g1
use aiken/crypto/bls12_381/scalar.{prime_field}

/// Supported schemes for key derivation.
pub type KeyDerivationScheme {
  PBKDF2,
  HKDF,
}

/// Supported cryptographic curves / systems used to represent secret
/// and public keys and to define the correspondence between them.
pub type Cryptography {
  BLS12_381,
}

/// A private key is stored as raw bytes.
pub type PrivateKey =
  ByteArray

/// A public key is stored as raw bytes.
pub type PublicKey =
  ByteArray

/// Derive a private key from a raw secret using the chosen
/// cryptographic method.
///
/// The secret is reduced modulo the curve prime order and then
/// serialised back to a `ByteArray` of the requested length.
pub fn to_pk(method: Cryptography, secret: ByteArray) -> PrivateKey {
  if method == BLS12_381 {
    to_pk_bls12_381(secret, 32)
  }
}

/// Derive a public key from a private key using the chosen
/// cryptographic method.
pub fn pk_from_sk(method: Cryptography, secret: ByteArray) -> PublicKey {
  if method == BLS12_381 {
    pk_from_sk_bls12_381(secret)
  }
}

/// --- BLS12-381 helpers ---
///
/// The functions below operate over the BLS12-381 G1 prime field.

/// Convert an arbitrary byte sequence into a valid BLS12-381 private
/// key that lies inside the prime field.
///
/// The secret is interpreted as a big-endian integer, reduced modulo
/// `field_prime`, and then padded / truncated to `len` bytes.
pub fn to_pk_bls12_381(secret: ByteArray, len: int) -> PrivateKey {
  //TO DO - think about possibility of making big endian and little endian option for the user
  let sk = bytearray.to_int_big_endian(secret) % field_prime
  expect sk != 0
  integer_to_bytearray(True, len, sk)
}

/// Derive a BLS12-381 public key from the provided secret key.
///
/// The public key is computed as the scalar multiplication of the
/// generator point by the secret scalar, then compressed to its
/// byte representation.
///
/// ```aiken
/// let pk = pk_from_sk_bls12_381(secret)
/// ```
pub fn pk_from_sk_bls12_381(secret: PrivateKey) -> PublicKey {
  bls12_381_g1_scalar_mul(scalar_from_sk_bls12_381(secret), g1.generator)
    |> bls12_381_g1_compress
}

/// Convert a secret key from its byte representation into a scalar
/// suitable for the BLS12-381 curve.
///
/// The conversion succeeds only when the scalar lies in the valid
/// range `(0, prime_order)`.
fn scalar_from_sk_bls12_381(sk: ByteArray) -> Int {
  let scalar = bytearray_to_integer(True, sk)
  expect scalar > 0 && scalar < field_prime
  scalar
}
