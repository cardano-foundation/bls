//// A key interface for deriving private and public keys across
//// supported cryptographic schemes. Currently includes BLS12-381
//// bindings built on top of the G1 prime-field.

use aiken/builtin.{
  bls12_381_g1_compress, bls12_381_g1_scalar_mul, bytearray_to_integer
}
use aiken/crypto/bls12_381/g1
use aiken/crypto/bls12_381/scalar.{prime_field}
use kdf/hkdf/hkdf
use kdf/pbkdf2/pbkdf2
use kdf/kdf.{HashAlgo}

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

/// Generate a private / public key pair using the selected KDF scheme
/// and elliptic-curve system.
///
/// # Parameters
///
/// - `scheme`       – key derivation scheme (`PBKDF2` or `HKDF`)
/// - `cryptography` – target curve (`BLS12_381`)
/// - `algo`         – hash algorithm (e.g. `Sha256`, `Blake2b_256`)
/// - `salt`         – salt byte array (used by both schemes)
/// - `ikm`          – input keying material / password (used by both schemes)
/// - `count`        – iteration count, **used only for PBKDF2**
/// - `info`         – context info, **used only for HKDF**
/// - `length`       – desired length of the derived secret in bytes
///
/// Returns a tuple `(PrivateKey, PublicKey)`.
pub fn gen_keys(
  scheme: KeyDerivationScheme,
  cryptography: Cryptography,
  algo: HashAlgo,
  salt: ByteArray,
  ikm: ByteArray,
  count: Int,
  info: ByteArray,
  length: Int,
) -> (PrivateKey, PublicKey) {
  if cryptography == BLS12_381 {
    gen_keys_bls12_381(scheme, algo, salt, ikm, count, info, length)
  }
}

/// BLS12-381 specific key-pair generation.
///
/// Runs the chosen KDF (`PBKDF2` or `HKDF`) and then converts the
/// derived material into a BLS12-381 private key (reduced modulo the
/// prime field) and the corresponding compressed public key.
///
/// # Parameters
///
/// - `scheme` – key derivation scheme
/// - `algo`   – hash algorithm
/// - `salt`   – salt
/// - `ikm`    – input keying material / password
/// - `count`  – iteration count (PBKDF2 only)
/// - `info`   – context info (HKDF only)
/// - `length` – KDF output length in bytes
///
/// Returns a tuple `(PrivateKey, PublicKey)`.
pub fn gen_keys_bls12_381(
  scheme: KeyDerivationScheme,
  algo: HashAlgo,
  salt: ByteArray,
  ikm: ByteArray,
  count: Int,
  info: ByteArray,
  length: Int,
) -> (PrivateKey, PublicKey) {
  let secret = when scheme is {
    PBKDF2 -> pbkdf2.kdf(algo, ikm, salt, count, length)
    HKDF -> hkdf.kdf(algo, salt, ikm, info, length)
  }
  let sk = to_pk_bls12_381(secret, 32)
  let pk = pk_from_sk_bls12_381(sk)
  (sk, pk)
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
