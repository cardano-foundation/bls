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


/// Supported cryptography methods for representing of secret/public keys and cryptographic correspondence between them 
pub type Cryptography {
  BLS12_381,
}

pub type PrivateKey =
  ByteArray

pub type PublicKey =
  ByteArray


pub fn to_pk(method: Cryptography, secret: ByteArray) -> PrivateKey {
    if method == BLS12_381 then
       to_pk_bls12_381(secret, 32)
}

pub fn pk_from_sk(method: Cryptography, secret: ByteArray) -> PublicKey {
    if method == BLS12_381 then
       pk_from_sk_bls12_381(secret)
}


/// Below is BLS12-381 related as G1 group prime field and its operations are used 

/// Converts an arbitrary number to the number that fits field constraints
pub fn to_pk_bls12_381(secret: ByteArray, len: int) -> PrivateKey {
  //TO DO - think about possibility of making big endian and little endian option for the user
  let sk = bytearray.to_int_big_endian(secret) % field_prime
  expect sk != 0
  integer_to_bytearray(True, len, sk)
}

/// Derive a public key from the provided secret key.
///
/// The public key is computed as scalar multiplication of the generator
/// point by the secret scalar.
///
/// ```aiken
/// let pk = pk_from_sk_bls12_381(secret)
/// ```
pub fn pk_from_sk_bls12_381(secret: PrivateKey) -> PublicKey {
  bls12_381_g1_scalar_mul(scalar_from_sk_bls12_381(secret), g1.generator)
    |> bls12_381_g1_compress
}

/// Converts a secret key (sk) from its byte representation into a scalar
/// suited for a given elliptic-curve.
///
/// The conversion is sucessful only if the resulting scalar lies in the valid range `(0, prime_order)`.
fn scalar_from_sk_bls12_381(sk: ByteArray) -> Int {
  let scalar = bytearray_to_integer(True, sk)
  expect scalar > 0 && scalar < field_prime
  scalar
}
