#![warn(missing_docs, rust_2018_idioms)]
//! BLS12-381 Aiken CLI tool

//! Common utilities for seed generation
pub mod common;

use midnight_curves::bls12_381::{G1Affine, G1Projective};
use midnight_curves::pairing::group::{Group, GroupEncoding};
use midnight_curves::BlsScalar;

/// Converts a 32-byte private key to a BLS12-381 scalar.
///
/// # Arguments
///
/// * `private_key` - A 32-byte private key
///
/// # Returns
///
/// * `Ok(BlsScalar)` if the private key is valid (32 bytes and within curve order)
/// * `Err(String)` if the private key is invalid
pub fn sk_to_scalar(private_key: &[u8]) -> Result<BlsScalar, String> {
    if private_key.len() != 32 {
        return Err(format!(
            "private key must be 32 bytes, got {}",
            private_key.len()
        ));
    }

    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(private_key);

    let scalar = BlsScalar::from_bytes_le(&bytes);

    if scalar.is_none().into() {
        return Err("private key is not a valid scalar (>= curve order)".to_string());
    }

    Ok(scalar.unwrap())
}

/// Converts a 32-byte private key to a BLS12-381 public key (G1 point).
///
/// # Arguments
///
/// * `private_key` - A 32-byte private key
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - compressed G1 public key (48 bytes)
/// * `Err(String)` if the private key is invalid
pub fn sk_to_pk(private_key: &[u8]) -> Result<Vec<u8>, String> {
    let scalar = sk_to_scalar(private_key)?;

    let generator = G1Projective::generator();
    let public_key = generator * scalar;
    let public_key_affine = G1Affine::from(public_key);
    let compressed = public_key_affine.to_bytes();

    Ok(compressed.as_ref().to_vec())
}
