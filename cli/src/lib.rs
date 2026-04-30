#![warn(missing_docs, rust_2018_idioms)]
//! BLS12-381 Aiken CLI tool

//! Common utilities for seed generation
pub mod common;

use blst::{blst_p1_affine, blst_p1_uncompress, blst_p2_affine, blst_p2_uncompress, BLST_ERROR};
use midnight_curves::bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};
use midnight_curves::pairing::group::prime::PrimeCurveAffine;
use midnight_curves::pairing::group::{Group, GroupEncoding};
use midnight_curves::BlsScalar;
use std::mem;

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

/// Computes BLS signature: hash message to G2, then multiply by private key scalar.
///
/// # Arguments
///
/// * `private_key` - A 32-byte private key
/// * `message` - The message to sign
/// * `dst` - Domain separation tag (optional, defaults to empty)
/// * `aug` - Augmentation data (optional, defaults to empty)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - compressed G2 signature (96 bytes)
/// * `Err(String)` if the private key is invalid
pub fn hash_to_group(
    private_key: &[u8],
    message: &[u8],
    dst: &[u8],
    aug: &[u8],
) -> Result<Vec<u8>, String> {
    let scalar = sk_to_scalar(private_key)?;

    let g2_point = G2Projective::hash_to_curve(message, dst, aug);
    let signature = g2_point * scalar;
    let signature_affine = G2Affine::from(signature);
    let compressed = signature_affine.to_bytes();

    Ok(compressed.as_ref().to_vec())
}

/// Verifies a BLS signature.
///
/// # Arguments
///
/// * `message` - The message that was signed
/// * `signature` - The signature (compressed G2 point, 96 bytes)
/// * `public_key` - The public key (compressed G1 point, 48 bytes)
/// * `dst` - Domain separation tag (optional, defaults to empty)
/// * `aug` - Augmentation data (optional, defaults to empty)
///
/// # Returns
///
/// * `Ok(bool)` - true if signature is valid, false otherwise
pub fn verify(
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
    dst: &[u8],
    aug: &[u8],
) -> Result<bool, String> {
    // (a) Check public key is not identity - decompress G1 (48 bytes compressed)
    let pk_bytes: [u8; 48] = public_key
        .try_into()
        .map_err(|_| "invalid public key length (must be 48 bytes for compressed)")?;
    let mut pk_blst = blst_p1_affine::default();
    let pk_result = unsafe { blst_p1_uncompress(&mut pk_blst, pk_bytes.as_ptr()) };
    if pk_result != BLST_ERROR::BLST_SUCCESS {
        return Err("invalid public key".to_string());
    }
    let pk_affine = unsafe { mem::transmute::<blst_p1_affine, G1Affine>(pk_blst) };
    if bool::from(pk_affine.is_identity()) {
        return Ok(false);
    }

    // (b) Check signature is not identity - decompress G2 (96 bytes compressed)
    let sig_bytes: [u8; 96] = signature
        .try_into()
        .map_err(|_| "invalid signature length (must be 96 bytes for compressed)")?;
    let mut sig_blst = blst_p2_affine::default();
    let sig_result = unsafe { blst_p2_uncompress(&mut sig_blst, sig_bytes.as_ptr()) };
    if sig_result != BLST_ERROR::BLST_SUCCESS {
        return Err("invalid signature".to_string());
    }
    let sig_affine = unsafe { mem::transmute::<blst_p2_affine, G2Affine>(sig_blst) };
    if bool::from(sig_affine.is_identity()) {
        return Ok(false);
    }

    // (c) Hash message to G2 point
    let g2_point = G2Projective::hash_to_curve(message, dst, aug);
    let g2_affine = G2Affine::from(g2_point);

    // (d) Compute pairing1 = e(public_key, hash_msg_to_point)
    let pairing1 = midnight_curves::bls12_381::pairing(&pk_affine, &g2_affine);

    // (e) Compute pairing2 = e(G1Generator, signature)
    let generator = G1Affine::from(G1Projective::generator());
    let pairing2 = midnight_curves::bls12_381::pairing(&generator, &sig_affine);

    // (f) Final verification
    Ok(pairing1 == pairing2)
}
