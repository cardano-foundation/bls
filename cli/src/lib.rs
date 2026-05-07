#![warn(missing_docs, rust_2018_idioms)]
//! BLS12-381 Aiken CLI tool

//! Common utilities for seed generation
pub mod common;

use blst::{
    blst_p1_affine, blst_p1_deserialize, blst_p1_uncompress, blst_p2_affine, blst_p2_deserialize,
    blst_p2_uncompress, BLST_ERROR,
};
use midnight_curves::bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};
use midnight_curves::pairing::group::prime::PrimeCurveAffine;
use midnight_curves::pairing::group::{Group, GroupEncoding};
use midnight_curves::serde_traits::SerdeObject;
use midnight_curves::BlsScalar;
use midnight_curves::CurveAffine;
use std::mem;
use std::ops::Add;
use std::ops::Mul;

/// Group selection for scalar multiplication
pub enum CurveGroup {
    /// G1 group (48-byte compressed points)
    G1,
    /// G2 group (96-byte compressed points)
    G2,
}

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

/// Performs scalar multiplication on a BLS12-381 G1 or G2 point.
///
/// # Arguments
///
/// * `group` - The group to operate on (G1 or G2)
/// * `point` - The compressed point bytes (48 for G1, 96 for G2)
/// * `scalar` - The 32-byte scalar value
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The compressed result point (48 for G1, 96 for G2)
/// * `Err(String)` if the point or scalar is invalid
pub fn scalar_mul(group: &CurveGroup, point: &[u8], scalar: &[u8]) -> Result<Vec<u8>, String> {
    let scalar = sk_to_scalar(scalar)?;

    match group {
        CurveGroup::G1 => {
            let bytes: [u8; 48] = point
                .try_into()
                .map_err(|_| "invalid point length (must be 48 bytes for G1)")?;
            let g1_affine = decompress_g1(&bytes)?;
            let g1_projective = G1Projective::from(g1_affine);
            let result = g1_projective.mul(&scalar);
            let result_affine = G1Affine::from(result);
            Ok(result_affine.to_bytes().as_ref().to_vec())
        }
        CurveGroup::G2 => {
            let bytes: [u8; 96] = point
                .try_into()
                .map_err(|_| "invalid point length (must be 96 bytes for G2)")?;
            let g2_affine = decompress_g2(&bytes)?;
            let g2_projective = G2Projective::from(g2_affine);
            let result = g2_projective.mul(&scalar);
            let result_affine = G2Affine::from(result);
            Ok(result_affine.to_bytes().as_ref().to_vec())
        }
    }
}

/// Checks if compressed bytes represent the identity element.
fn is_compressed_identity(bytes: &[u8]) -> bool {
    bytes.len() > 0 && bytes[0] == 0xc0 && bytes[1..].iter().all(|&b| b == 0)
}

/// Decompresses a G1 point, handling identity as a special case since
/// blst's `blst_p1_uncompress` does not accept the identity encoding.
fn decompress_g1(bytes: &[u8; 48]) -> Result<G1Affine, String> {
    if is_compressed_identity(bytes) {
        return Ok(G1Affine::identity());
    }
    let mut blst = blst_p1_affine::default();
    let result = unsafe { blst_p1_uncompress(&mut blst, bytes.as_ptr()) };
    if result != BLST_ERROR::BLST_SUCCESS {
        return Err("invalid G1 compressed point".to_string());
    }
    Ok(unsafe { mem::transmute::<blst_p1_affine, G1Affine>(blst) })
}

/// Decompresses a G2 point, handling identity as a special case since
/// blst's `blst_p2_uncompress` does not accept the identity encoding.
fn decompress_g2(bytes: &[u8; 96]) -> Result<G2Affine, String> {
    if is_compressed_identity(bytes) {
        return Ok(G2Affine::identity());
    }
    let mut blst = blst_p2_affine::default();
    let result = unsafe { blst_p2_uncompress(&mut blst, bytes.as_ptr()) };
    if result != BLST_ERROR::BLST_SUCCESS {
        return Err("invalid G2 compressed point".to_string());
    }
    Ok(unsafe { mem::transmute::<blst_p2_affine, G2Affine>(blst) })
}

/// Adds two BLS12-381 G1 or G2 points.
///
/// # Arguments
///
/// * `group` - The group to operate on (G1 or G2)
/// * `left` - The left compressed point bytes (48 for G1, 96 for G2)
/// * `right` - The right compressed point bytes (48 for G1, 96 for G2)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The compressed result point (48 for G1, 96 for G2)
/// * `Err(String)` if either point is invalid
pub fn group_add(group: &CurveGroup, left: &[u8], right: &[u8]) -> Result<Vec<u8>, String> {
    match group {
        CurveGroup::G1 => {
            let left_bytes: [u8; 48] = left
                .try_into()
                .map_err(|_| "invalid left point length (must be 48 bytes for G1)")?;
            let right_bytes: [u8; 48] = right
                .try_into()
                .map_err(|_| "invalid right point length (must be 48 bytes for G1)")?;

            let left_affine = decompress_g1(&left_bytes)?;
            let right_affine = decompress_g1(&right_bytes)?;

            let left_projective = G1Projective::from(left_affine);
            let right_projective = G1Projective::from(right_affine);
            let result = left_projective.add(&right_projective);
            let result_affine = G1Affine::from(result);
            Ok(result_affine.to_bytes().as_ref().to_vec())
        }
        CurveGroup::G2 => {
            let left_bytes: [u8; 96] = left
                .try_into()
                .map_err(|_| "invalid left point length (must be 96 bytes for G2)")?;
            let right_bytes: [u8; 96] = right
                .try_into()
                .map_err(|_| "invalid right point length (must be 96 bytes for G2)")?;

            let left_affine = decompress_g2(&left_bytes)?;
            let right_affine = decompress_g2(&right_bytes)?;

            let left_projective = G2Projective::from(left_affine);
            let right_projective = G2Projective::from(right_affine);
            let result = left_projective.add(&right_projective);
            let result_affine = G2Affine::from(result);
            Ok(result_affine.to_bytes().as_ref().to_vec())
        }
    }
}

/// Compresses a BLS12-381 G1 or G2 point.
///
/// Accepts both compressed (48/96 bytes) and uncompressed (96/192 bytes) input.
/// Identity encoded as `c0` + zeros is handled specially. The output is always
/// the compressed form.
///
/// # Arguments
///
/// * `group` - The group to operate on (G1 or G2)
/// * `point` - The point bytes (compressed or uncompressed)
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The compressed point bytes (48 for G1, 96 for G2)
/// * `Err(String)` if the point is invalid
pub fn compress_point(group: &CurveGroup, point: &[u8]) -> Result<Vec<u8>, String> {
    match group {
        CurveGroup::G1 => compress_g1(point),
        CurveGroup::G2 => compress_g2(point),
    }
}

fn compress_g1(point: &[u8]) -> Result<Vec<u8>, String> {
    match point.len() {
        48 => {
            if is_compressed_identity(point) {
                return Ok(point.to_vec());
            }
            let bytes: [u8; 48] = point
                .try_into()
                .map_err(|_| "invalid G1 compressed point length")?;
            let affine = decompress_g1(&bytes)?;
            Ok(affine.to_bytes().as_ref().to_vec())
        }
        96 => {
            let mut raw = blst_p1_affine::default();
            let result = unsafe { blst_p1_deserialize(&mut raw, point.as_ptr()) };
            if result != BLST_ERROR::BLST_SUCCESS {
                return Err("invalid G1 uncompressed point".to_string());
            }
            let affine: G1Affine = unsafe { mem::transmute(raw) };
            if !bool::from(affine.is_on_curve()) {
                return Err("G1 point is not on the curve".to_string());
            }
            if affine.is_identity().into() {
                let mut identity = vec![0xc0u8];
                identity.extend(std::iter::repeat(0u8).take(47));
                return Ok(identity);
            }
            Ok(affine.to_bytes().as_ref().to_vec())
        }
        _ => Err("invalid G1 point length (expected 48 or 96 bytes)".to_string()),
    }
}

fn compress_g2(point: &[u8]) -> Result<Vec<u8>, String> {
    match point.len() {
        96 => {
            if is_compressed_identity(point) {
                return Ok(point.to_vec());
            }
            let bytes: [u8; 96] = point
                .try_into()
                .map_err(|_| "invalid G2 compressed point length")?;
            let affine = decompress_g2(&bytes)?;
            Ok(affine.to_bytes().as_ref().to_vec())
        }
        192 => {
            let mut raw = blst_p2_affine::default();
            let result = unsafe { blst_p2_deserialize(&mut raw, point.as_ptr()) };
            if result != BLST_ERROR::BLST_SUCCESS {
                return Err("invalid G2 uncompressed point".to_string());
            }
            let affine: G2Affine = unsafe { mem::transmute(raw) };
            if !bool::from(affine.is_on_curve()) {
                return Err("G2 point is not on the curve".to_string());
            }
            if affine.is_identity().into() {
                let mut identity = vec![0xc0u8];
                identity.extend(std::iter::repeat(0u8).take(95));
                return Ok(identity);
            }
            Ok(affine.to_bytes().as_ref().to_vec())
        }
        _ => Err("invalid G2 point length (expected 96 or 192 bytes)".to_string()),
    }
}

/// Uncompresses (decompresses) a BLS12-381 G1 or G2 point.
///
/// Takes a compressed point (48 bytes for G1, 96 bytes for G2) or identity
/// and returns the uncompressed form (96 bytes for G1, 192 bytes for G2).
///
/// # Arguments
///
/// * `group` - The group to operate on (G1 or G2)
/// * `point` - The compressed point bytes
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - The uncompressed point bytes (96 for G1, 192 for G2)
/// * `Err(String)` if the point is invalid
pub fn uncompress_point(group: &CurveGroup, point: &[u8]) -> Result<Vec<u8>, String> {
    match group {
        CurveGroup::G1 => {
            if is_compressed_identity(point) {
                return Ok(vec![0u8; 96]);
            }
            let bytes: [u8; 48] = point
                .try_into()
                .map_err(|_| "invalid G1 point length (must be 48 bytes)")?;
            let affine = decompress_g1(&bytes)?;
            Ok(affine.to_raw_bytes())
        }
        CurveGroup::G2 => {
            if is_compressed_identity(point) {
                return Ok(vec![0u8; 192]);
            }
            let bytes: [u8; 96] = point
                .try_into()
                .map_err(|_| "invalid G2 point length (must be 96 bytes)")?;
            let affine = decompress_g2(&bytes)?;
            Ok(affine.to_raw_bytes())
        }
    }
}
