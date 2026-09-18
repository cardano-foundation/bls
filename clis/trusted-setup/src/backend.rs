//! Native-backend bridge: arkworks types in, ABI bytes out, cross-validated.
//!
//! This module is the Rust half of the C++ FFI story (C++ half: `native/`).
//! It converts between arkworks' `Fr`/`G1Affine`/`G2Affine` and the plain-byte
//! encodings in [`crate::bls_ffi`], and exposes the primitives the prover /
//! verifier will call once backend selection is wired into them:
//!
//!   - [`native_msm_g1`] / [`native_msm_g2`] — Pippenger MSM via blst
//!   - [`native_pairing_batch_check`] — multi-pairing product check via blst
//!   - [`native_ntt`] — radix-2 NTT (landing with the NTT milestone)
//!
//! Encoding reference (`native/include/bls_backend.h`):
//!   - Fr    : 32-byte little-endian canonical scalar
//!   - G1    : x (48B BE) || y (48B BE)
//!   - G2    : x.c1 || x.c0 || y.c1 || y.c0 (48B BE each)
//!   - infinity is all-zero bytes
#![allow(dead_code)] // wired into the prover/verifier in the backend-selection milestone

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::{BigInt, BigInteger, PrimeField};

use crate::bls_ffi::{self, BackendError, BlsFr, BlsG1, BlsG2, BlsStatus};

fn err(status: BlsStatus) -> BackendError {
    BackendError {
        status,
        message: status.as_str(),
    }
}

// ---------------------------------------------------------------- encoding --

fn fr_to_bls(fr: &Fr) -> BlsFr {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&fr.into_bigint().to_bytes_le());
    BlsFr(bytes)
}

fn fr_from_bls(bls: &BlsFr) -> Result<Fr, BackendError> {
    let bigint = bigint_from_le::<4>(&bls.0);
    Fr::from_bigint(bigint).ok_or_else(|| err(BlsStatus::InvalidArgument))
}

fn fp_to_48_bytes(fp: &ark_bls12_381::Fq) -> [u8; 48] {
    let mut bytes = [0u8; 48];
    bytes.copy_from_slice(&fp.into_bigint().to_bytes_be());
    bytes
}

fn fp_from_bytes(bytes: &[u8]) -> Result<ark_bls12_381::Fq, BackendError> {
    <ark_bls12_381::Fq as PrimeField>::from_bigint(bigint_from_be::<6>(bytes))
        .ok_or_else(|| err(BlsStatus::PointNotOnCurve))
}

fn bigint_from_le<const N: usize>(bytes: &[u8]) -> BigInt<N> {
    let mut limbs = [0u64; N];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = i * 8;
        let mut chunk = [0u8; 8];
        if start + 8 <= bytes.len() {
            chunk.copy_from_slice(&bytes[start..start + 8]);
        } else {
            chunk[..bytes.len() - start].copy_from_slice(&bytes[start..]);
        }
        *limb = u64::from_le_bytes(chunk);
    }
    BigInt::new(limbs)
}

fn bigint_from_be<const N: usize>(bytes: &[u8]) -> BigInt<N> {
    let mut limbs = [0u64; N];
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(chunk);
        limbs[N - 1 - i] = u64::from_be_bytes(arr);
    }
    BigInt::new(limbs)
}

fn g1_to_bytes(p: &G1Affine) -> BlsG1 {
    if p.is_zero() {
        return BlsG1([0u8; 96]);
    }
    let mut buf = [0u8; 96];
    buf[..48].copy_from_slice(&fp_to_48_bytes(&p.x));
    buf[48..].copy_from_slice(&fp_to_48_bytes(&p.y));
    BlsG1(buf)
}

fn g1_from_bytes(bytes: &BlsG1) -> Result<G1Affine, BackendError> {
    if bytes.0.iter().all(|&b| b == 0) {
        return Ok(G1Affine::identity());
    }
    let x = fp_from_bytes(&bytes.0[..48])?;
    let y = fp_from_bytes(&bytes.0[48..])?;
    let p = G1Affine::new_unchecked(x, y);
    debug_assert!(p.is_on_curve(), "native backend produced an off-curve G1 point");
    Ok(p)
}

fn g2_to_bytes(p: &G2Affine) -> BlsG2 {
    if p.is_zero() {
        return BlsG2([0u8; 192]);
    }
    let mut buf = [0u8; 192];
    buf[..48].copy_from_slice(&fp_to_48_bytes(&p.x.c1));
    buf[48..96].copy_from_slice(&fp_to_48_bytes(&p.x.c0));
    buf[96..144].copy_from_slice(&fp_to_48_bytes(&p.y.c1));
    buf[144..].copy_from_slice(&fp_to_48_bytes(&p.y.c0));
    BlsG2(buf)
}

fn g2_from_bytes(bytes: &BlsG2) -> Result<G2Affine, BackendError> {
    if bytes.0.iter().all(|&b| b == 0) {
        return Ok(G2Affine::identity());
    }
    let x_c1 = fp_from_bytes(&bytes.0[..48])?;
    let x_c0 = fp_from_bytes(&bytes.0[48..96])?;
    let y_c1 = fp_from_bytes(&bytes.0[96..144])?;
    let y_c0 = fp_from_bytes(&bytes.0[144..])?;
    let x = ark_bls12_381::Fq2::new(x_c0, x_c1);
    let y = ark_bls12_381::Fq2::new(y_c0, y_c1);
    let p = G2Affine::new_unchecked(x, y);
    debug_assert!(p.is_on_curve(), "native backend produced an off-curve G2 point");
    Ok(p)
}

// ---------------------------------------------------------------- wrappers --

/// Pippenger MSM on G1 via the native backend.
pub fn native_msm_g1(
    bases: &[G1Affine],
    scalars: &[Fr],
) -> Result<G1Affine, BackendError> {
    let bls_bases: Vec<BlsG1> = bases.iter().map(g1_to_bytes).collect();
    let bls_scalars: Vec<BlsFr> = scalars.iter().map(fr_to_bls).collect();
    let out = bls_ffi::msm_g1(&bls_bases, &bls_scalars)?;
    g1_from_bytes(&out)
}

/// Pippenger MSM on G2 via the native backend.
pub fn native_msm_g2(
    bases: &[G2Affine],
    scalars: &[Fr],
) -> Result<G2Affine, BackendError> {
    let bls_bases: Vec<BlsG2> = bases.iter().map(g2_to_bytes).collect();
    let bls_scalars: Vec<BlsFr> = scalars.iter().map(fr_to_bls).collect();
    let out = bls_ffi::msm_g2(&bls_bases, &bls_scalars)?;
    g2_from_bytes(&out)
}

/// Multi-pairing product check via the native backend:
/// `Ok(true)` when `prod_i e(g2_i, g1_i)` is the identity.
pub fn native_pairing_batch_check(
    g1: &[G1Affine],
    g2: &[G2Affine],
) -> Result<bool, BackendError> {
    let bls_g1: Vec<BlsG1> = g1.iter().map(g1_to_bytes).collect();
    let bls_g2: Vec<BlsG2> = g2.iter().map(g2_to_bytes).collect();
    bls_ffi::pairing_batch(&bls_g1, &bls_g2)
}

/// Radix-2 NTT via the native backend (implemented in the NTT milestone).
pub(crate) fn native_ntt(_values: &mut [Fr], _inverse: bool) -> Result<(), BackendError> {
    Err(err(BlsStatus::InternalError))
}

pub fn native_version() -> u32 {
    bls_ffi::version()
}

pub fn native_flavor() -> String {
    bls_ffi::flavor()
}

#[cfg(test)]
mod tests {
    use super::*;

    use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
    use ark_ec::{
        pairing::{prepare_g1, prepare_g2, Pairing},
        AffineRepr, CurveGroup, VariableBaseMSM,
    };
    use ark_ff::{Field, One, UniformRand, Zero};
    use rand::thread_rng;

    #[test]
    fn version_and_flavor_sanity() {
        assert!(native_version() >= 1, "native version must be bumped monotonically");
        assert!(
            native_flavor().contains("blst"),
            "flavor should advertise blst, got: {}",
            native_flavor()
        );
    }

    #[test]
    fn scalar_byte_order_roundtrip() {
        let mut rng = thread_rng();
        for _ in 0..64 {
            let fr = Fr::rand(&mut rng);
            let bytes = fr_to_bls(&fr);
            let back = fr_from_bls(&bytes).unwrap();
            assert_eq!(fr, back, "Fr byte round-trip broke the value");
        }
        assert_eq!(
            fr_to_bls(&Fr::one()).0,
            {
                let mut b = [0u8; 32];
                b[0] = 1;
                b
            },
            "Fr::one must be the little-endian byte 0x01 first"
        );
    }

    #[test]
    fn point_byte_order_g1() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let p = G1Projective::rand(&mut rng).into_affine();
            let bytes = g1_to_bytes(&p);
            let back = g1_from_bytes(&bytes).unwrap();
            assert_eq!(p, back, "G1 byte round-trip broke the point");
            assert!(p.is_on_curve());
        }
        let ident = G1Affine::identity();
        assert!(g1_from_bytes(&g1_to_bytes(&ident)).unwrap().is_zero());
    }

    #[test]
    fn point_byte_order_g2() {
        let mut rng = thread_rng();
        for _ in 0..16 {
            let p = G2Projective::rand(&mut rng).into_affine();
            let bytes = g2_to_bytes(&p);
            let back = g2_from_bytes(&bytes).unwrap();
            assert_eq!(p, back, "G2 byte round-trip broke the point");
            assert!(p.is_on_curve());
        }
        let ident = G2Affine::identity();
        assert!(g2_from_bytes(&g2_to_bytes(&ident)).unwrap().is_zero());
    }

    #[test]
    fn g1_msm_cross_validates_against_arkworks() {
        let mut rng = thread_rng();
        for n in [1, 2, 4, 64, 256] {
            let bases: Vec<G1Affine> = (0..n)
                .map(|_| G1Projective::rand(&mut rng).into_affine())
                .collect();
            let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let expected: G1Affine =
                G1Projective::msm_unchecked(&bases, &scalars).into_affine();
            let got = native_msm_g1(&bases, &scalars).unwrap();
            assert_eq!(
                expected, got,
                "G1 MSM disagrees with arkworks for n={n}"
            );
        }
    }

    #[test]
    fn g2_msm_cross_validates_against_arkworks() {
        let mut rng = thread_rng();
        for n in [1, 2, 4, 32, 128] {
            let bases: Vec<G2Affine> = (0..n)
                .map(|_| G2Projective::rand(&mut rng).into_affine())
                .collect();
            let scalars: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
            let expected: G2Affine =
                G2Projective::msm_unchecked(&bases, &scalars).into_affine();
            let got = native_msm_g2(&bases, &scalars).unwrap();
            assert_eq!(
                expected, got,
                "G2 MSM disagrees with arkworks for n={n}"
            );
        }
    }

    #[test]
    fn g1_msm_handles_infinity_base() {
        let mut rng = thread_rng();
        let ident = G1Affine::identity();
        let p = G1Projective::rand(&mut rng).into_affine();
        let one = Fr::one();
        let two = Fr::one().double();

        let got = native_msm_g1(&[ident, p, ident], &[one, two, one]).unwrap();
        let expected = (G1Projective::from(p) * two).into_affine();
        assert_eq!(got, expected);
    }

    #[test]
    fn pairing_batch_cross_validates_against_arkworks() {
        let mut rng = thread_rng();

        // e(P,Q) * e(-P,Q) must be the identity
        for _ in 0..2 {
            let p = G1Projective::rand(&mut rng).into_affine();
            let q = G2Projective::rand(&mut rng).into_affine();
            let neg_p = (-G1Projective::from(p)).into_affine();

            let g1 = [p, neg_p];
            let g2 = [q, q];

            let native = native_pairing_batch_check(&g1, &g2).unwrap();
            let ark = Bls12_381::multi_pairing(
                [prepare_g1::<Bls12_381>(p), prepare_g1::<Bls12_381>(neg_p)],
                [prepare_g2::<Bls12_381>(q), prepare_g2::<Bls12_381>(q)],
            )
            .is_zero();
            assert_eq!(native, ark, "positive pairing check disagrees with arkworks");
            assert!(native, "e(P,Q)*e(-P,Q) must be one");
        }

        // e(P,Q) * e(P,Q) must not be the identity
        {
            let p = G1Projective::rand(&mut rng).into_affine();
            let q = G2Projective::rand(&mut rng).into_affine();
            let g1 = [p, p];
            let g2 = [q, q];

            let native = native_pairing_batch_check(&g1, &g2).unwrap();
            let ark = Bls12_381::multi_pairing(
                [prepare_g1::<Bls12_381>(p), prepare_g1::<Bls12_381>(p)],
                [prepare_g2::<Bls12_381>(q), prepare_g2::<Bls12_381>(q)],
            )
            .is_zero();
            assert_eq!(native, ark, "negative pairing check disagrees with arkworks");
            assert!(!native);
        }
    }

    #[test]
    fn pairing_batch_empty_product_is_identity() {
        assert!(native_pairing_batch_check(&[], &[]).unwrap());
    }
}