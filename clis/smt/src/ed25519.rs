//! Ed25519 key handling for the CardanoKeyOwnershipSMT circuit.
//!
//! The circuit proves ownership of a Cardano payment key: it re-derives the
//! public key `A = sk · G` in-circuit and commits the public key into a
//! Sparse Merkle Tree. The witness therefore has to supply:
//!
//!   - `PointA[4][3]` — the decompressed extended coordinates `[X, Y, Z, T]`
//!     of `A`, each split into three base-2^85 limbs,
//!   - `A[256]` — the little-endian bits of the compressed public key,
//!   - `sk[255]` — the little-endian bits of the clamped private scalar.
//!
//! All coordinate arithmetic happens in the Ed25519 base field
//! `Fq = Z/(2^255 - 19)` (not the BLS12-381 scalar field); only the final
//! 85-bit limbs are reinterpreted as BLS12-381 scalar field elements in the
//! circuit input.

use ark_ff::fields::{Fp, MontBackend, MontConfig};
use ark_ff::{BigInt, Field, One, PrimeField};

/// Config for the Ed25519 base field `Z/(2^255 - 19)`.
///
/// `p - 1 = 2^253 - 20 = 4 · 3 · 65147 · q` (q a 74-digit prime), and `2` is
/// a primitive root of `Fq` (see `generator_is_primitive_root`).
#[derive(MontConfig)]
#[modulus = "57896044618658097711785492504343953926634992332820282019728792003956564819949"]
#[generator = "2"]
pub struct Ed25519FieldConfig;

/// The Ed25519 base field `Fq = Z/(2^255 - 19)`.
pub type Fq = Fp<MontBackend<Ed25519FieldConfig, 4>, 4>;

/// `(p + 3) / 8 = 2^252 - 2`, the square-root exponent for `p ≡ 5 (mod 8)`.
const SQRT_EXPONENT: [u64; 4] = [
    0xffff_ffff_ffff_fffe,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x0fff_ffff_ffff_ffff,
];

/// `(p - 1) / 4 = 2^253 - 5`, the exponent of `sqrt(-1) = 2^((p-1)/4)`.
const SQRT_M1_EXPONENT: [u64; 4] = [
    0xffff_ffff_ffff_fffb,
    0xffff_ffff_ffff_ffff,
    0xffff_ffff_ffff_ffff,
    0x1fff_ffff_ffff_ffff,
];

/// Decompress a compressed Ed25519 public key to extended coordinates
/// `[X, Y, Z, T]` in the Ed25519 base field.
///
/// `pk` is the standard 32-byte compressed point: the low 255 bits are `Y`
/// and bit 255 is the sign of `X`. Returns `None` if the point is not on the
/// curve (i.e. `u/v` is not a quadratic residue).
pub fn decompress_point(pk: &[u8; 32]) -> Option<[Fq; 4]> {
    let sign = u64::from(pk[31] >> 7);

    let mut y_limbs = [0u64; 4];
    for i in 0..4 {
        y_limbs[i] = u64::from_le_bytes(pk[i * 8..i * 8 + 8].try_into().unwrap());
    }
    y_limbs[3] &= 0x7fff_ffff_ffff_ffff;
    let y = Fq::from(BigInt::new(y_limbs));

    // d = -121665/121666  (curve constant)
    let d = -Fq::from(121665u64) * Fq::from(121666u64).inverse()?;

    let y2 = y * y;
    let u = y2 - Fq::one();
    let v = d * y2 + Fq::one();
    let x2 = u * v.inverse()?;

    // p ≡ 5 (mod 8): x = x2^((p+3)/8), and if that fails, x *= sqrt(-1).
    let x = x2.pow(SQRT_EXPONENT);
    let x = if x * x == x2 {
        x
    } else {
        x * Fq::from(2u64).pow(SQRT_M1_EXPONENT)
    };

    let x = if x.into_bigint().0[0] & 1 == sign { x } else { -x };

    Some([x, y, Fq::one(), x * y])
}

/// Split a field element into three base-2^85 limbs (little-endian).
///
/// The circuit's `PointA[4][3]` layout expects every extended coordinate to
/// be decomposed into `n = 3` chunks of `bits = 85` each, matching
/// `to_chunks` in `gen_smt_input.py`.
pub fn to_chunks(coord: Fq) -> [u128; 3] {
    let limbs = coord.into_bigint().0;
    let lo = (limbs[0] as u128) | ((limbs[1] as u128) << 64);
    let hi = (limbs[2] as u128) | ((limbs[3] as u128) << 64);
    let mask = (1u128 << 85) - 1;
    [lo & mask, ((lo >> 85) | (hi << 43)) & mask, hi >> 42]
}

/// Little-endian bit decomposition of a byte slice (`A[256]` / `sk[255]`).
pub fn bits_le(data: &[u8]) -> Vec<u8> {
    let mut bits = Vec::with_capacity(data.len() * 8);
    for byte in data {
        for i in 0..8 {
            bits.push((byte >> i) & 1);
        }
    }
    bits
}

/// Clamp an Ed25519 scalar (first 32 bytes of an extended signing key):
/// clear bits 0-2 and 255, set bit 254.
pub fn clamp_scalar(mut k: [u8; 32]) -> [u8; 32] {
    k[0] &= 0xf8;
    k[31] &= 0x7f;
    k[31] |= 0x40;
    k
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::One;

    fn from_hex_le(hex_str: &str) -> [u8; 32] {
        let bytes: Vec<u8> = (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    #[test]
    fn generator_is_primitive_root() {
        // p - 1 = 4 · 3 · 65147 · q with q prime, so 2 is a generator of Fq
        // iff 2^((p-1)/q) != 1 for each prime q dividing p - 1.
        let two = Fq::from(2u64);
        for quotient in [
            [18446744073709551606, 18446744073709551615, 18446744073709551615, 4611686018427387903], // (p-1)/2
            [12297829382473034404, 12297829382473034410, 12297829382473034410, 3074457345618258602], // (p-1)/3
            [2855342030166962692, 11885460305063294228, 15904005931018226251, 141577847588603],      // (p-1)/65147
            [781764, 0, 0, 0],                                                                        // (p-1)/q
        ] {
            assert_ne!(two.pow(BigInt::new(quotient)), Fq::one());
        }
    }

    #[test]
    fn to_chunks_round_trips_field_element() {
        let v = Fq::from(BigInt::new([
            0xffff_ffff_ffff_ffec,
            0xffff_ffff_ffff_ffff,
            0xffff_ffff_ffff_ffff,
            0x7fff_ffff_ffff_ffff,
        ])) - Fq::one();
        let chunks = to_chunks(v);
        let bigint = v.into_bigint().0;
        let lo = (bigint[0] as u128) | ((bigint[1] as u128) << 64);
        let hi = (bigint[2] as u128) | ((bigint[3] as u128) << 64);
        let mut rebuilt_lo = 0u128;
        let mut rebuilt_hi = 0u128;
        // c0 at bits 0..85 (lo), c1 at bits 85..170 (lo 43 + hi 42), c2 at 170..255 (hi)
        rebuilt_lo |= chunks[0];
        rebuilt_lo |= (chunks[1] << 85) & u128::MAX;
        rebuilt_hi |= chunks[1] >> 43;
        rebuilt_hi |= chunks[2] << 42;
        assert_eq!(rebuilt_lo, lo);
        assert_eq!(rebuilt_hi, hi);
        // each chunk is < 2^85
        for c in chunks {
            assert!(c < (1u128 << 85));
        }
    }

    #[test]
    fn decompress_matches_known_vector() {
        // Public key from the CardanoKeyOwnershipSMT e2e run.
        let pk = from_hex_le("820c32b69eb1402ed2516631041562dff14926ffaa64bbb87c177f44bebbe89f");
        let [x, y, z, t] = decompress_point(&pk).unwrap();
        assert_eq!(z, Fq::one());
        let to_str = |f: Fq| f.to_string();
        assert_eq!(to_str(x), "16898654222766501230360042753808997519668143548935929965202866598045890387463");
        assert_eq!(to_str(y), "14432902581280078143708270982465756518356835159810302713196284416804963617922");
        assert_eq!(to_str(t), "30359189629241321789774938535172306918949613991876134894828091163724660760767");

        let chunks = [to_chunks(x), to_chunks(y), to_chunks(z), to_chunks(t)];
        assert_eq!(
            chunks[0],
            [11802314750758161668382215, 14687450817863025263804952, 11291531663665191350912841]
        );
        assert_eq!(
            chunks[1],
            [7639943751914714790235266, 6460071846630592709403019, 9643938170860987566927577]
        );
        assert_eq!(chunks[2], [1, 0, 0]);
        assert_eq!(
            chunks[3],
            [14825295602590827820245183, 38372323862364294726689068, 20285742667008293514408867]
        );
    }

    #[test]
    fn bits_le_and_clamp_match_python() {
        let pk = from_hex_le("820c32b69eb1402ed2516631041562dff14926ffaa64bbb87c177f44bebbe89f");
        let a = bits_le(&pk);
        assert_eq!(a.len(), 256);
        assert_eq!(&a[..8], &[0, 1, 0, 0, 0, 0, 0, 1]);
        assert_eq!(&a[248..], &[1, 1, 1, 1, 1, 0, 0, 1]);

        let k = from_hex_le("c0d771af79a864c78fe8519b7510580bdda94cc59f628d77cb43ba5e0fe7e067");
        let clamped = clamp_scalar(k);
        assert_eq!(clamped[0] & 0x07, 0);
        assert_eq!(clamped[31] >> 6, 1);
        let sk = bits_le(&clamped);
        assert_eq!(sk.len(), 256);
        assert_eq!(&sk[..8], &[0, 0, 0, 0, 0, 0, 1, 1]);
    }
}
