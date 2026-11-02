#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use alloc::vec::Vec;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut mac = HmacSha512::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

fn le256(b: &[u8]) -> BigUint {
    BigUint::from_bytes_le(b)
}

fn le28(b: &[u8]) -> BigUint {
    BigUint::from_bytes_le(&b[..28])
}

fn to_bytes32_le(n: &BigUint) -> [u8; 32] {
    let b = n.to_bytes_le();
    let mut out = [0u8; 32];
    let len = b.len().min(32);
    out[..len].copy_from_slice(&b[..len]);
    out
}

fn ckd_hardened(
    kl: &[u8; 32],
    kr: &[u8; 32],
    cc: &[u8; 32],
    idx: u32,
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let idx_le = idx.to_le_bytes();

    let mut data = Vec::with_capacity(1 + 32 + 32 + 4);
    data.push(0x00);
    data.extend_from_slice(kl);
    data.extend_from_slice(kr);
    data.extend_from_slice(&idx_le);
    let z = hmac_sha512(cc, &data);

    let mod2_256 = BigUint::from(1u8) << 256;
    let new_kl = (le28(&z) * 8u32 + le256(kl)) % &mod2_256;
    let new_kr = (le256(&z[32..]) + le256(kr)) % &mod2_256;

    let mut data_ncc = Vec::with_capacity(1 + 32 + 32 + 4);
    data_ncc.push(0x01);
    data_ncc.extend_from_slice(kl);
    data_ncc.extend_from_slice(kr);
    data_ncc.extend_from_slice(&idx_le);
    let ncc = hmac_sha512(cc, &data_ncc)[32..].try_into().unwrap();

    (to_bytes32_le(&new_kl), to_bytes32_le(&new_kr), ncc)
}

fn ckd_soft(
    kl: &[u8; 32],
    kr: &[u8; 32],
    cc: &[u8; 32],
    idx: u32,
    apub: &[u8; 32],
) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let idx_le = idx.to_le_bytes();

    let mut data = Vec::with_capacity(1 + 32 + 4);
    data.push(0x02);
    data.extend_from_slice(apub);
    data.extend_from_slice(&idx_le);
    let z = hmac_sha512(cc, &data);

    let mod2_256 = BigUint::from(1u8) << 256;
    let new_kl = (le28(&z) * 8u32 + le256(kl)) % &mod2_256;
    let new_kr = (le256(&z[32..]) + le256(kr)) % &mod2_256;

    let mut data_ncc = Vec::with_capacity(1 + 32 + 4);
    data_ncc.push(0x03);
    data_ncc.extend_from_slice(apub);
    data_ncc.extend_from_slice(&idx_le);
    let ncc = hmac_sha512(cc, &data_ncc)[32..].try_into().unwrap();

    (to_bytes32_le(&new_kl), to_bytes32_le(&new_kr), ncc)
}

fn pubkey(kl: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(*kl);
    let point = &scalar * ED25519_BASEPOINT_TABLE;
    point.compress().to_bytes()
}

fn derive_strong(master: &[u8; 96]) -> [u8; 32] {
    let mut kl: [u8; 32] = master[..32].try_into().unwrap();
    let mut kr: [u8; 32] = master[32..64].try_into().unwrap();
    let mut cc: [u8; 32] = master[64..96].try_into().unwrap();

    (kl, kr, cc) = ckd_hardened(&kl, &kr, &cc, 0x8000073c);
    (kl, kr, cc) = ckd_hardened(&kl, &kr, &cc, 0x80000717);
    (kl, kr, cc) = ckd_hardened(&kl, &kr, &cc, 0x80000000);

    let ap = pubkey(&kl);
    (kl, kr, cc) = ckd_soft(&kl, &kr, &cc, 0x00000000, &ap);

    let ap = pubkey(&kl);
    (kl, _, _) = ckd_soft(&kl, &kr, &cc, 0x00000000, &ap);

    pubkey(&kl)
}

#[jolt::provable(heap_size = 32768, max_trace_length = 10000000)]
pub fn derive_cardano_strong(master: &[u8]) -> [u8; 32] {
    assert_eq!(master.len(), 96, "expected 96-byte master XPrv");
    let master: [u8; 96] = master.try_into().unwrap();
    derive_strong(&master)
}
