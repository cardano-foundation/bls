#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_main)]
#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_std)]

extern crate alloc;

#[cfg(not(target_os = "zkvm"))]
use alloc::format;
#[cfg(not(target_os = "zkvm"))]
use alloc::string::String;
use alloc::vec::Vec;
use curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use num_bigint::BigUint;
#[cfg(not(target_os = "zkvm"))]
use openvm_sha2::Digest;
use openvm_sha2::Sha512;

openvm::entry!(main);

const SHA512_BLOCK_SIZE: usize = 128;

/// Manual HMAC-SHA512 using the OpenVM `Sha512` digest.
///
/// The `hmac` crate cannot be used directly because the guest `Sha512` type does
/// not expose the low-level `core_api` traits that `hmac` requires.
fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    // Normalize key length.
    let mut k = [0u8; SHA512_BLOCK_SIZE];
    if key.len() > SHA512_BLOCK_SIZE {
        k[..64].copy_from_slice(&sha512(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; SHA512_BLOCK_SIZE];
    let mut opad = [0x5cu8; SHA512_BLOCK_SIZE];
    for i in 0..SHA512_BLOCK_SIZE {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }

    let mut inner = Sha512::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_hash: [u8; 64] = inner.finalize().into();

    let mut outer = Sha512::new();
    outer.update(&opad);
    outer.update(&inner_hash);
    outer.finalize().into()
}

fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize().into()
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

/// BIP32-Ed25519 hardened child derivation.
///
/// `idx` must already include the hardened bit (`0x80000000 | i`).
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

/// BIP32-Ed25519 soft (non-hardened) child derivation.
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

/// Ed25519 public key from the left half of an extended private key.
///
/// The scalar is reduced modulo the subgroup order, matching the behaviour of
/// the reference Circom implementation and `cardano-address`.
fn pubkey(kl: &[u8; 32]) -> [u8; 32] {
    let scalar = Scalar::from_bytes_mod_order(*kl);
    let point = &scalar * ED25519_BASEPOINT_TABLE;
    point.compress().to_bytes()
}

/// Derive the payment public key at `m/1852H/1815H/0H/0/0` from a 96-byte master `XPrv`.
pub fn derive_strong(master: &[u8; 96]) -> [u8; 32] {
    let mut kl: [u8; 32] = master[..32].try_into().unwrap();
    let mut kr: [u8; 32] = master[32..64].try_into().unwrap();
    let mut cc: [u8; 32] = master[64..96].try_into().unwrap();

    // m / 1852H
    (kl, kr, cc) = ckd_hardened(&kl, &kr, &cc, 0x8000073c);
    // m / 1815H
    (kl, kr, cc) = ckd_hardened(&kl, &kr, &cc, 0x80000717);
    // m / 0H
    (kl, kr, cc) = ckd_hardened(&kl, &kr, &cc, 0x80000000);

    // m / 0 (role = external)
    let ap = pubkey(&kl);
    (kl, kr, cc) = ckd_soft(&kl, &kr, &cc, 0x00000000, &ap);

    // m / 0 (address index)
    let ap = pubkey(&kl);
    (kl, _, _) = ckd_soft(&kl, &kr, &cc, 0x00000000, &ap);

    pubkey(&kl)
}

#[cfg(not(target_os = "zkvm"))]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn main() {
    #[cfg(target_os = "zkvm")]
    {
        let master = openvm::io::read_vec();
        assert_eq!(master.len(), 96, "expected 96-byte master XPrv");
        let master: [u8; 96] = master.try_into().unwrap_or_else(|_| panic!("bad length"));
        let apk = derive_strong(&master);
        openvm::io::reveal_bytes32(apk);
    }

    #[cfg(not(target_os = "zkvm"))]
    {
        let master_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                          202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                          404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
        let master = hex::decode(master_hex).expect("valid fixture hex");
        let master: [u8; 96] = master.try_into().unwrap();

        let apk = derive_strong(&master);
        println!("derived apk: {}", hex(&apk));

        let expected = "63658c2ec89f2fc978bd99c4ee00c6057d6a5b0baa29dc9d62beb4c5e511862c";
        assert_eq!(hex(&apk), expected, "fixture mismatch");
        println!("fixture OK");
    }
}
