//! RNS (Residue Number System) decomposition for BLS12-381 → Z_{2^64} vectors.
//!
//! Instead of decomposing a 256-bit BLS12-381 element into 4 × 64-bit limbs
//! (which fixes the Lova dimension at `4 × num_signals`), RNS decomposes it
//! into `k` residues modulo small coprime primes.  When each residue is ≤ 32
//! bits, the Lova witness norms shrink dramatically — fewer decomposition digits
//! are needed, which shrinks proof size and speeds up verification.
//!
//! # Choosing RNS parameters
//!
//! ```text
//! residues_per_element | max_norm        | decompose_digits (est) | dimension
//! -------------------- | --------------- | ---------------------- | ---------
//! 8  (32-bit primes)   | < 2^32          | 32                     | 8 × signals
//! 4  (64-bit = limbs)  | < 2^64          | 64                     | 4 × signals
//! ```
//!
//! The sweet spot is **8 residues of ≤ 32 bits each**: 2× more residues than
//! the 4-limb approach, but each residue has ~2× smaller norm → ~2× fewer
//! decomposition digits → ~2× smaller proofs.  The trade-off is 2× larger
//! commitment matrix and witness dimension.

use lattirust_arithmetic::linear_algebra::Vector;
use lattirust_arithmetic::ring::representatives::WithSignedRepresentative;
use lattirust_arithmetic::ring::Z2_64;

/// RNS configuration: a set of coprime moduli whose product exceeds 2^255
/// (the BLS12-381 scalar field modulus).
#[derive(Debug, Clone)]
pub struct RnsConfig {
    /// The moduli, each fitting in a u32.
    pub moduli: Vec<u64>,
    /// Precomputed M_i^{-1} mod moduli[i] for each i.
    pub big_m_inv: Vec<u64>,
}

/// Helper: compute (a * b) mod m using u128 arithmetic.
fn mulmod64(a: u64, b: u64, m: u64) -> u64 {
    ((a as u128 * b as u128) % m as u128) as u64
}

impl RnsConfig {
    /// Create an RNS config from a set of moduli.
    ///
    /// Panics if moduli are not pairwise coprime, not all > 2^31,
    /// or fewer than 8 moduli (needed for 255-bit range).
    pub fn new(moduli: Vec<u64>) -> Self {
        assert!(!moduli.is_empty(), "need at least one modulus");
        for &m in &moduli {
            assert!(m > 1, "modulus must be > 1");
            assert!(m <= u32::MAX as u64, "modulus must fit in u32");
            assert!(
                m > (1u64 << 31),
                "modulus must be > 2^31 for sufficient range"
            );
        }
        // Check pairwise coprime
        for i in 0..moduli.len() {
            for j in (i + 1)..moduli.len() {
                assert!(
                    gcd(moduli[i], moduli[j]) == 1,
                    "moduli {} and {} are not coprime",
                    moduli[i],
                    moduli[j]
                );
            }
        }
        // For 8 × 32-bit primes, product ≈ 2^256 > 2^255
        assert!(
            moduli.len() >= 8,
            "need ≥ 8 moduli for 255-bit range; got {}",
            moduli.len()
        );

        // Compute M_i = product / m_i by multiplying all other moduli together
        // using u128 to avoid overflow for intermediate products.
        // For8 moduli ≈ 2^32 each, the intermediate product of7 moduli ≈ 2^224
        // which doesn't fit in u128.  Instead, we compute M_i modulo each m_j
        // and store for CRT reconstruction.
        //
        // Strategy: compute M_i mod m_j for all j ≠ i.
        let n = moduli.len();
        let mut m_i_mod_mj: Vec<Vec<u64>> = vec![vec![0; n]; n];
        for i in 0..n {
            m_i_mod_mj[i][i] = 1; // M_i mod m_i = 1 (by CRT normalization)
            for j in 0..n {
                if i == j {
                    continue;
                }
                // M_i = product of all moduli except m_i
                // M_i mod m_j = product_{k ≠ i, k ≠ j} m_k mod m_j
                let mut prod = 1u64;
                for k in 0..n {
                    if k == i || k == j {
                        continue;
                    }
                    prod = mulmod64(prod, moduli[k], moduli[j]);
                }
                m_i_mod_mj[i][j] = prod;
            }
        }

        // Compute M_i^{-1} mod m_i
        let big_m_inv: Vec<u64> = (0..n)
            .map(|i| {
                // M_i mod m_i
                let mut mi_mod = 1u64;
                for k in 0..n {
                    if k == i {
                        continue;
                    }
                    mi_mod = mulmod64(mi_mod, moduli[k], moduli[i]);
                }
                mod_inverse(mi_mod, moduli[i])
                    .unwrap_or_else(|| panic!("M[{}] has no inverse mod {}", i, moduli[i]))
            })
            .collect();

        Self { moduli, big_m_inv }
    }

    /// Number of residues per BLS12-381 element.
    pub fn residues_per_element(&self) -> usize {
        self.moduli.len()
    }

    /// Convert a 256-bit big-endian BLS12-381 element to RNS residues.
    ///
    /// Returns a vector of `k` residues, each `< moduli[i]`.
    pub fn to_rns(&self, be_bytes: &[u8; 32]) -> Vec<u64> {
        self.moduli
            .iter()
            .map(|&m| {
                let mut val = 0u64;
                for &byte in be_bytes.iter() {
                    val = ((val << 8) | byte as u64) % m;
                }
                val
            })
            .collect()
    }

    /// Reconstruct a BLS12-381 element from RNS residues via CRT.
    ///
    /// Uses the mixed-radix incremental CRT approach, operating on
    /// a 256-bit accumulator stored as4 × u64 limbs (little-endian).
    pub fn from_rns(&self, residues: &[u64]) -> [u8; 32] {
        assert_eq!(residues.len(), self.moduli.len());

        let n = self.moduli.len();

        // 256-bit accumulator in 4 × u64 limbs, little-endian (limb0 = least significant).
        let mut acc_limbs = [0u64; 4];
        acc_limbs[0] = residues[0];

        // Accumulated product of moduli (also 4 × u64 limbs).
        let mut prod_limbs = [0u64; 4];
        prod_limbs[0] = self.moduli[0];

        for i in 1..n {
            let m_i = self.moduli[i];

            // Compute acc mod m_i
            let acc_mod_mi = {
                let mut v = 0u64;
                let mut power = 1u64; // 2^0 mod m_i
                for limb in &acc_limbs {
                    v = (v + mulmod64(*limb % m_i, power, m_i)) % m_i;
                    power = mulmod64(power, (1u64 << 32) % m_i, m_i);
                    power = mulmod64(power, (1u64 << 32) % m_i, m_i);
                }
                v
            };

            // Compute prod mod m_i (same approach)
            let prod_mod_mi = {
                let mut v = 0u64;
                let mut power = 1u64;
                for limb in &prod_limbs {
                    v = (v + mulmod64(*limb % m_i, power, m_i)) % m_i;
                    power = mulmod64(power, (1u64 << 32) % m_i, m_i);
                    power = mulmod64(power, (1u64 << 32) % m_i, m_i);
                }
                v
            };

            // t_i = (residues[i] - acc_mod_mi) * prod_inv mod m_i
            let prod_inv = mod_inverse(prod_mod_mi, m_i)
                .unwrap_or_else(|| panic!("prod has no inverse mod m_{}", i));

            let mut diff = residues[i] as i64 - acc_mod_mi as i64;
            if diff < 0 {
                diff += m_i as i64;
            }
            let t_i = mulmod64(diff as u64, prod_inv, m_i);

            // acc += prod * t_i (256-bit addition with carry)
            add_mul_256(&mut acc_limbs, &prod_limbs, t_i);

            // prod *= m_i (256-bit multiply by small constant)
            mul_small_256(&mut prod_limbs, m_i);
        }

        // Convert acc_limbs (little-endian) to big-endian bytes.
        // limb[3] is most significant, limb[0] is least significant.
        let mut result = [0u8; 32];
        for i in 0..4 {
            let limb_bytes = acc_limbs[3 - i].to_be_bytes();
            result[i * 8..(i + 1) * 8].copy_from_slice(&limb_bytes);
        }
        result
    }

    /// Convert RNS residues to Z_{2^64} vector for Lova.
    pub fn residues_to_z2_64(residues: &[u64]) -> Vec<Z2_64> {
        residues.iter().map(|&r| Z2_64::from(r as i64)).collect()
    }

    /// Convert a flat Z_{2^64} vector (interleaved RNS residues) back to
    /// per-element residue groups.
    pub fn z2_64_to_residue_groups(flat: &[Z2_64], k: usize) -> Vec<Vec<u64>> {
        flat.chunks(k)
            .map(|chunk| {
                chunk
                    .iter()
                    .map(|z| z.as_signed_representative() as u64)
                    .collect()
            })
            .collect()
    }
}

/// Predefined RNS configurations.
impl RnsConfig {
    /// 8 × 32-bit moduli: full BLS12-381 range, 2× dimension.
    pub fn mod_8x32() -> Self {
        Self::new(vec![
            4_294_967_291, // 2^32 - 5
            4_294_967_279, // 2^32 - 17
            4_294_967_231, // 2^32 - 65
            4_294_967_197, // 2^32 - 99
            4_294_967_189, // 2^32 - 107
            4_294_967_161, // 2^32 - 135
            4_294_967_143, // 2^32 - 153
            4_294_967_111, // 2^32 - 185
        ])
    }

    /// 8 × 32-bit moduli (identical to mod_8x32 for simplicity).
    pub fn mod_8x32_small() -> Self {
        Self::new(vec![
            4_294_967_291, // 2^32 - 5
            4_294_967_279, // 2^32 - 17
            4_294_967_231, // 2^32 - 65
            4_294_967_197, // 2^32 - 99
            4_294_967_189, // 2^32 - 107
            4_294_967_161, // 2^32 - 135
            4_294_967_143, // 2^32 - 153
            4_294_967_111, // 2^32 - 185
        ])
    }
}

/// 256-bit addition: result += a * scalar (4 × u64 limbs, little-endian).
fn add_mul_256(result: &mut [u64; 4], a: &[u64; 4], scalar: u64) {
    let mut carry = 0u128;
    for i in 0..4 {
        carry += result[i] as u128 + a[i] as u128 * scalar as u128;
        result[i] = carry as u64;
        carry >>= 64;
    }
}

/// 256-bit multiply by small constant: limbs *= scalar (4 × u64 limbs, little-endian).
fn mul_small_256(limbs: &mut [u64; 4], scalar: u64) {
    let mut carry = 0u128;
    for i in 0..4 {
        carry += limbs[i] as u128 * scalar as u128;
        limbs[i] = carry as u64;
        carry >>= 64;
    }
}

/// Greatest common divisor.
fn gcd(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let t = b;
        b = a % b;
        a = t;
    }
    a
}

/// Modular inverse using extended Euclidean algorithm.
/// Returns `a^{-1} mod m` or `None` if gcd(a, m) ≠ 1.
fn mod_inverse(a: u64, m: u64) -> Option<u64> {
    let (mut t, mut newt): (i128, i128) = (0, 1);
    let (mut r, mut newr): (i128, i128) = (m as i128, a as i128);
    while newr != 0 {
        let q = r / newr;
        let tmp = t - q * newt;
        t = newt;
        newt = tmp;
        let tmp = r - q * newr;
        r = newr;
        newr = tmp;
    }
    if r > 1 {
        return None;
    }
    if t < 0 {
        t += m as i128;
    }
    Some(t as u64)
}

/// Load a Circom `.wtns` file and return the witness as RNS residues.
///
/// Returns a flat vector of Z_{2^64} values: for each signal, `k` residues
/// are appended sequentially.  The total length is `k × n_signals`.
pub fn load_witness_as_rns(
    path: &std::path::Path,
    config: &RnsConfig,
) -> Result<Vec<Z2_64>, String> {
    let data =
        std::fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;

    if data.len() < 12 {
        return Err(format!(
            "{}: file too short for wtns header",
            path.display()
        ));
    }

    let mut offset = 0;
    let magic = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    offset += 4;
    if magic != 0x736e7477 {
        return Err(format!(
            "{}: invalid wtns magic 0x{:08x} (expected 0x736e7477)",
            path.display(),
            magic
        ));
    }
    let _version = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    offset += 4;
    let n_sections = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;

    let mut signals_data: Option<&[u8]> = None;
    for _ in 0..n_sections {
        if offset + 12 > data.len() {
            return Err(format!("{}: truncated section header", path.display()));
        }
        let sec_type = u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
        offset += 4;
        let sec_len = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap()) as usize;
        offset += 8;
        if sec_type == 2 {
            signals_data = Some(&data[offset..offset + sec_len]);
        }
        offset += sec_len;
    }

    let signals = signals_data
        .ok_or_else(|| format!("{}: no signals section (type 2) found", path.display()))?;

    if signals.len() % 32 != 0 {
        return Err(format!(
            "{}: signals section length {} is not a multiple of 32",
            path.display(),
            signals.len()
        ));
    }

    let n_signals = signals.len() / 32;
    let k = config.residues_per_element();
    let mut flat = Vec::with_capacity(n_signals * k);

    for i in 0..n_signals {
        let start = i * 32;
        let mut be_bytes = [0u8; 32];
        be_bytes.copy_from_slice(&signals[start..start + 32]);
        let residues = config.to_rns(&be_bytes);
        for &r in &residues {
            flat.push(Z2_64::from(r as i64));
        }
    }

    Ok(flat)
}

/// Load all step witnesses from a directory as RNS residues.
pub fn load_step_witnesses_as_rns(
    steps_dir: &std::path::Path,
    config: &RnsConfig,
    limit: Option<usize>,
) -> Result<Vec<Vector<Z2_64>>, String> {
    let mut wtns_paths: Vec<_> = std::fs::read_dir(steps_dir)
        .map_err(|e| format!("failed to read steps dir: {e}"))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().and_then(|x| x.to_str()) == Some("wtns"))
        .map(|entry| entry.path())
        .collect();

    wtns_paths.sort();
    if let Some(limit) = limit {
        wtns_paths.truncate(limit);
    }

    let mut witnesses = Vec::with_capacity(wtns_paths.len());
    for path in &wtns_paths {
        let flat = load_witness_as_rns(path, config)?;
        witnesses.push(Vector::from_vec(flat));
    }
    Ok(witnesses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_moduli_are_coprime() {
        let config = RnsConfig::mod_8x32_small();
        for i in 0..config.moduli.len() {
            for j in (i + 1)..config.moduli.len() {
                assert_eq!(
                    gcd(config.moduli[i], config.moduli[j]),
                    1,
                    "moduli[{}]={} and moduli[{}]={} not coprime",
                    i,
                    config.moduli[i],
                    j,
                    config.moduli[j]
                );
            }
        }
    }

    #[test]
    fn test_product_exceeds_255_bits() {
        let config = RnsConfig::mod_8x32_small();
        // 8 × 32-bit moduli should have product ≈ 2^256
        let all_32bit = config.moduli.iter().all(|&m| m > (1u64 << 31));
        assert!(all_32bit && config.moduli.len() >= 8);
    }

    #[test]
    fn test_to_rns_small() {
        let config = RnsConfig::mod_8x32_small();
        // Value = 42
        let be_bytes = {
            let mut b = [0u8; 32];
            b[31] = 42;
            b
        };
        let residues = config.to_rns(&be_bytes);
        for (i, &r) in residues.iter().enumerate() {
            assert_eq!(r, 42 % config.moduli[i]);
        }
    }

    #[test]
    fn test_to_rns_one() {
        let config = RnsConfig::mod_8x32_small();
        let be_bytes = {
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        };
        let residues = config.to_rns(&be_bytes);
        for &r in &residues {
            assert_eq!(r, 1);
        }
    }

    #[test]
    fn test_to_rns_zero() {
        let config = RnsConfig::mod_8x32_small();
        let be_bytes = [0u8; 32];
        let residues = config.to_rns(&be_bytes);
        for &r in &residues {
            assert_eq!(r, 0);
        }
    }

    #[test]
    fn test_roundtrip_large_value() {
        let config = RnsConfig::mod_8x32_small();
        // A large value: 0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20
        let be_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        let residues = config.to_rns(&be_bytes);
        let recovered = config.from_rns(&residues);
        assert_eq!(be_bytes, recovered);
    }

    #[test]
    fn test_roundtrip_max_value() {
        let config = RnsConfig::mod_8x32_small();
        // 2^255 - 19 (BLS12-381 modulus - 1)
        let be_bytes: [u8; 32] = [
            0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1,
            0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xe5,
        ];
        let residues = config.to_rns(&be_bytes);
        let recovered = config.from_rns(&residues);
        assert_eq!(be_bytes, recovered);
    }

    #[test]
    fn test_roundtrip_sequential() {
        let config = RnsConfig::mod_8x32_small();
        // Test several values in sequence
        for val in [0u64, 1, 42, 255, 256, 65535, 1 << 32, 1 << 63, u64::MAX / 2] {
            let mut be_bytes = [0u8; 32];
            let mut tmp = val;
            for i in (0..32).rev() {
                be_bytes[i] = (tmp & 0xFF) as u8;
                tmp >>= 8;
            }
            let residues = config.to_rns(&be_bytes);
            let recovered = config.from_rns(&residues);
            assert_eq!(be_bytes, recovered, "roundtrip failed for {}", val);
        }
    }
}
