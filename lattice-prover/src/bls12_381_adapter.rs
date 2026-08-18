//! Adapter for loading Circom witnesses into Lova vectors.
//!
//! Each BLS12-381 field element (256-bit) is represented as 4 × Z_{2^64} limbs
//! using little-endian decomposition: x = x_0 + x_1·2^64 + x_2·2^128 + x_3·2^192.

use lattirust_arithmetic::linear_algebra::Vector;
use lattirust_arithmetic::ring::Z2_64;
use std::path::Path;

/// Convert a BLS12-381 field element (32 bytes, big-endian) to 4 × u64 limbs (little-endian).
pub fn bls12381_bytes_to_limbs(be_bytes: &[u8; 32]) -> [u64; 4] {
    let mut limbs = [0u64; 4];
    for i in 0..4 {
        let offset = (3 - i) * 8;
        limbs[i] = u64::from_be_bytes(be_bytes[offset..offset + 8].try_into().unwrap());
    }
    limbs
}

/// Convert 4 × u64 limbs (little-endian) back to a BLS12-381 field element bytes (big-endian).
pub fn limbs_to_bls12381_bytes(limbs: [u64; 4]) -> [u8; 32] {
    let mut be_bytes = [0u8; 32];
    for i in 0..4 {
        let offset = (3 - i) * 8;
        be_bytes[offset..offset + 8].copy_from_slice(&limbs[i].to_be_bytes());
    }
    be_bytes
}

/// Parse a Circom `.wtns` file and return the witness as a flat vector of Z_{2^64} values.
///
/// Each BLS12-381 field element is expanded to 4 × Z_{2^64} limbs, so the returned
/// vector has length `4 × n_signals`.
pub fn load_witness_as_limbs(path: &Path) -> Result<Vec<Z2_64>, String> {
    let data =
        std::fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;

    if data.len() < 12 {
        return Err(format!(
            "{}: file too short for wtns header",
            path.display()
        ));
    }

    // Snarkjs wtns format:
    // Header: magic (4 bytes LE), version (4 bytes LE), nSections (4 bytes LE)
    // Each section: type (4 bytes LE), length (8 bytes LE), data (length bytes)
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

    // Find the signals section (type = 2)
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
    let mut limbs = Vec::with_capacity(n_signals * 4);

    for i in 0..n_signals {
        let start = i * 32;
        let mut be_bytes = [0u8; 32];
        be_bytes.copy_from_slice(&signals[start..start + 32]);

        let signal_limbs = bls12381_bytes_to_limbs(&be_bytes);
        for &limb in &signal_limbs {
            limbs.push(Z2_64::from(limb as i64));
        }
    }

    Ok(limbs)
}

/// Load a directory of `.wtns` files and return them as a vector of Lova witness vectors.
pub fn load_step_witnesses_as_limbs(
    steps_dir: &Path,
    max_steps: Option<usize>,
) -> Result<Vec<Vector<Z2_64>>, String> {
    let mut wtns_paths: Vec<_> = std::fs::read_dir(steps_dir)
        .map_err(|e| format!("failed to read steps dir: {e}"))?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().and_then(|x| x.to_str()) == Some("wtns"))
        .map(|entry| entry.path())
        .collect();

    wtns_paths.sort();

    if let Some(max) = max_steps {
        wtns_paths.truncate(max);
    }

    if wtns_paths.is_empty() {
        return Err(format!("no .wtns files found in {}", steps_dir.display()));
    }

    eprintln!(
        "Loading {} step witnesses from {}",
        wtns_paths.len(),
        steps_dir.display()
    );

    let mut witnesses = Vec::with_capacity(wtns_paths.len());
    for path in &wtns_paths {
        let limbs = load_witness_as_limbs(path)?;
        witnesses.push(Vector::from_vec(limbs));
    }

    Ok(witnesses)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bls12381_bytes_to_limbs_roundtrip() {
        // Test with known value: 256 = 0x100
        let mut be_bytes = [0u8; 32];
        be_bytes[30] = 0x01; // 256 in big-endian

        let limbs = bls12381_bytes_to_limbs(&be_bytes);
        assert_eq!(limbs[0], 256);
        assert_eq!(limbs[1], 0);
        assert_eq!(limbs[2], 0);
        assert_eq!(limbs[3], 0);

        let roundtrip = limbs_to_bls12381_bytes(limbs);
        assert_eq!(be_bytes, roundtrip);
    }

    #[test]
    fn test_bls12381_bytes_to_limbs_large_value() {
        // Test with value that uses multiple limbs.
        // Big-endian bytes: MSB at index 0, LSB at index 31.
        let mut be_bytes = [0u8; 32];
        be_bytes[0] = 0x01; // MSB: bits 248-255 → limb 3
        be_bytes[16] = 0x02; // bits 120-127 → limb 1
        be_bytes[31] = 0xFF; // LSB: bits 0-7 → limb 0

        let limbs = bls12381_bytes_to_limbs(&be_bytes);
        // limb 0 (bytes 24..32): [0,0,0,0,0,0,0,0xFF] → 0xFF
        assert_eq!(limbs[0], 0xFF);
        // limb 1 (bytes 16..24): [0x02,0,0,0,0,0,0,0] → 0x02 << 56
        assert_eq!(limbs[1], 0x02 << 56);
        // limb 2 (bytes 8..16): all zeros
        assert_eq!(limbs[2], 0);
        // limb 3 (bytes 0..8): [0x01,0,0,0,0,0,0,0] → 0x01 << 56
        assert_eq!(limbs[3], 0x01 << 56);

        let roundtrip = limbs_to_bls12381_bytes(limbs);
        assert_eq!(be_bytes, roundtrip);
    }
}
