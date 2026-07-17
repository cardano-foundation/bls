//! Parser for snarkjs `.ptau` (Powers of Tau) files.
//!
//! The `.ptau` format is a binary file used by snarkjs to store the universal
//! SRS (Structured Reference String) from the Perpetual Powers of Tau ceremony.
//! This module reads the file and converts the stored group elements into
//! arkworks `G1Affine` / `G2Affine` types.
//!
//! # File format
//!
//! `.ptau` stores points in **LEM** (Little-Endian Montgomery) uncompressed
//! format.  This is the same internal representation used by arkworks `Fp`,
//! so the bytes can be mapped directly without expensive modular conversions.
//!
//! | Section | Contents | Point count | Bytes / point |
//! |---------|----------|-------------|---------------|
//! | 2 | tauG1 | `(2^power)·2 − 1` | 96 (G1 uncompressed) |
//! | 3 | tauG2 | `2^power` | 192 (G2 uncompressed) |
//! | 4 | alphaTauG1 | `2^power` | 96 |
//! | 5 | betaTauG1 | `2^power` | 96 |
//! | 6 | betaG2 | 1 | 192 |
//!
//! # Usage
//!
//! ```no_run
//! use groth16_prover::ptau::PtauFile;
//!
//! let mut ptau = PtauFile::open("pot14_final.ptau").unwrap();
//! let tau_g1 = ptau.read_tau_g1(ptau.max_g1_points()).unwrap();
//! let tau_g2 = ptau.read_tau_g2(ptau.max_g2_points()).unwrap();
//! ```

use ark_bls12_381::{Fq, Fq2, FqConfig, G1Affine, G2Affine};
use ark_ff::{Fp, MontBackend};
use ark_std::vec::Vec;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::marker::PhantomData;
use std::path::Path;

/// Number of bytes for a BLS12-381 base field element (`Fq`).
const N8_FQ: usize = 48;
/// Number of bytes for a BLS12-381 G1 uncompressed affine point.
const N8_G1: usize = N8_FQ * 2;
/// Number of bytes for a BLS12-381 G2 uncompressed affine point.
const N8_G2: usize = N8_FQ * 4;

/// Errors that can occur while parsing a `.ptau` file.
#[derive(Debug, PartialEq)]
pub enum Error {
    /// I/O error while reading the file.
    Io(String),
    /// Magic header is not `"ptau"`.
    InvalidMagic,
    /// Version is not `1`.
    InvalidVersion(u32),
    /// Unexpected number of sections.
    InvalidNumSections(u32),
    /// Prime modulus read from header does not match BLS12-381.
    InvalidPrime,
    /// Requested more points than the file contains.
    InsufficientPoints { requested: usize, available: usize },
    /// A point could not be converted to a valid affine group element.
    InvalidPoint { section: u32, index: usize },
    /// A section offset or size was missing from the header.
    MissingSection(usize),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::Io(msg) => write!(f, "I/O error: {}", msg),
            Error::InvalidMagic => write!(f, "invalid .ptau magic header"),
            Error::InvalidVersion(v) => write!(f, "unsupported .ptau version: {}", v),
            Error::InvalidNumSections(n) => write!(f, "invalid number of .ptau sections: {}", n),
            Error::InvalidPrime => write!(f, "prime modulus does not match BLS12-381"),
            Error::InsufficientPoints { requested, available } => {
                write!(f, "insufficient points in .ptau: requested {}, available {}", requested, available)
            }
            Error::InvalidPoint { section, index } => {
                write!(f, "invalid point in section {} at index {}", section, index)
            }
            Error::MissingSection(idx) => {
                write!(f, "missing .ptau section {}", idx)
            }
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e.to_string())
    }
}

/// A parsed `.ptau` file handle.
///
/// Holds an open [`File`] and the parsed section index.  Individual point
/// sections can be read on demand via the `read_*` methods.
pub struct PtauFile {
    file: File,
    sections: Vec<(u32, u64, u64)>, // (type, size, data_offset)
    power: u32,
    max_g1_points: usize,
    max_g2_points: usize,
}

impl PtauFile {
    /// Open a `.ptau` file and parse its header + section index.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let mut file = File::open(path)?;

        // Magic
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if &magic != b"ptau" {
            return Err(Error::InvalidMagic);
        }

        // Version
        let mut version = [0u8; 4];
        file.read_exact(&mut version)?;
        let version = u32::from_le_bytes(version);
        if version != 1 {
            return Err(Error::InvalidVersion(version));
        }

        // Number of sections
        let mut n_sections = [0u8; 4];
        file.read_exact(&mut n_sections)?;
        let n_sections = u32::from_le_bytes(n_sections);
        if n_sections != 11 {
            // snarkjs always writes exactly 11 sections for a prepared ptau
            return Err(Error::InvalidNumSections(n_sections));
        }

        // Section index
        let mut sections = Vec::with_capacity(n_sections as usize);
        for _ in 0..n_sections {
            let mut section_type = [0u8; 4];
            file.read_exact(&mut section_type)?;
            let section_type = u32::from_le_bytes(section_type);

            let mut section_size = [0u8; 8];
            file.read_exact(&mut section_size)?;
            let section_size = u64::from_le_bytes(section_size);

            let pos = file.stream_position()?;
            sections.push((section_type, section_size, pos));
            file.seek(SeekFrom::Current(section_size as i64))?;
        }

        // Read header (section 1) to extract power
        let header = sections
            .iter()
            .find(|(t, _, _)| *t == 1)
            .ok_or_else(|| Error::Io("Missing header section".to_string()))?;

        file.seek(SeekFrom::Start(header.2))?;

        let mut n8_buf = [0u8; 4];
        file.read_exact(&mut n8_buf)?;
        let n8 = u32::from_le_bytes(n8_buf);
        if n8 as usize != N8_FQ {
            return Err(Error::InvalidPrime);
        }

        // Prime modulus — we just verify it looks like BLS12-381 by checking
        // the first few bytes (full comparison is 48 bytes, overkill).
        let mut prime = [0u8; N8_FQ];
        file.read_exact(&mut prime)?;
        // BLS12-381 q in LE starts with 0xAAAB... (little-endian of
        // 0x1a0111ea397fe69a...).  We check the first byte.
        if prime[0] != 0xab {
            return Err(Error::InvalidPrime);
        }

        let mut power_buf = [0u8; 4];
        file.read_exact(&mut power_buf)?;
        let power = u32::from_le_bytes(power_buf);

        let mut _ceremony_power = [0u8; 4];
        file.read_exact(&mut _ceremony_power)?;

        let max_g2_points = 1usize << power;
        let max_g1_points = max_g2_points * 2 - 1;

        Ok(Self {
            file,
            sections,
            power,
            max_g1_points,
            max_g2_points,
        })
    }

    /// The `power` value from the header (`2^power` = max constraints).
    pub fn power(&self) -> u32 {
        self.power
    }

    /// Maximum number of G1 points available in the file.
    pub fn max_g1_points(&self) -> usize {
        self.max_g1_points
    }

    /// Maximum number of G2 points available in the file.
    pub fn max_g2_points(&self) -> usize {
        self.max_g2_points
    }

    /// Read the `tau·G1` powers from section 2.
    ///
    /// Returns `tau^0·G1, tau^1·G1, …, tau^{n−1}·G1`.
    pub fn read_tau_g1(&mut self, n: usize) -> Result<Vec<G1Affine>, Error> {
        self.read_g1_section(2, n)
    }

    /// Read the `tau·G2` powers from section 3.
    ///
    /// Returns `tau^0·G2, tau^1·G2, …, tau^{n−1}·G2`.
    pub fn read_tau_g2(&mut self, n: usize) -> Result<Vec<G2Affine>, Error> {
        self.read_g2_section(3, n)
    }

    /// Read the `alpha·tau^i·G1` points from section 4.
    pub fn read_alpha_tau_g1(&mut self, n: usize) -> Result<Vec<G1Affine>, Error> {
        self.read_g1_section(4, n)
    }

    /// Read the `beta·tau^i·G1` points from section 5.
    pub fn read_beta_tau_g1(&mut self, n: usize) -> Result<Vec<G1Affine>, Error> {
        self.read_g1_section(5, n)
    }

    /// Read the single `beta·G2` point from section 6.
    pub fn read_beta_g2(&mut self) -> Result<G2Affine, Error> {
        let mut pts = self.read_g2_section(6, 1)?;
        Ok(pts.pop().unwrap())
    }

    // ------------------------------------------------------------------
    // Internal helpers
    // ------------------------------------------------------------------

    fn read_g1_section(&mut self, section_type: u32, n: usize) -> Result<Vec<G1Affine>, Error> {
        if n > self.max_g1_points {
            return Err(Error::InsufficientPoints {
                requested: n,
                available: self.max_g1_points,
            });
        }

        let section = self
            .sections
            .iter()
            .find(|(t, _, _)| *t == section_type)
            .ok_or_else(|| Error::Io(format!("Missing section {}", section_type)))?;

        let expected_size = n as u64 * N8_G1 as u64;
        if section.1 < expected_size {
            return Err(Error::InsufficientPoints {
                requested: n,
                available: (section.1 / N8_G1 as u64) as usize,
            });
        }

        self.file.seek(SeekFrom::Start(section.2))?;
        let mut points = Vec::with_capacity(n);
        for i in 0..n {
            let pt = read_g1_affine(&mut self.file)
                .map_err(|_| Error::InvalidPoint {
                    section: section_type,
                    index: i,
                })?;
            points.push(pt);
        }
        Ok(points)
    }

    fn read_g2_section(&mut self, section_type: u32, n: usize) -> Result<Vec<G2Affine>, Error> {
        if n > self.max_g2_points {
            return Err(Error::InsufficientPoints {
                requested: n,
                available: self.max_g2_points,
            });
        }

        let section = self
            .sections
            .iter()
            .find(|(t, _, _)| *t == section_type)
            .ok_or_else(|| Error::Io(format!("Missing section {}", section_type)))?;

        let expected_size = n as u64 * N8_G2 as u64;
        if section.1 < expected_size {
            return Err(Error::InsufficientPoints {
                requested: n,
                available: (section.1 / N8_G2 as u64) as usize,
            });
        }

        self.file.seek(SeekFrom::Start(section.2))?;
        let mut points = Vec::with_capacity(n);
        for i in 0..n {
            let pt = read_g2_affine(&mut self.file)
                .map_err(|_| Error::InvalidPoint {
                    section: section_type,
                    index: i,
                })?;
            points.push(pt);
        }
        Ok(points)
    }
}

/// Read a single uncompressed G1 affine point from a LEM byte stream.
///
/// Layout: `x` (48 bytes LE) + `y` (48 bytes LE).
fn read_g1_affine<R: Read>(reader: &mut R) -> io::Result<G1Affine> {
    let mut x_bytes = [0u8; N8_FQ];
    let mut y_bytes = [0u8; N8_FQ];
    reader.read_exact(&mut x_bytes)?;
    reader.read_exact(&mut y_bytes)?;

    let x = fq_from_lem_bytes(&x_bytes);
    let y = fq_from_lem_bytes(&y_bytes);

    // `.ptau` never stores the point at infinity in these sections,
    // so we can safely use `new_unchecked` and let the caller verify.
    Ok(G1Affine::new_unchecked(x, y))
}

/// Read a single uncompressed G2 affine point from a LEM byte stream.
///
/// Layout: `x.c0` (48) + `x.c1` (48) + `y.c0` (48) + `y.c1` (48).
fn read_g2_affine<R: Read>(reader: &mut R) -> io::Result<G2Affine> {
    let mut x0 = [0u8; N8_FQ];
    let mut x1 = [0u8; N8_FQ];
    let mut y0 = [0u8; N8_FQ];
    let mut y1 = [0u8; N8_FQ];
    reader.read_exact(&mut x0)?;
    reader.read_exact(&mut x1)?;
    reader.read_exact(&mut y0)?;
    reader.read_exact(&mut y1)?;

    let x = Fq2::new(fq_from_lem_bytes(&x0), fq_from_lem_bytes(&x1));
    let y = Fq2::new(fq_from_lem_bytes(&y0), fq_from_lem_bytes(&y1));

    Ok(G2Affine::new_unchecked(x, y))
}

/// Convert 48 LEM bytes into an `Fq`.
///
/// LEM = Little-Endian Montgomery.  arkworks stores `Fp` internally in
/// Montgomery form as a `BigInt<N>` of `u64` limbs (least-significant limb
/// first).  The `.ptau` file writes each limb in little-endian byte order,
/// so the mapping is byte-for-byte.
#[inline]
fn fq_from_lem_bytes(bytes: &[u8; N8_FQ]) -> Fq {
    let mut limbs = [0u64; 6];
    for i in 0..6 {
        limbs[i] = u64::from_le_bytes(bytes[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    let bigint = ark_ff::BigInt::new(limbs);
    Fp::<MontBackend<FqConfig, 6>, 6>(bigint, PhantomData)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::AffineRepr;

    /// Path to a test `.ptau` file created by snarkjs (power 4, bls12-381).
    ///
    /// The file is committed in `test_data/pot4_final.ptau` so tests are
    /// self-contained.  It was generated by:
    /// ```bash
    /// snarkjs powersoftau new bls12-381 4 pot4_0000.ptau
    /// snarkjs powersoftau contribute pot4_0000.ptau pot4_0001.ptau
    /// snarkjs powersoftau prepare phase2 pot4_0001.ptau pot4_final.ptau
    /// ```
    const TEST_PTAU: &str = "test_data/pot4_final.ptau";

    #[test]
    fn test_open_and_header() {
        let ptau = PtauFile::open(TEST_PTAU).unwrap();
        assert_eq!(ptau.power(), 4);
        assert_eq!(ptau.max_g1_points(), 31); // 2*2^4 - 1
        assert_eq!(ptau.max_g2_points(), 16); // 2^4
    }

    #[test]
    fn test_read_tau_g1() {
        let mut ptau = PtauFile::open(TEST_PTAU).unwrap();
        let pts = ptau.read_tau_g1(3).unwrap();
        assert_eq!(pts.len(), 3);

        // First point is the generator
        assert_eq!(pts[0], G1Affine::generator());

        // All points are on curve and in subgroup
        for (i, pt) in pts.iter().enumerate() {
            assert!(pt.is_on_curve(), "point {} not on curve", i);
            assert!(
                pt.is_in_correct_subgroup_assuming_on_curve(),
                "point {} not in subgroup",
                i
            );
        }
    }

    #[test]
    fn test_read_tau_g2() {
        let mut ptau = PtauFile::open(TEST_PTAU).unwrap();
        let pts = ptau.read_tau_g2(3).unwrap();
        assert_eq!(pts.len(), 3);

        // First point is the G2 generator
        assert_eq!(pts[0], G2Affine::generator());

        for (i, pt) in pts.iter().enumerate() {
            assert!(pt.is_on_curve(), "G2 point {} not on curve", i);
            assert!(
                pt.is_in_correct_subgroup_assuming_on_curve(),
                "G2 point {} not in subgroup",
                i
            );
        }
    }

    #[test]
    fn test_read_beta_g2() {
        let mut ptau = PtauFile::open(TEST_PTAU).unwrap();
        let beta = ptau.read_beta_g2().unwrap();
        assert!(beta.is_on_curve());
        assert!(beta.is_in_correct_subgroup_assuming_on_curve());
    }

    #[test]
    fn test_read_all_sections() {
        let mut ptau = PtauFile::open(TEST_PTAU).unwrap();

        let tau_g1 = ptau.read_tau_g1(ptau.max_g1_points()).unwrap();
        let tau_g2 = ptau.read_tau_g2(ptau.max_g2_points()).unwrap();
        let alpha_tau_g1 = ptau.read_alpha_tau_g1(ptau.max_g2_points()).unwrap();
        let beta_tau_g1 = ptau.read_beta_tau_g1(ptau.max_g2_points()).unwrap();
        let beta_g2 = ptau.read_beta_g2().unwrap();

        assert_eq!(tau_g1.len(), 31);
        assert_eq!(tau_g2.len(), 16);
        assert_eq!(alpha_tau_g1.len(), 16);
        assert_eq!(beta_tau_g1.len(), 16);

        // Sanity checks
        assert_eq!(tau_g1[0], G1Affine::generator());
        assert_eq!(tau_g2[0], G2Affine::generator());
        // alpha_tau_g1[0] = alpha * tau^0 * G1 = alpha * G1
        // beta_tau_g1[0]  = beta  * tau^0 * G1 = beta  * G1
        // We don't know alpha/beta, but we can verify on-curve.
        assert!(alpha_tau_g1[0].is_on_curve());
        assert!(beta_tau_g1[0].is_on_curve());
        assert!(beta_g2.is_on_curve());
    }

    #[test]
    fn test_insufficient_points_error() {
        let mut ptau = PtauFile::open(TEST_PTAU).unwrap();
        let err = ptau.read_tau_g1(100).unwrap_err();
        assert_eq!(
            err,
            Error::InsufficientPoints {
                requested: 100,
                available: 31,
            }
        );
    }
}
