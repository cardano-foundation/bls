//! Circom adapter — load `.r1cs` constraint systems and `.wtns` witness files.
//!
//! This module uses `nom` to parse Circom's binary formats and converts them
//! into the dynamic matrix representation used by our `QapEngine` / `Prover`
//! pipeline.

use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use ark_std::vec::Vec;
use ark_std::Zero;
use nom::{
    bytes::complete::{tag, take},
    number::complete::{le_u32, le_u64},
    IResult,
};

/// Parsed R1CS circuit from a `.r1cs` file (dense representation).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircomCircuit {
    pub field_size: u32,
    pub prime: Vec<u8>,
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prv_in: u32,
    pub n_constraints: u32,
    /// Dense L matrix (constraints × wires)
    pub l: Vec<Vec<Fr>>,
    /// Dense R matrix (constraints × wires)
    pub r: Vec<Vec<Fr>>,
    /// Dense O matrix (constraints × wires)
    pub o: Vec<Vec<Fr>>,
    /// Witness values (loaded separately from `.wtns`)
    pub witness: Vec<Fr>,
}

/// Parsed R1CS circuit from a `.r1cs` file (sparse representation).
///
/// This is the native Circom format: each constraint stores only its
/// non-zero `(wire_id, coefficient)` entries.  Memory drops from
/// `O(n_constraints × n_wires)` to `O(#non_zero_entries)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseCircomCircuit {
    pub field_size: u32,
    pub prime: Vec<u8>,
    pub n_wires: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prv_in: u32,
    pub n_constraints: u32,
    /// Sparse L matrix: per-constraint list of (wire_id, coeff)
    pub l: Vec<Vec<(u32, Fr)>>,
    /// Sparse R matrix: per-constraint list of (wire_id, coeff)
    pub r: Vec<Vec<(u32, Fr)>>,
    /// Sparse O matrix: per-constraint list of (wire_id, coeff)
    pub o: Vec<Vec<(u32, Fr)>>,
    /// Witness values (loaded separately from `.wtns`)
    pub witness: Vec<Fr>,
}

impl CircomCircuit {
    /// Load a circuit from raw `.r1cs` bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        Self::parse_r1cs(data).map_err(|e| format!("Parse error: {:?}", e))
    }

    /// Load a circuit from a `.r1cs` file path.
    pub fn from_r1cs(path: &str) -> Result<Self, String> {
        let data = std::fs::read(path).map_err(|e| format!("Failed to read {}: {}", path, e))?;
        Self::from_bytes(&data)
    }

    /// Load a witness from raw `.wtns` bytes.
    pub fn load_witness_from_bytes(
        &mut self,
        data: &[u8],
        field_size: usize,
    ) -> Result<(), String> {
        let witness =
            parse_wtns(data, field_size).map_err(|e| format!("Parse error: {:?}", e))?;
        if witness.len() != self.n_wires as usize {
            return Err(format!(
                "Witness length {} does not match n_wires {}",
                witness.len(),
                self.n_wires
            ));
        }
        self.witness = witness;
        Ok(())
    }

    /// Load a witness from a `.wtns` file path.
    pub fn load_witness(&mut self, path: &str) -> Result<(), String> {
        let data = std::fs::read(path).map_err(|e| format!("Failed to read {}: {}", path, e))?;
        self.load_witness_from_bytes(&data, self.field_size as usize)
    }

    fn parse_r1cs(data: &[u8]) -> Result<CircomCircuit, nom::Err<nom::error::Error<&[u8]>>> {
        let (header, constraints) = parse_r1cs_raw(data)?;

        let n_constraints = header.n_constraints as usize;
        let n_wires = header.n_wires as usize;

        // Convert sparse constraints to dense matrices
        let mut l = vec![vec![Fr::zero(); n_wires]; n_constraints];
        let mut r = vec![vec![Fr::zero(); n_wires]; n_constraints];
        let mut o = vec![vec![Fr::zero(); n_wires]; n_constraints];

        for (i, (a, b, c)) in constraints.iter().enumerate() {
            for &(wire, val) in a {
                l[i][wire as usize] = val;
            }
            for &(wire, val) in b {
                r[i][wire as usize] = val;
            }
            for &(wire, val) in c {
                o[i][wire as usize] = val;
            }
        }

        Ok(CircomCircuit {
            field_size: header.field_size,
            prime: header.prime.to_vec(),
            n_wires: header.n_wires,
            n_pub_out: header.n_pub_out,
            n_pub_in: header.n_pub_in,
            n_prv_in: header.n_prv_in,
            n_constraints: header.n_constraints,
            l,
            r,
            o,
            witness: Vec::new(),
        })
    }
}

impl SparseCircomCircuit {
    /// Load a sparse circuit from raw `.r1cs` bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, String> {
        Self::parse_r1cs(data).map_err(|e| format!("Parse error: {:?}", e))
    }

    /// Load a sparse circuit from a `.r1cs` file path.
    pub fn from_r1cs(path: &str) -> Result<Self, String> {
        let data = std::fs::read(path).map_err(|e| format!("Failed to read {}: {}", path, e))?;
        Self::from_bytes(&data)
    }

    /// Load a witness from raw `.wtns` bytes.
    pub fn load_witness_from_bytes(
        &mut self,
        data: &[u8],
        field_size: usize,
    ) -> Result<(), String> {
        let witness =
            parse_wtns(data, field_size).map_err(|e| format!("Parse error: {:?}", e))?;
        if witness.len() != self.n_wires as usize {
            return Err(format!(
                "Witness length {} does not match n_wires {}",
                witness.len(),
                self.n_wires
            ));
        }
        self.witness = witness;
        Ok(())
    }

    /// Load a witness from a `.wtns` file path.
    pub fn load_witness(&mut self, path: &str) -> Result<(), String> {
        let data = std::fs::read(path).map_err(|e| format!("Failed to read {}: {}", path, e))?;
        self.load_witness_from_bytes(&data, self.field_size as usize)
    }

    fn parse_r1cs(data: &[u8]) -> Result<SparseCircomCircuit, nom::Err<nom::error::Error<&[u8]>>> {
        let (header, constraints) = parse_r1cs_raw(data)?;

        Ok(SparseCircomCircuit {
            field_size: header.field_size,
            prime: header.prime.to_vec(),
            n_wires: header.n_wires,
            n_pub_out: header.n_pub_out,
            n_pub_in: header.n_pub_in,
            n_prv_in: header.n_prv_in,
            n_constraints: header.n_constraints,
            l: constraints.iter().map(|(a, _, _)| a.clone()).collect(),
            r: constraints.iter().map(|(_, b, _)| b.clone()).collect(),
            o: constraints.iter().map(|(_, _, c)| c.clone()).collect(),
            witness: Vec::new(),
        })
    }
}

// ------------------------------------------------------------------
// .r1cs parser helpers (nom)
// ------------------------------------------------------------------

/// Parse the file-level magic + version + section count.
fn parse_r1cs_header(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, _) = tag(b"r1cs")(input)?;
    let (input, _version) = le_u32(input)?;
    let (input, _n_sections) = le_u32(input)?;
    Ok((input, ()))
}

#[derive(Debug)]
struct R1csHeader {
    field_size: u32,
    prime: Vec<u8>,
    n_wires: u32,
    n_pub_out: u32,
    n_pub_in: u32,
    n_prv_in: u32,
    _n_labels: u64,
    n_constraints: u32,
}

fn parse_header_section(input: &[u8]) -> IResult<&[u8], R1csHeader> {
    let (input, field_size) = le_u32(input)?;
    let (input, prime) = take(field_size as usize)(input)?;
    let (input, n_wires) = le_u32(input)?;
    let (input, n_pub_out) = le_u32(input)?;
    let (input, n_pub_in) = le_u32(input)?;
    let (input, n_prv_in) = le_u32(input)?;
    let (input, _n_labels) = le_u64(input)?;
    let (input, n_constraints) = le_u32(input)?;
    Ok((
        input,
        R1csHeader {
            field_size,
            prime: prime.to_vec(),
            n_wires,
            n_pub_out,
            n_pub_in,
            n_prv_in,
            _n_labels,
            n_constraints,
        },
    ))
}

/// One constraint is three sparse vectors (A, B, C).
type Constraint = (Vec<(u32, Fr)>, Vec<(u32, Fr)>, Vec<(u32, Fr)>);

/// Parse raw `.r1cs` bytes into header + sparse constraints.
/// Shared by both `CircomCircuit` (dense) and `SparseCircomCircuit` (sparse).
fn parse_r1cs_raw(data: &[u8]) -> Result<(R1csHeader, Vec<Constraint>), nom::Err<nom::error::Error<&[u8]>>> {
    let (rest, _) = parse_r1cs_header(data)?;

    let mut header: Option<R1csHeader> = None;
    let mut constraints: Option<Vec<Constraint>> = None;

    let mut rest = rest;
    while !rest.is_empty() {
        let (r, section_type) = le_u32(rest)?;
        let (r, section_size) = le_u64(r)?;
        let section_size = section_size as usize;
        let (r, section_data) = take(section_size)(r)?;

        match section_type {
            1 => {
                let (_, h) = parse_header_section(section_data)?;
                header = Some(h);
            }
            2 => {
                let (_, c) = parse_constraints_section(section_data)?;
                constraints = Some(c);
            }
            _ => {} // skip unknown sections
        }
        rest = r;
    }

    let header = header.ok_or_else(|| {
        nom::Err::Error(nom::error::Error::new(data, nom::error::ErrorKind::Tag))
    })?;
    let constraints = constraints.ok_or_else(|| {
        nom::Err::Error(nom::error::Error::new(data, nom::error::ErrorKind::Tag))
    })?;

    Ok((header, constraints))
}

fn parse_constraints_section(input: &[u8]) -> IResult<&[u8], Vec<Constraint>> {
    // The section size tells us how many bytes, but we parse until exhausted.
    let mut rest = input;
    let mut constraints = Vec::new();
    while !rest.is_empty() {
        let (r, a) = parse_sparse_vector(rest)?;
        let (r, b) = parse_sparse_vector(r)?;
        let (r, c) = parse_sparse_vector(r)?;
        constraints.push((a, b, c));
        rest = r;
    }
    Ok((&[], constraints))
}

fn parse_sparse_vector(input: &[u8]) -> IResult<&[u8], Vec<(u32, Fr)>> {
    let (input, n_terms) = le_u32(input)?;
    let mut rest = input;
    let mut terms = Vec::with_capacity(n_terms as usize);
    for _ in 0..n_terms {
        let (r, wire) = le_u32(rest)?;
        // In Circom .r1cs, values are stored as 32-byte field elements (BLS12-381).
        let field_size = 32usize;
        let (r, val_bytes) = take(field_size)(r)?;
        let val = parse_field_element(val_bytes);
        rest = r;
        terms.push((wire, val));
    }
    Ok((rest, terms))
}

/// Parse a 32-byte BLS12-381 field element into `Fr`.
fn parse_field_element(bytes: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

// ------------------------------------------------------------------
// .wtns parser helpers (nom)
// ------------------------------------------------------------------

fn parse_wtns_header(input: &[u8]) -> IResult<&[u8], ()> {
    let (input, _) = tag(b"wtns")(input)?;
    let (input, _version) = le_u32(input)?;
    let (input, _n_sections) = le_u32(input)?;
    Ok((input, ()))
}

fn parse_wtns(
    data: &[u8],
    field_size: usize,
) -> Result<Vec<Fr>, nom::Err<nom::error::Error<&[u8]>>> {
    let (rest, _) = parse_wtns_header(data)?;

    let mut witness = Vec::new();
    let mut rest = rest;
    while !rest.is_empty() {
        let (r, section_type) = le_u32(rest)?;
        let (r, section_size) = le_u64(r)?;
        let section_size = section_size as usize;
        let (r, section_data) = take(section_size)(r)?;

        if section_type == 2 {
            // Witness data section
            let n_wires = section_data.len() / field_size;
            let mut srest = section_data;
            for _ in 0..n_wires {
                let (sr, val_bytes) = take(field_size)(srest)?;
                let val = Fr::from_le_bytes_mod_order(val_bytes);
                witness.push(val);
                srest = sr;
            }
        }
        rest = r;
    }
    Ok(witness)
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::{L, O, R, WITNESS};

    /// Build a synthetic `.r1cs`-style byte stream for our 3-constraint,
    /// 8-wire circuit. All non-zero coefficients are 1.
    fn build_synthetic_r1cs() -> Vec<u8> {
        let mut out = Vec::new();
        // File header
        out.extend_from_slice(b"r1cs");
        out.extend_from_slice(&1u32.to_le_bytes()); // version
        out.extend_from_slice(&2u32.to_le_bytes()); // n_sections

        // Section 1: Header
        let field_size = 32u32;
        let n_wires = 8u32;
        let n_pub_out = 1u32;
        let n_pub_in = 0u32;
        let n_prv_in = 4u32;
        let n_labels = 8u64;
        let n_constraints = 3u32;

        let mut header = Vec::new();
        header.extend_from_slice(&field_size.to_le_bytes());
        header.extend_from_slice(&[0u8; 32]); // prime placeholder
        header.extend_from_slice(&n_wires.to_le_bytes());
        header.extend_from_slice(&n_pub_out.to_le_bytes());
        header.extend_from_slice(&n_pub_in.to_le_bytes());
        header.extend_from_slice(&n_prv_in.to_le_bytes());
        header.extend_from_slice(&n_labels.to_le_bytes());
        header.extend_from_slice(&n_constraints.to_le_bytes());

        out.extend_from_slice(&1u32.to_le_bytes()); // section type
        out.extend_from_slice(&(header.len() as u64).to_le_bytes());
        out.extend_from_slice(&header);

        // Section 2: Constraints (sparse)
        // Constraint 0: x1 * x2 = x5  →  L[2]=1, R[3]=1, O[6]=1
        // Constraint 1: x3 * x4 = x6  →  L[4]=1, R[5]=1, O[7]=1
        // Constraint 2: x5 * x6 = a   →  L[6]=1, R[7]=1, O[1]=1
        let mut constraints = Vec::new();

        // Helper: write a sparse vector with given (wire, val=1) pairs
        let mut write_vec = |terms: &[(u32, u64)]| {
            constraints.extend_from_slice(&(terms.len() as u32).to_le_bytes());
            for &(w, v) in terms {
                constraints.extend_from_slice(&w.to_le_bytes());
                // value = 1, padded to field_size bytes
                constraints.push(v as u8);
                constraints.extend_from_slice(&vec![0u8; field_size as usize - 1]);
            }
        };

        // Constraint 0
        write_vec(&[(2, 1)]); // A
        write_vec(&[(3, 1)]); // B
        write_vec(&[(6, 1)]); // C

        // Constraint 1
        write_vec(&[(4, 1)]); // A
        write_vec(&[(5, 1)]); // B
        write_vec(&[(7, 1)]); // C

        // Constraint 2
        write_vec(&[(6, 1)]); // A
        write_vec(&[(7, 1)]); // B
        write_vec(&[(1, 1)]); // C

        out.extend_from_slice(&2u32.to_le_bytes()); // section type
        out.extend_from_slice(&(constraints.len() as u64).to_le_bytes());
        out.extend_from_slice(&constraints);

        out
    }

    fn build_synthetic_wtns() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"wtns");
        out.extend_from_slice(&1u32.to_le_bytes()); // version
        out.extend_from_slice(&2u32.to_le_bytes()); // n_sections

        // Section 1: Header
        let field_size = 32u32;
        let n_wires = 8u32;
        let mut header = Vec::new();
        header.extend_from_slice(&field_size.to_le_bytes());
        header.extend_from_slice(&[0u8; 32]);
        header.extend_from_slice(&n_wires.to_le_bytes());

        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&(header.len() as u64).to_le_bytes());
        out.extend_from_slice(&header);

        // Section 2: Witness data
        let witness = vec![1u64, 48, 2, 2, 3, 4, 4, 12];
        let mut data = Vec::new();
        for &v in &witness {
            data.push(v as u8);
            data.extend_from_slice(&vec![0u8; field_size as usize - 1]);
        }

        out.extend_from_slice(&2u32.to_le_bytes());
        out.extend_from_slice(&(data.len() as u64).to_le_bytes());
        out.extend_from_slice(&data);

        out
    }

    #[test]
    fn test_parse_synthetic_r1cs() {
        let bytes = build_synthetic_r1cs();
        let circuit = CircomCircuit::parse_r1cs(&bytes).unwrap();

        assert_eq!(circuit.n_wires, 8);
        assert_eq!(circuit.n_constraints, 3);
        assert_eq!(circuit.l.len(), 3);
        assert_eq!(circuit.l[0].len(), 8);

        // Compare against hard-coded matrices
        for j in 0..3 {
            for i in 0..8 {
                assert_eq!(
                    circuit.l[j][i],
                    Fr::from(L[j][i]),
                    "L[{}][{}] mismatch",
                    j,
                    i
                );
                assert_eq!(
                    circuit.r[j][i],
                    Fr::from(R[j][i]),
                    "R[{}][{}] mismatch",
                    j,
                    i
                );
                assert_eq!(
                    circuit.o[j][i],
                    Fr::from(O[j][i]),
                    "O[{}][{}] mismatch",
                    j,
                    i
                );
            }
        }
    }

    #[test]
    fn test_parse_synthetic_wtns() {
        let bytes = build_synthetic_wtns();
        let witness = parse_wtns(&bytes, 32).unwrap();
        let expected: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();
        assert_eq!(witness, expected);
    }

    #[test]
    fn test_circom_circuit_roundtrip() {
        let r1cs_bytes = build_synthetic_r1cs();
        let wtns_bytes = build_synthetic_wtns();

        let mut circuit = CircomCircuit::parse_r1cs(&r1cs_bytes).unwrap();
        circuit.load_witness_from_bytes(&wtns_bytes, 32).unwrap();

        let expected: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();
        assert_eq!(circuit.witness, expected);
    }

    /// Implementation 5 parity: Circom-loaded circuit + FullProvingKey must
    /// produce the same proof as the legacy scalar path.
    #[test]
    fn test_circom_full_pk_matches_scalar_path() {
        use crate::ceremony::{single_party_ceremony_full_from_tw, ToxicWaste};
        use crate::engine::FftQapEngine;
        use crate::prover::{NaiveProver, PippengerProver, Prover};

        let r1cs_bytes = build_synthetic_r1cs();
        let wtns_bytes = build_synthetic_wtns();

        let mut circuit = CircomCircuit::parse_r1cs(&r1cs_bytes).unwrap();
        circuit.load_witness_from_bytes(&wtns_bytes, 32).unwrap();

        let engine = FftQapEngine::new();
        let tw = ToxicWaste::deterministic();
        // Circom witness ordering: constant (1), public outputs, public inputs, private inputs, intermediates.
        // Synthetic circuit: n_pub_out = 1, n_pub_in = 0, n_prv_in = 4, plus 2 intermediates = 8 wires.
        let n_public = 1 + circuit.n_pub_out as usize + circuit.n_pub_in as usize;

        // Legacy scalar path
        let naive = NaiveProver::new();
        let (proof_scalar, public_scalar) = naive.prove(
            &engine,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            &circuit.witness,
            tw.tau,
            tw.alpha,
            tw.beta,
            tw.gamma,
            tw.delta,
        );

        // New FullProvingKey path (on-the-fly QAP construction)
        let (full_pk, _vk) = single_party_ceremony_full_from_tw(
            &engine, &circuit.l, &circuit.r, &circuit.o, n_public, tw,
        );
        let (proof_full, public_full) = naive.prove_with_full_pk(
            &engine,
            &full_pk,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            &circuit.witness,
        );

        assert_eq!(
            proof_scalar.a, proof_full.a,
            "A must match between scalar and FullPK path"
        );
        assert_eq!(
            proof_scalar.b, proof_full.b,
            "B must match between scalar and FullPK path"
        );
        assert_eq!(
            proof_scalar.c, proof_full.c,
            "C must match between scalar and FullPK path"
        );
        assert_eq!(
            public_scalar.v, public_full.v,
            "V must match between scalar and FullPK path"
        );

        // Pippenger prover on the FullPK path must also match
        let pippenger = PippengerProver::new();
        let (proof_pipp, public_pipp) = pippenger.prove_with_full_pk(
            &engine,
            &full_pk,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            &circuit.witness,
        );
        assert_eq!(
            proof_full.a, proof_pipp.a,
            "A must match between naive and Pippenger FullPK"
        );
        assert_eq!(
            proof_full.b, proof_pipp.b,
            "B must match between naive and Pippenger FullPK"
        );
        assert_eq!(
            proof_full.c, proof_pipp.c,
            "C must match between naive and Pippenger FullPK"
        );
        assert_eq!(
            public_full.v, public_pipp.v,
            "V must match between naive and Pippenger FullPK"
        );
    }

    // ------------------------------------------------------------------
    // Implementation 6 parity: sparse vs dense
    // ------------------------------------------------------------------

    #[test]
    fn test_sparse_parse_matches_dense() {
        let bytes = build_synthetic_r1cs();
        let dense = CircomCircuit::parse_r1cs(&bytes).unwrap();
        let sparse = SparseCircomCircuit::parse_r1cs(&bytes).unwrap();

        assert_eq!(dense.n_wires, sparse.n_wires);
        assert_eq!(dense.n_constraints, sparse.n_constraints);
        assert_eq!(dense.n_pub_out, sparse.n_pub_out);
        assert_eq!(dense.n_pub_in, sparse.n_pub_in);
        assert_eq!(dense.n_prv_in, sparse.n_prv_in);

        // Verify every non-zero sparse entry matches the dense matrix
        for c in 0..dense.n_constraints as usize {
            for &(wire, coeff) in &sparse.l[c] {
                assert_eq!(dense.l[c][wire as usize], coeff, "sparse L[{}][{}] mismatch", c, wire);
            }
            for &(wire, coeff) in &sparse.r[c] {
                assert_eq!(dense.r[c][wire as usize], coeff, "sparse R[{}][{}] mismatch", c, wire);
            }
            for &(wire, coeff) in &sparse.o[c] {
                assert_eq!(dense.o[c][wire as usize], coeff, "sparse O[{}][{}] mismatch", c, wire);
            }
        }

        // Verify dense zeros are not present in sparse
        for c in 0..dense.n_constraints as usize {
            for i in 0..dense.n_wires as usize {
                if dense.l[c][i] != Fr::zero() {
                    assert!(sparse.l[c].iter().any(|(w, _)| *w == i as u32), "missing sparse L[{}][{}]", c, i);
                }
                if dense.r[c][i] != Fr::zero() {
                    assert!(sparse.r[c].iter().any(|(w, _)| *w == i as u32), "missing sparse R[{}][{}]", c, i);
                }
                if dense.o[c][i] != Fr::zero() {
                    assert!(sparse.o[c].iter().any(|(w, _)| *w == i as u32), "missing sparse O[{}][{}]", c, i);
                }
            }
        }
    }

    #[test]
    fn test_sparse_ceremony_matches_dense() {
        use crate::ceremony::{single_party_ceremony_full_from_tw, single_party_ceremony_full_from_tw_sparse, ToxicWaste};
        use crate::engine::FftQapEngine;

        let bytes = build_synthetic_r1cs();
        let dense = CircomCircuit::parse_r1cs(&bytes).unwrap();
        let sparse = SparseCircomCircuit::parse_r1cs(&bytes).unwrap();

        let engine = FftQapEngine::new();
        let tw = ToxicWaste::deterministic();
        let n_public = 1 + dense.n_pub_out as usize + dense.n_pub_in as usize;

        let (pk_dense, vk_dense) = single_party_ceremony_full_from_tw(
            &engine, &dense.l, &dense.r, &dense.o, n_public, tw.clone(),
        );
        let (pk_sparse, vk_sparse) = single_party_ceremony_full_from_tw_sparse(
            &engine,
            dense.n_constraints as usize,
            dense.n_wires as usize,
            n_public,
            &sparse.l,
            &sparse.r,
            &sparse.o,
            tw,
        );

        assert_eq!(vk_dense.alpha_g1, vk_sparse.alpha_g1, "VK alpha_g1 mismatch");
        assert_eq!(vk_dense.beta_g2, vk_sparse.beta_g2, "VK beta_g2 mismatch");
        assert_eq!(vk_dense.gamma_g2, vk_sparse.gamma_g2, "VK gamma_g2 mismatch");
        assert_eq!(vk_dense.delta_g2, vk_sparse.delta_g2, "VK delta_g2 mismatch");
        assert_eq!(vk_dense.ic, vk_sparse.ic, "VK ic mismatch");
        assert_eq!(vk_dense.n_public, vk_sparse.n_public, "VK n_public mismatch");

        assert_eq!(pk_dense.a_query, pk_sparse.a_query, "PK a_query mismatch");
        assert_eq!(pk_dense.b_g1_query, pk_sparse.b_g1_query, "PK b_g1_query mismatch");
        assert_eq!(pk_dense.b_g2_query, pk_sparse.b_g2_query, "PK b_g2_query mismatch");
        assert_eq!(pk_dense.c_query, pk_sparse.c_query, "PK c_query mismatch");
        assert_eq!(pk_dense.h_query, pk_sparse.h_query, "PK h_query mismatch");
        assert_eq!(pk_dense.l_query, pk_sparse.l_query, "PK l_query mismatch");
    }

    #[test]
    fn test_sparse_prover_matches_dense_naive() {
        use crate::ceremony::{single_party_ceremony_full_from_tw, single_party_ceremony_full_from_tw_sparse, ToxicWaste};
        use crate::engine::FftQapEngine;
        use crate::prover::{NaiveProver, Prover};

        let r1cs_bytes = build_synthetic_r1cs();
        let wtns_bytes = build_synthetic_wtns();

        let mut dense = CircomCircuit::parse_r1cs(&r1cs_bytes).unwrap();
        dense.load_witness_from_bytes(&wtns_bytes, 32).unwrap();
        let mut sparse = SparseCircomCircuit::parse_r1cs(&r1cs_bytes).unwrap();
        sparse.load_witness_from_bytes(&wtns_bytes, 32).unwrap();

        let engine = FftQapEngine::new();
        let tw = ToxicWaste::deterministic();
        let n_public = 1 + dense.n_pub_out as usize + dense.n_pub_in as usize;

        let (pk_dense, _) = single_party_ceremony_full_from_tw(
            &engine, &dense.l, &dense.r, &dense.o, n_public, tw.clone(),
        );
        let (pk_sparse, _) = single_party_ceremony_full_from_tw_sparse(
            &engine,
            dense.n_constraints as usize,
            dense.n_wires as usize,
            n_public,
            &sparse.l,
            &sparse.r,
            &sparse.o,
            tw,
        );

        let prover = NaiveProver::new();

        let (proof_dense, public_dense) = prover.prove_with_full_pk(
            &engine, &pk_dense, &dense.l, &dense.r, &dense.o, &dense.witness,
        );
        let (proof_sparse, public_sparse) = prover.prove_with_full_pk_sparse(
            &engine, &pk_sparse,
            dense.n_constraints as usize,
            &sparse.l, &sparse.r, &sparse.o,
            &sparse.witness,
        );

        assert_eq!(proof_dense.a, proof_sparse.a, "A mismatch sparse vs dense");
        assert_eq!(proof_dense.b, proof_sparse.b, "B mismatch sparse vs dense");
        assert_eq!(proof_dense.c, proof_sparse.c, "C mismatch sparse vs dense");
        assert_eq!(public_dense.v, public_sparse.v, "V mismatch sparse vs dense");
    }

    #[test]
    fn test_sparse_prover_matches_dense_pippenger() {
        use crate::ceremony::{single_party_ceremony_full_from_tw, single_party_ceremony_full_from_tw_sparse, ToxicWaste};
        use crate::engine::FftQapEngine;
        use crate::prover::{PippengerProver, Prover};

        let r1cs_bytes = build_synthetic_r1cs();
        let wtns_bytes = build_synthetic_wtns();

        let mut dense = CircomCircuit::parse_r1cs(&r1cs_bytes).unwrap();
        dense.load_witness_from_bytes(&wtns_bytes, 32).unwrap();
        let mut sparse = SparseCircomCircuit::parse_r1cs(&r1cs_bytes).unwrap();
        sparse.load_witness_from_bytes(&wtns_bytes, 32).unwrap();

        let engine = FftQapEngine::new();
        let tw = ToxicWaste::deterministic();
        let n_public = 1 + dense.n_pub_out as usize + dense.n_pub_in as usize;

        let (pk_dense, _) = single_party_ceremony_full_from_tw(
            &engine, &dense.l, &dense.r, &dense.o, n_public, tw.clone(),
        );
        let (pk_sparse, _) = single_party_ceremony_full_from_tw_sparse(
            &engine,
            dense.n_constraints as usize,
            dense.n_wires as usize,
            n_public,
            &sparse.l,
            &sparse.r,
            &sparse.o,
            tw,
        );

        let prover = PippengerProver::new();

        let (proof_dense, public_dense) = prover.prove_with_full_pk(
            &engine, &pk_dense, &dense.l, &dense.r, &dense.o, &dense.witness,
        );
        let (proof_sparse, public_sparse) = prover.prove_with_full_pk_sparse(
            &engine, &pk_sparse,
            dense.n_constraints as usize,
            &sparse.l, &sparse.r, &sparse.o,
            &sparse.witness,
        );

        assert_eq!(proof_dense.a, proof_sparse.a, "A mismatch sparse vs dense (Pippenger)");
        assert_eq!(proof_dense.b, proof_sparse.b, "B mismatch sparse vs dense (Pippenger)");
        assert_eq!(proof_dense.c, proof_sparse.c, "C mismatch sparse vs dense (Pippenger)");
        assert_eq!(public_dense.v, public_sparse.v, "V mismatch sparse vs dense (Pippenger)");
    }

    #[test]
    fn test_sparse_prover_produces_valid_proof() {
        use crate::ceremony::{single_party_ceremony_full_from_tw_sparse, ToxicWaste};
        use crate::engine::FftQapEngine;
        use crate::prover::{PippengerProver, Prover};
        use crate::ceremony::verify_with_vk;

        let r1cs_bytes = build_synthetic_r1cs();
        let wtns_bytes = build_synthetic_wtns();

        let mut sparse = SparseCircomCircuit::parse_r1cs(&r1cs_bytes).unwrap();
        sparse.load_witness_from_bytes(&wtns_bytes, 32).unwrap();

        let engine = FftQapEngine::new();
        let tw = ToxicWaste::deterministic();
        let n_public = 1 + sparse.n_pub_out as usize + sparse.n_pub_in as usize;

        let (pk_sparse, vk_sparse) = single_party_ceremony_full_from_tw_sparse(
            &engine,
            sparse.n_constraints as usize,
            sparse.n_wires as usize,
            n_public,
            &sparse.l,
            &sparse.r,
            &sparse.o,
            tw,
        );

        let prover = PippengerProver::new();
        let (proof, public_input) = prover.prove_with_full_pk_sparse(
            &engine, &pk_sparse,
            sparse.n_constraints as usize,
            &sparse.l, &sparse.r, &sparse.o,
            &sparse.witness,
        );

        assert!(
            verify_with_vk(&proof, &public_input, &vk_sparse),
            "Sparse prover must produce a valid proof"
        );
    }
}
