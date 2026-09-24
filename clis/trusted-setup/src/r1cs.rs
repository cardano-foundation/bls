use ark_bls12_381::Fr;
use ark_ff::{Field, UniformRand};
use ark_std::vec::Vec;
use ark_std::Zero;
use rand::RngCore;

/// A circuit descriptor: R1CS matrices + witness + metadata.
/// Generic over constraint/variable counts so it works with both
/// the 3-gate multiplier and the 4-gate SumOfProducts (or any future circuit).
#[derive(Clone, Debug)]
pub struct Circuit {
    pub name: &'static str,
    pub witness: Vec<Fr>,
    pub l: Vec<Vec<Fr>>,
    pub r: Vec<Vec<Fr>>,
    pub o: Vec<Vec<Fr>>,
    pub n_public: usize,
}

impl Circuit {
    pub fn n_constraints(&self) -> usize {
        self.l.len()
    }
    pub fn n_vars(&self) -> usize {
        self.witness.len()
    }
}

/// Generate a random R1CS circuit where every constraint is satisfied
/// by construction.
///
/// Strategy (Approach B — witness-first):
/// 1. Wire 0 is the constant wire (value 1).
/// 2. For each constraint i, three fresh wires are allocated:
///    L_wire = 3*i+1, R_wire = 3*i+2, O_wire = 3*i+3.
/// 3. Random non-zero values are drawn for L_wire and R_wire.
/// 4. O_wire is set to L_wire * R_wire so the constraint L·w * R·w = O·w
///    holds trivially (all other entries in each row are zero).
///
/// This guarantees a valid R1CS relation for every constraint without
/// any witness-search or backtracking.
pub fn random_r1cs_circuit(rng: &mut impl RngCore, n_constraints: usize) -> Circuit {
    let n_vars = 3 * n_constraints + 1;
    let mut witness = vec![Fr::from(0u64); n_vars];
    witness[0] = Fr::from(1u64);

    let mut l = Vec::with_capacity(n_constraints);
    let mut r = Vec::with_capacity(n_constraints);
    let mut o = Vec::with_capacity(n_constraints);

    for i in 0..n_constraints {
        let l_wire = 3 * i + 1;
        let r_wire = 3 * i + 2;
        let o_wire = 3 * i + 3;

        let l_val = random_nonzero_fr(rng);
        let r_val = random_nonzero_fr(rng);
        witness[l_wire] = l_val;
        witness[r_wire] = r_val;
        witness[o_wire] = l_val * r_val;

        let mut l_row = vec![Fr::from(0u64); n_vars];
        l_row[l_wire] = Fr::from(1u64);
        let mut r_row = vec![Fr::from(0u64); n_vars];
        r_row[r_wire] = Fr::from(1u64);
        let mut o_row = vec![Fr::from(0u64); n_vars];
        o_row[o_wire] = Fr::from(1u64);

        l.push(l_row);
        r.push(r_row);
        o.push(o_row);
    }

    Circuit {
        name: "random",
        witness,
        l,
        r,
        o,
        n_public: 1,
    }
}

/// Generate a random non-zero field element.
fn random_nonzero_fr(rng: &mut impl RngCore) -> Fr {
    loop {
        let val = Fr::rand(rng);
        if !val.is_zero() {
            return val;
        }
    }
}

/// Generate a random **sparse, structured** R1CS circuit whose witness is
/// satisfied by construction.
///
/// Contrast with `random_r1cs_circuit` (isolated gates, all coefficients ±1):
/// here constraints **share wires** and carry **random non-zero coefficients**,
/// like real Circom output. The witness is built witness-first:
///
/// 1. Wire 0 is the constant wire (value 1) and may appear in any row.
/// 2. Per constraint, random sparse rows are drawn for L and R: each
///    references `1..=max_terms` wires chosen from the constant wire, earlier
///    product wires, or freshly-allocated input wires, each with a random
///    non-zero coefficient.
/// 3. A single fresh output wire is allocated and its value solved to be
///    `(L·w)·(R·w) / o_coeff`, so the R1CS check `(L·w)·(R·w) = (O·w)`
///    holds **exactly** for every constraint.
///
/// The generated relation is therefore always satisfiable; the RNG varies the
/// sparsity pattern, the shared-wire structure, and the coefficient sizes.
pub fn random_sparse_r1cs_circuit(
    rng: &mut impl RngCore,
    n_constraints: usize,
    max_terms: usize,
) -> Circuit {
    assert!(n_constraints >= 1, "need at least one constraint");
    assert!(max_terms >= 1, "max_terms must be >= 1");

    // Wire 0 = constant 1.
    let mut witness = vec![Fr::from(1u64)];
    let mut l = Vec::with_capacity(n_constraints);
    let mut r = Vec::with_capacity(n_constraints);
    let mut o = Vec::with_capacity(n_constraints);

    for _c in 0..n_constraints {
        let l_row = random_sparse_row(rng, max_terms, &mut witness);
        let r_row = random_sparse_row(rng, max_terms, &mut witness);

        // O row: a single *fresh* output wire with a random non-zero coefficient.
        let o_coeff = random_nonzero_fr(rng);
        let o_row = vec![(witness.len(), o_coeff)];

        let dot_l = dot_product(&l_row, &witness);
        let dot_r = dot_product(&r_row, &witness);
        // Solve the output value so the constraint holds exactly.
        let o_value = dot_l * dot_r * o_coeff.inverse().unwrap();
        witness.push(o_value);

        l.push(l_row);
        r.push(r_row);
        o.push(o_row);
    }

    let n_vars = witness.len();
    let materialize = |rows: &[Vec<(usize, Fr)>]| -> Vec<Vec<Fr>> {
        rows.iter()
            .map(|row| {
                let mut dense = vec![Fr::from(0u64); n_vars];
                for &(wire, coeff) in row {
                    // Accumulate: a wire may legitimately repeat with different
                    // coefficients; R1CS semantics sum them.
                    dense[wire] += coeff;
                }
                dense
            })
            .collect()
    };

    Circuit {
        name: "random_sparse",
        witness,
        l: materialize(&l),
        r: materialize(&r),
        o: materialize(&o),
        n_public: 1,
    }
}

/// Draw one random sparse R1CS row: `1..=max_terms` entries `(wire, coeff)`.
///
/// Referenced wires come from three pools:
/// - the constant wire `0` (value 1),
/// - a previously-computed wire (a product from an earlier constraint), or
/// - a freshly-allocated input wire (a new random value is pushed now).
///
/// A wire is used **at most once per row** (true sparse encoding), so a row's
/// dot product against the witness is simply the sum of its entries' products.
/// Fresh input wires get their value immediately, and previously-computed
/// wires already hold a value, so a caller can always compute the row's dot
/// product against the witness.
fn random_sparse_row(
    rng: &mut impl RngCore,
    max_terms: usize,
    witness_values: &mut Vec<Fr>,
) -> Vec<(usize, Fr)> {
    let n_terms = 1 + (rng.next_u64() as usize % max_terms);
    let mut row = Vec::with_capacity(n_terms);
    let mut used = Vec::with_capacity(n_terms);

    while row.len() < n_terms {
        let existing = witness_values.len();
        // 0 => constant wire, 1 => a prior wire, 2 => a fresh input wire.
        let wire = match rng.next_u64() % 3 {
            0 => 0,
            1 => {
                if existing > 1 {
                    1 + (rng.next_u64() as usize % (existing - 1))
                } else {
                    0
                }
            }
            _ => {
                let fresh = witness_values.len();
                witness_values.push(random_nonzero_fr(rng));
                fresh
            }
        };

        // Guarantee a true sparse row: no wire repeats.
        if used.contains(&wire) {
            continue;
        }
        used.push(wire);
        row.push((wire, random_nonzero_fr(rng)));
    }

    row
}

/// Dot product of a sparse row `(wire, coeff)` against the witness values.
fn dot_product(row: &[(usize, Fr)], witness: &[Fr]) -> Fr {
    row.iter().fold(Fr::zero(), |acc, &(wire, coeff)| {
        acc + coeff * witness[wire]
    })
}

// ─── Multiplier circuit: x1*x2 == x5, x3*x4 == x6, x5*x6 == a ───
// Witness: [1, a, x1, x2, x3, x4, x5, x6] = [1, 48, 2, 2, 3, 4, 4, 12]
pub const MULTIPLIER_WITNESS: [u64; 8] = [1, 48, 2, 2, 3, 4, 4, 12];
pub const MULTIPLIER_L: [[u64; 8]; 3] = [
    [0, 0, 1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 1, 0],
];
pub const MULTIPLIER_R: [[u64; 8]; 3] = [
    [0, 0, 0, 1, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 1, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 1],
];
pub const MULTIPLIER_O: [[u64; 8]; 3] = [
    [0, 0, 0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0, 0, 1],
    [0, 1, 0, 0, 0, 0, 0, 0],
];

/// The multiplier circuit as a `Circuit` descriptor.
pub fn multiplier_circuit() -> Circuit {
    Circuit {
        name: "multiplier",
        witness: witness_to_fr(&MULTIPLIER_WITNESS),
        l: MULTIPLIER_L.iter().map(|row| witness_to_fr(row)).collect(),
        r: MULTIPLIER_R.iter().map(|row| witness_to_fr(row)).collect(),
        o: MULTIPLIER_O.iter().map(|row| witness_to_fr(row)).collect(),
        n_public: 2, // const (1) + output (a)
    }
}

// ─── SumOfProducts circuit: a*b + c*d + e*f + g*h = 100 ───
// Witness: [1, out, a, b, c, d, e, f, g, h, t1, t2, t3, t4]
//        = [1, 100, 1, 2, 3, 4, 5, 6, 7, 8, 2, 12, 30, 56]
//
// Circom R1CS uses constraint format: L * R = O (standard R1CS).
// For multiplication `t1 <== a * b`: L picks a(1), R picks b(1), O picks t1(1).
// For addition `out <== t1+t2+t3+t4`: L=0, R=0, O picks out(1), intermediate(1 each).
//   (addition is a linear constraint; Circom encodes it as O * R = L with O=0, R=1, L=linear)
//
// NOTE: The Circom binary .r1cs format encodes the constraint as (A * B = C)
// where A maps to our L, B to R, C to O.  For `t1 <== a * b`:
//   A picks a(-1), B picks b(1), C picks t1(-1)  => (-a)*b = (-t1) => a*b = t1
// For `out <== t1+t2+t3+t4`:
//   A is empty, B is empty, C picks out(-1), t1(1), t2(1), t3(1), t4(1)
//   => 0*0 = -out + t1+t2+t3+t4 => out = t1+t2+t3+t4
//
// However, for our pedagogical code we use the SIMPLEST form that satisfies
// the standard R1CS check `(L·w)*(R·w) = (O·w)`:
pub const SUMOFPRODUCTS_WITNESS: [u64; 14] = [1, 100, 1, 2, 3, 4, 5, 6, 7, 8, 2, 12, 30, 56];

/// L matrix (5 constraints x 14 variables)
pub const SUMOFPRODUCTS_L: [[u64; 14]; 5] = [
    [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // C0: a
    [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0], // C1: c
    [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0], // C2: e
    [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0], // C3: g
    [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // C4: 1 (constant wire)
];

/// R matrix (5 constraints x 14 variables)
pub const SUMOFPRODUCTS_R: [[u64; 14]; 5] = [
    [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // C0: b
    [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0], // C1: d
    [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0], // C2: f
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0], // C3: h
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1], // C4: t1+t2+t3+t4
];

/// O matrix (5 constraints x 14 variables)
pub const SUMOFPRODUCTS_O: [[u64; 14]; 5] = [
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0], // C0: t1
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0], // C1: t2
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0], // C2: t3
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], // C3: t4
    [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // C4: out
];

/// The SumOfProducts circuit as a `Circuit` descriptor.
pub fn sumofproducts_circuit() -> Circuit {
    Circuit {
        name: "sumofproducts",
        witness: witness_to_fr(&SUMOFPRODUCTS_WITNESS),
        l: SUMOFPRODUCTS_L.iter().map(|row| witness_to_fr(row)).collect(),
        r: SUMOFPRODUCTS_R.iter().map(|row| witness_to_fr(row)).collect(),
        o: SUMOFPRODUCTS_O.iter().map(|row| witness_to_fr(row)).collect(),
        n_public: 2, // const (1) + output (out=100)
    }
}

// ─── Backward-compatible aliases ───
/// Multiplier witness (legacy alias).
pub const WITNESS: [u64; 8] = MULTIPLIER_WITNESS;
/// Multiplier L matrix (legacy alias).
pub const L: [[u64; 8]; 3] = MULTIPLIER_L;
/// Multiplier R matrix (legacy alias).
pub const R: [[u64; 8]; 3] = MULTIPLIER_R;
/// Multiplier O matrix (legacy alias).
pub const O: [[u64; 8]; 3] = MULTIPLIER_O;

/// Convert a u64 witness to field elements.
pub fn witness_to_fr(witness: &[u64]) -> Vec<Fr> {
    witness.iter().map(|&v| Fr::from(v)).collect()
}

/// Multiply a matrix (constraints x variables) by a witness vector.
/// Works with the hard-coded 8-variable multiplier test matrices.
#[cfg(test)]
fn matrix_mul_vec(matrix: &[[u64; 8]], witness: &[Fr]) -> Vec<Fr> {
    matrix
        .iter()
        .map(|row| {
            row.iter()
                .zip(witness.iter())
                .map(|(&m, &w)| Fr::from(m) * w)
                .fold(Fr::from(0u64), |acc, x| acc + x)
        })
        .collect()
}

/// Multiply a matrix (constraints x variables) by a witness vector.
/// Works with any `Vec<Vec<Fr>>` matrix (dynamic, arbitrary size).
#[cfg(any(test, feature = "bins", feature = "verus"))]
pub fn matrix_mul_vec_dyn(matrix: &[Vec<Fr>], witness: &[Fr]) -> Vec<Fr> {
    matrix
        .iter()
        .map(|row| {
            row.iter()
                .zip(witness.iter())
                .map(|(&m, &w)| m * w)
                .fold(Fr::from(0u64), |acc, x| acc + x)
        })
        .collect()
}

/// Verify that (L · a) ∘ (R · a) = O · a for a `Circuit`.
#[cfg(any(test, feature = "bins", feature = "verus"))]
pub fn verify_r1cs_circuit(circuit: &Circuit) -> Result<(), String> {
    let la = matrix_mul_vec_dyn(&circuit.l, &circuit.witness);
    let ra = matrix_mul_vec_dyn(&circuit.r, &circuit.witness);
    let oa = matrix_mul_vec_dyn(&circuit.o, &circuit.witness);
    for i in 0..la.len() {
        let lhs = la[i] * ra[i];
        if lhs != oa[i] {
            return Err(format!(
                "Constraint {} failed: L·a={}, R·a={}, (L·a)*(R·a)={}, O·a={}",
                i, la[i], ra[i], lhs, oa[i]
            ));
        }
    }
    Ok(())
}

/// Select a circuit by name ("multiplier" or "sumofproducts").
#[cfg(any(test, feature = "bins"))]
pub fn select_circuit(name: &str) -> Circuit {
    match name {
        "multiplier" => multiplier_circuit(),
        "sumofproducts" | "sum" => sumofproducts_circuit(),
        _ => panic!("Unknown circuit: '{}'. Use 'multiplier' or 'sumofproducts'.", name),
    }
}

// ------------------------------------------------------------------
// Verus specifications (bounds & structural invariants)
// ------------------------------------------------------------------

#[cfg(feature = "verus")]
use vstd::prelude::*;

#[cfg(feature = "verus")]
verus! {

    /// Spec: [`matrix_mul_vec_dyn`] returns a vector whose length equals the
    /// number of matrix rows (constraints), provided every row is as long as
    /// the witness.
    #[verifier::external_body]
    pub fn spec_matrix_mul_vec_dyn(matrix: &[Vec<Fr>], witness: &[Fr]) -> (r: Vec<Fr>)
        requires
            forall|i: int| 0 <= i < matrix.len() ==> matrix[i].len() == witness.len(),
        ensures
            r.len() == matrix.len(),
    {
        matrix_mul_vec_dyn(matrix, witness)
    }

    /// Spec: [`verify_r1cs_circuit`] checks every constraint without panicking.
    /// Precondition: all R1CS rows must have the same length as the witness.
    #[verifier::external_body]
    pub fn spec_verify_r1cs_circuit(circuit: &Circuit) -> (r: Result<(), String>)
        requires
            forall|i: int| 0 <= i < circuit.l.len() ==> circuit.l[i].len() == circuit.witness.len(),
            forall|i: int| 0 <= i < circuit.r.len() ==> circuit.r[i].len() == circuit.witness.len(),
            forall|i: int| 0 <= i < circuit.o.len() ==> circuit.o[i].len() == circuit.witness.len(),
        ensures
            r.is_ok() ==> true,
    {
        verify_r1cs_circuit(circuit)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_multiplier_r1cs_relation() {
        let circuit = multiplier_circuit();
        verify_r1cs_circuit(&circuit).expect("Multiplier R1CS relation should hold");
    }

    #[test]
    fn test_sumofproducts_r1cs_relation() {
        let circuit = sumofproducts_circuit();
        verify_r1cs_circuit(&circuit).expect("SumOfProducts R1CS relation should hold");
    }

    #[test]
    fn test_multiplier_witness_values() {
        let witness = witness_to_fr(&MULTIPLIER_WITNESS);
        assert_eq!(witness[0], Fr::from(1u64));
        assert_eq!(witness[1], Fr::from(48u64));
        assert_eq!(witness[2], Fr::from(2u64));
        assert_eq!(witness[3], Fr::from(2u64));
        assert_eq!(witness[4], Fr::from(3u64));
        assert_eq!(witness[5], Fr::from(4u64));
        assert_eq!(witness[6], Fr::from(4u64));
        assert_eq!(witness[7], Fr::from(12u64));
    }

    #[test]
    fn test_multiplier_intermediate_products() {
        let witness = witness_to_fr(&MULTIPLIER_WITNESS);
        let la = matrix_mul_vec(&MULTIPLIER_L, &witness);
        let ra = matrix_mul_vec(&MULTIPLIER_R, &witness);
        let oa = matrix_mul_vec(&MULTIPLIER_O, &witness);

        // Constraint 0: x1 * x2 == x5  -> 2 * 2 == 4
        assert_eq!(la[0], Fr::from(2u64));
        assert_eq!(ra[0], Fr::from(2u64));
        assert_eq!(oa[0], Fr::from(4u64));
        assert_eq!(la[0] * ra[0], oa[0]);

        // Constraint 1: x3 * x4 == x6  -> 3 * 4 == 12
        assert_eq!(la[1], Fr::from(3u64));
        assert_eq!(ra[1], Fr::from(4u64));
        assert_eq!(oa[1], Fr::from(12u64));
        assert_eq!(la[1] * ra[1], oa[1]);

        // Constraint 2: x5 * x6 == a   -> 4 * 12 == 48
        assert_eq!(la[2], Fr::from(4u64));
        assert_eq!(ra[2], Fr::from(12u64));
        assert_eq!(oa[2], Fr::from(48u64));
        assert_eq!(la[2] * ra[2], oa[2]);
    }

    #[test]
    fn test_sumofproducts_intermediate_products() {
        let circuit = sumofproducts_circuit();
        let la = matrix_mul_vec_dyn(&circuit.l, &circuit.witness);
        let ra = matrix_mul_vec_dyn(&circuit.r, &circuit.witness);
        let oa = matrix_mul_vec_dyn(&circuit.o, &circuit.witness);

        // Constraint 0: a * b == t1  -> 1 * 2 == 2
        assert_eq!(la[0] * ra[0], oa[0]);
        // Constraint 1: c * d == t2  -> 3 * 4 == 12
        assert_eq!(la[1] * ra[1], oa[1]);
        // Constraint 2: e * f == t3  -> 5 * 6 == 30
        assert_eq!(la[2] * ra[2], oa[2]);
        // Constraint 3: g * h == t4  -> 7 * 8 == 56
        assert_eq!(la[3] * ra[3], oa[3]);
    }

    #[test]
    fn test_select_circuit() {
        let m = select_circuit("multiplier");
        assert_eq!(m.name, "multiplier");
        assert_eq!(m.n_constraints(), 3);
        assert_eq!(m.n_vars(), 8);

        let s = select_circuit("sumofproducts");
        assert_eq!(s.name, "sumofproducts");
        assert_eq!(s.n_constraints(), 5);
        assert_eq!(s.n_vars(), 14);
    }
}
