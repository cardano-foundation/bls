use ark_bls12_381::Fr;
use ark_std::vec::Vec;

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
#[cfg(any(test, feature = "bins"))]
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
#[cfg(any(test, feature = "bins"))]
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
