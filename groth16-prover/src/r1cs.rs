use ark_bls12_381::Fr;
use ark_ff::Field;

/// Concrete circuit: x1*x2 == x5, x3*x4 == x6, x5*x6 == a
/// Witness vector: [1, a, x1, x2, x3, x4, x5, x6]
pub const WITNESS: [u64; 8] = [1, 48, 2, 2, 3, 4, 4, 12];

/// L matrix (3 constraints x 8 variables)
pub const L: [[u64; 8]; 3] = [
    [0, 0, 1, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 1, 0, 0, 0],
    [0, 0, 0, 0, 0, 0, 1, 0],
];

/// R matrix (3 constraints x 8 variables)
pub const R: [[u64; 8]; 3] = [
    [0, 0, 0, 1, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 1, 0, 0],
    [0, 0, 0, 0, 0, 0, 0, 1],
];

/// O matrix (3 constraints x 8 variables)
pub const O: [[u64; 8]; 3] = [
    [0, 0, 0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0, 0, 1],
    [0, 1, 0, 0, 0, 0, 0, 0],
];

/// Convert a u64 witness to field elements.
pub fn witness_to_fr(witness: &[u64]) -> Vec<Fr> {
    witness.iter().map(|&v| Fr::from(v)).collect()
}

/// Multiply a matrix (constraints x variables) by a witness vector.
/// Returns a vector with one element per constraint.
pub fn matrix_mul_vec(matrix: &[[u64; 8]], witness: &[Fr]) -> Vec<Fr> {
    matrix
        .iter()
        .map(|row| {
            row.iter()
                .zip(witness.iter())
                .map(|(&m, &w)| Fr::from(m) * w)
                .fold(Fr::ZERO, |acc, x| acc + x)
        })
        .collect()
}

/// Verify that (L · a) ∘ (R · a) = O · a (element-wise multiplication).
pub fn verify_r1cs(witness: &[Fr]) -> Result<(), String> {
    let la = matrix_mul_vec(&L, witness);
    let ra = matrix_mul_vec(&R, witness);
    let oa = matrix_mul_vec(&O, witness);

    for i in 0..la.len() {
        let lhs = la[i] * ra[i];
        if lhs != oa[i] {
            return Err(format!(
                "Constraint {} failed: L·a = {}, R·a = {}, (L·a)*(R·a) = {}, O·a = {}",
                i, la[i], ra[i], lhs, oa[i]
            ));
        }
    }
    Ok(())
}

/// Pretty-print a vector of field elements.
pub fn print_fr_vec(name: &str, vec: &[Fr]) {
    println!("{}: {:?}", name, vec.iter().map(|f| f.to_string()).collect::<Vec<_>>());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_r1cs_relation() {
        let witness = witness_to_fr(&WITNESS);
        verify_r1cs(&witness).expect("R1CS relation should hold");
    }

    #[test]
    fn test_witness_values() {
        let witness = witness_to_fr(&WITNESS);
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
    fn test_intermediate_products() {
        let witness = witness_to_fr(&WITNESS);
        let la = matrix_mul_vec(&L, &witness);
        let ra = matrix_mul_vec(&R, &witness);
        let oa = matrix_mul_vec(&O, &witness);

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
}
