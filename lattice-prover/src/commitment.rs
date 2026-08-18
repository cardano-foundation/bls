use lattirust_arithmetic::linear_algebra::{Matrix, Vector};
use lattirust_arithmetic::ring::Z2_64;

use crate::params::AjtaiCommitment;

/// Public parameters for Ajtai commitments.
///
/// The commitment matrix `A` is `m × n` over `Z_{2^64}`.
/// For a commitment to a vector `s ∈ Z^n`, compute `A * s mod 2^64`.
#[derive(Debug, Clone)]
pub struct AjtaiParams {
    pub a: Matrix<Z2_64>,
    pub m: usize,
    pub n: usize,
}

impl AjtaiParams {
    pub fn new(m: usize, n: usize) -> Self {
        let mut rng = rand::thread_rng();
        let a = Matrix::<Z2_64>::rand(m, n, &mut rng);
        Self { a, m, n }
    }

    pub fn from_seed(m: usize, n: usize, seed: u64) -> Self {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
        let a = Matrix::<Z2_64>::rand(m, n, &mut rng);
        Self { a, m, n }
    }

    pub fn commit(&self, s: &Vector<Z2_64>) -> AjtaiCommitment {
        assert_eq!(s.len(), self.n, "witness dimension must match");
        let committed = &self.a * s;
        AjtaiCommitment {
            values: committed.iter().copied().collect(),
        }
    }
}

pub fn verify_commitment(
    params: &AjtaiParams,
    s: &Vector<Z2_64>,
    commitment: &AjtaiCommitment,
) -> bool {
    let expected = params.commit(s);
    expected == *commitment
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;

    #[test]
    fn test_ajtai_commitment_basic() {
        let params = AjtaiParams::new(16, 8);
        let s = Vector::<Z2_64>::rand(8, &mut rand::thread_rng());
        let c = params.commit(&s);
        assert!(verify_commitment(&params, &s, &c));
    }

    #[test]
    fn test_ajtai_commitment_wrong_witness() {
        let params = AjtaiParams::new(16, 8);
        let s = Vector::<Z2_64>::rand(8, &mut rand::thread_rng());
        let c = params.commit(&s);
        let s_wrong = Vector::<Z2_64>::rand(8, &mut rand::thread_rng());
        assert!(!verify_commitment(&params, &s_wrong, &c));
    }

    #[test]
    fn test_ajtai_commitment_short_vector() {
        let params = AjtaiParams::new(16, 8);
        let mut rng = rand::thread_rng();
        let s = Vector::from_fn(8, |_, _| Z2_64::from(rng.gen::<u8>() as i64));
        let c = params.commit(&s);
        assert!(verify_commitment(&params, &s, &c));
    }

    #[test]
    fn test_ajtai_commitment_deterministic() {
        let params = AjtaiParams::new(16, 8);
        let s = Vector::from_fn(8, |i, _| Z2_64::from(i as i64));
        let c1 = params.commit(&s);
        let c2 = params.commit(&s);
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_ajtai_deterministic_from_seed() {
        let p1 = AjtaiParams::from_seed(16, 8, 42);
        let p2 = AjtaiParams::from_seed(16, 8, 42);
        assert_eq!(p1.a, p2.a);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_ajtai_commitment_homomorphic_add(
            s1 in proptest::collection::vec(any::<i8>().prop_map(|x| Z2_64::from(x as i64)), 8),
            s2 in proptest::collection::vec(any::<i8>().prop_map(|x| Z2_64::from(x as i64)), 8),
        ) {
            let params = AjtaiParams::new(16, 8);
            let v1 = Vector::from_vec(s1);
            let v2 = Vector::from_vec(s2);
            let c1 = params.commit(&v1);
            let c2 = params.commit(&v2);
            let s_sum = &v1 + &v2;
            let c_sum = params.commit(&s_sum);
            for i in 0..params.m {
                prop_assert_eq!(c1.values[i] + c2.values[i], c_sum.values[i]);
            }
        }

        #[test]
        fn test_ajtai_commitment_homomorphic_scalar(
            s in proptest::collection::vec(any::<i8>().prop_map(|x| Z2_64::from(x as i64)), 8),
            r in any::<i8>(),
        ) {
            let params = AjtaiParams::new(16, 8);
            let v = Vector::from_vec(s);
            let scalar = Z2_64::from(r as i64);
            let c = params.commit(&v);
            let rs = v.map(|x| x * scalar);
            let c_rs = params.commit(&rs);
            let expected: Vec<Z2_64> = c.values.into_iter().map(|x| x * scalar).collect();
            for i in 0..params.m {
                prop_assert_eq!(c_rs.values[i], expected[i]);
            }
        }
    }
}
