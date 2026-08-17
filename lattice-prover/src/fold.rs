use lattirust_arithmetic::linear_algebra::Vector;
use lattirust_arithmetic::ring::Ring;
use lattirust_arithmetic::ring::Z2_64;
use lattirust_arithmetic::traits::WithLinfNorm;
use rand::Rng;

use crate::commitment::{self, AjtaiParams};
use crate::decompose;
use crate::params::{AjtaiCommitment, LovaParams};

/// A relaxed R1CS instance over `Z_{2^64}`.
#[derive(Debug, Clone)]
pub struct RelaxedInstance {
    pub u: Z2_64,
    pub com_z: AjtaiCommitment,
    pub com_e: AjtaiCommitment,
    pub e_digits: Vec<Vector<Z2_64>>,
}

/// The folded state after `N` steps.
#[derive(Debug, Clone)]
pub struct FoldedState {
    pub instance: RelaxedInstance,
    pub witness: Vector<Z2_64>,
    pub error: Vector<Z2_64>,
    pub transcript: Vec<Z2_64>,
}

/// Create the initial (non-relaxed) instance from a witness.
pub fn init_instance(
    params: &LovaParams,
    ajtai: &AjtaiParams,
    witness: &Vector<Z2_64>,
    error: &Vector<Z2_64>,
) -> RelaxedInstance {
    let com_z = ajtai.commit(witness);
    let com_e = ajtai.commit(error);
    let e_digits = decompose::decompose_vector(error, params.decompose_base as i64, params.decompose_digits);

    RelaxedInstance {
        u: Z2_64::ONE,
        com_z,
        com_e,
        e_digits,
    }
}

/// Sample a ternary challenge vector `c ∈ {-1, 0, 1}^k`.
pub fn sample_ternary_challenge(k: usize) -> Vector<Z2_64> {
    let mut rng = rand::thread_rng();
    Vector::from_fn(k, |_, _| {
        let r: i8 = rng.gen_range(-1..=1);
        Z2_64::from(r as i64)
    })
}

/// Fold two relaxed instances into one.
///
/// Computes:
/// - `u'  = c1 * u1 + c2 * u2`
/// - `s'  = c1 * s1 + c2 * s2`
/// - `E'  = c1 * E1 + c2 * E2`
pub fn fold_instances(
    params: &LovaParams,
    ajtai: &AjtaiParams,
    inst1: &RelaxedInstance,
    witness1: &Vector<Z2_64>,
    error1: &Vector<Z2_64>,
    inst2: &RelaxedInstance,
    witness2: &Vector<Z2_64>,
    error2: &Vector<Z2_64>,
    challenge: &Vector<Z2_64>,
) -> (RelaxedInstance, Vector<Z2_64>, Vector<Z2_64>) {
    let n = witness1.len();
    let c1 = challenge[0];
    let c2 = if challenge.len() > 1 { challenge[1] } else { Z2_64::ONE };

    let u_prime = c1 * inst1.u + c2 * inst2.u;

    let mut witness_prime = Vector::from_element(n, Z2_64::ZERO);
    let mut error_prime = Vector::from_element(n, Z2_64::ZERO);
    for j in 0..n {
        witness_prime[j] = c1 * witness1[j] + c2 * witness2[j];
        error_prime[j] = c1 * error1[j] + c2 * error2[j];
    }

    let com_z_prime = ajtai.commit(&witness_prime);
    let com_e_prime = ajtai.commit(&error_prime);
    let e_digits = decompose::decompose_vector(&error_prime, params.decompose_base as i64, params.decompose_digits);

    let inst_prime = RelaxedInstance {
        u: u_prime,
        com_z: com_z_prime,
        com_e: com_e_prime,
        e_digits,
    };

    (inst_prime, witness_prime, error_prime)
}

/// Verify a folded instance against norm bounds and commitments.
pub fn verify_folded_instance(
    params: &LovaParams,
    ajtai: &AjtaiParams,
    instance: &RelaxedInstance,
    witness: &Vector<Z2_64>,
    error: &Vector<Z2_64>,
) -> Result<(), String> {
    if !commitment::verify_commitment(ajtai, witness, &instance.com_z) {
        return Err("witness commitment mismatch".to_string());
    }
    if !commitment::verify_commitment(ajtai, error, &instance.com_e) {
        return Err("error commitment mismatch".to_string());
    }

    let error_linf = error.linf_norm();
    if error_linf > params.error_norm_bound.into() {
        return Err(format!("error norm {} exceeds bound {}", error_linf, params.error_norm_bound));
    }

    let chunk_size = params.witness_chunk_size;
    for (chunk_idx, chunk) in witness.as_slice().chunks(chunk_size).enumerate() {
        let chunk_vec = Vector::from_vec(chunk.to_vec());
        let chunk_linf = chunk_vec.linf_norm();
        if chunk_linf > params.witness_norm_bound.into() {
            return Err(format!(
                "witness chunk {} norm {} exceeds bound {}",
                chunk_idx, chunk_linf, params.witness_norm_bound
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn toy_params() -> (LovaParams, AjtaiParams) {
        let params = LovaParams::toy();
        let ajtai = AjtaiParams::new(params.m, params.n);
        (params, ajtai)
    }

    fn short_vector(n: usize, bound: i64) -> Vector<Z2_64> {
        let mut rng = rand::thread_rng();
        Vector::from_fn(n, |_, _| Z2_64::from(rng.gen_range(-bound..=bound)))
    }

    #[test]
    fn test_init_and_verify() {
        let (params, ajtai) = toy_params();
        let witness = short_vector(params.n, params.witness_norm_bound as i64);
        let error = short_vector(params.n, params.error_norm_bound as i64);
        let inst = init_instance(&params, &ajtai, &witness, &error);
        assert!(verify_folded_instance(&params, &ajtai, &inst, &witness, &error).is_ok());
    }

    #[test]
    fn test_fold_two_instances() {
        let (params, ajtai) = toy_params();
        let w1 = short_vector(params.n, 4);
        let e1 = short_vector(params.n, 4);
        let w2 = short_vector(params.n, 4);
        let e2 = short_vector(params.n, 4);

        let inst1 = init_instance(&params, &ajtai, &w1, &e1);
        let inst2 = init_instance(&params, &ajtai, &w2, &e2);

        let challenge = sample_ternary_challenge(2);
        let (inst_prime, w_prime, e_prime) =
            fold_instances(&params, &ajtai, &inst1, &w1, &e1, &inst2, &w2, &e2, &challenge);

        let c1 = challenge[0];
        let c2 = challenge[1];
        for j in 0..params.n {
            let expected = c1 * w1[j] + c2 * w2[j];
            assert_eq!(w_prime[j], expected, "witness mismatch at {}", j);
            let expected_e = c1 * e1[j] + c2 * e2[j];
            assert_eq!(e_prime[j], expected_e, "error mismatch at {}", j);
        }

        assert!(verify_folded_instance(&params, &ajtai, &inst_prime, &w_prime, &e_prime).is_ok());
    }

    #[test]
    fn test_fold_multiple_rounds() {
        let (params, ajtai) = toy_params();

        let mut w = short_vector(params.n, 2);
        let mut e = short_vector(params.n, 2);
        let mut inst = init_instance(&params, &ajtai, &w, &e);

        for _ in 0..4 {
            let w_new = short_vector(params.n, 2);
            let e_new = short_vector(params.n, 2);
            let inst_new = init_instance(&params, &ajtai, &w_new, &e_new);
            let challenge = sample_ternary_challenge(2);

            let (inst_prime, w_prime, e_prime) = fold_instances(
                &params, &ajtai,
                &inst, &w, &e,
                &inst_new, &w_new, &e_new,
                &challenge,
            );

            inst = inst_prime;
            w = w_prime;
            e = e_prime;
        }

        assert!(verify_folded_instance(&params, &ajtai, &inst, &w, &e).is_ok());
    }

    proptest::proptest! {
        #[test]
        fn test_fold_preserves_linear_relation(
            c1 in any::<i8>().prop_map(|x| x.clamp(-1, 1)),
            c2 in any::<i8>().prop_map(|x| x.clamp(-1, 1)),
        ) {
            let (params, ajtai) = toy_params();
            let w1 = short_vector(params.n, 4);
            let e1 = short_vector(params.n, 4);
            let w2 = short_vector(params.n, 4);
            let e2 = short_vector(params.n, 4);

            let inst1 = init_instance(&params, &ajtai, &w1, &e1);
            let inst2 = init_instance(&params, &ajtai, &w2, &e2);

            let challenge = Vector::from_vec(vec![
                Z2_64::from(c1 as i64),
                Z2_64::from(c2 as i64),
            ]);

            let (_, w_prime, e_prime) =
                fold_instances(&params, &ajtai, &inst1, &w1, &e1, &inst2, &w2, &e2, &challenge);

            let c1_z = Z2_64::from(c1 as i64);
            let c2_z = Z2_64::from(c2 as i64);
            for j in 0..params.n {
                prop_assert_eq!(w_prime[j], c1_z * w1[j] + c2_z * w2[j], "witness fold at {}", j);
                prop_assert_eq!(e_prime[j], c1_z * e1[j] + c2_z * e2[j], "error fold at {}", j);
            }
        }
    }
}
