use lattice_prover::commitment::AjtaiParams;
use lattice_prover::fold::{self, RelaxedInstance};
use lattice_prover::params::LovaParams;
use lattirust_arithmetic::linear_algebra::Vector;
use lattirust_arithmetic::ring::representatives::WithSignedRepresentative;
use lattirust_arithmetic::ring::Ring;
use lattirust_arithmetic::ring::Z2_64;
use rand::Rng;

/// Create a short random vector with bounded entries.
fn short_vector(n: usize, bound: i64) -> Vector<Z2_64> {
    let mut rng = rand::thread_rng();
    Vector::from_fn(n, |_, _| Z2_64::from(rng.gen_range(-bound..=bound)))
}

/// Simulate a simple circuit step: witness + error → instance.
fn simulate_circuit_step(
    params: &LovaParams,
    ajtai: &AjtaiParams,
) -> (Vector<Z2_64>, Vector<Z2_64>, RelaxedInstance) {
    let witness = short_vector(params.n, params.witness_norm_bound as i64 / 4);
    let error = short_vector(params.n, params.error_norm_bound as i64 / 4);
    let instance = fold::init_instance(params, ajtai, &witness, &error);
    (witness, error, instance)
}

#[test]
fn test_full_ivc_chain_4_steps() {
    let params = LovaParams::toy();
    let ajtai = AjtaiParams::new(params.m, params.n);

    // Step 1: initialize
    let (mut w, mut e, mut inst) = simulate_circuit_step(&params, &ajtai);
    assert!(
        fold::verify_folded_instance(&params, &ajtai, &inst, &w, &e).is_ok(),
        "step 1 verification failed"
    );

    // Steps 2-4: fold
    for step in 2..=4 {
        let (w_new, e_new, inst_new) = simulate_circuit_step(&params, &ajtai);
        let challenge = fold::sample_ternary_challenge(2);

        let (inst_prime, w_prime, e_prime) = fold::fold_instances(
            &params, &ajtai, &inst, &w, &e, &inst_new, &w_new, &e_new, &challenge,
        );

        assert!(
            fold::verify_folded_instance(&params, &ajtai, &inst_prime, &w_prime, &e_prime).is_ok(),
            "step {} verification failed",
            step
        );

        inst = inst_prime;
        w = w_prime;
        e = e_prime;
    }
}

#[test]
fn test_fold_with_ternary_challenges_only() {
    let params = LovaParams::toy();
    let ajtai = AjtaiParams::new(params.m, params.n);

    let mut w = short_vector(params.n, 2);
    let mut e = short_vector(params.n, 2);
    let mut inst = fold::init_instance(&params, &ajtai, &w, &e);

    // Fold 8 times with ternary challenges
    for _ in 0..8 {
        let w_new = short_vector(params.n, 2);
        let e_new = short_vector(params.n, 2);
        let inst_new = fold::init_instance(&params, &ajtai, &w_new, &e_new);

        // Only ternary challenges: {-1, 0, 1}
        let challenge = fold::sample_ternary_challenge(2);
        for j in 0..challenge.len() {
            let val = challenge[j].as_signed_representative();
            assert!(val >= -1 && val <= 1, "non-ternary challenge: {}", val);
        }

        let (inst_prime, w_prime, e_prime) = fold::fold_instances(
            &params, &ajtai, &inst, &w, &e, &inst_new, &w_new, &e_new, &challenge,
        );

        assert!(
            fold::verify_folded_instance(&params, &ajtai, &inst_prime, &w_prime, &e_prime).is_ok()
        );

        inst = inst_prime;
        w = w_prime;
        e = e_prime;
    }
}

#[test]
fn test_fold_detects_witness_norm_violation() {
    let params = LovaParams::toy();
    let ajtai = AjtaiParams::new(params.m, params.n);

    // Create a witness that violates the norm bound
    let mut w = short_vector(params.n, 2);
    let e = short_vector(params.n, 2);

    // Manually set one element to exceed the bound
    w[0] = Z2_64::from(params.witness_norm_bound as i64 + 1);

    let inst = fold::init_instance(&params, &ajtai, &w, &e);
    let result = fold::verify_folded_instance(&params, &ajtai, &inst, &w, &e);
    assert!(result.is_err(), "should detect norm violation");
    assert!(result.unwrap_err().contains("witness chunk"));
}

#[test]
fn test_fold_detects_error_norm_violation() {
    let params = LovaParams::toy();
    let ajtai = AjtaiParams::new(params.m, params.n);

    let w = short_vector(params.n, 2);
    let mut e = short_vector(params.n, 2);

    // Manually set one element to exceed the bound
    e[0] = Z2_64::from(params.error_norm_bound as i64 + 1);

    let inst = fold::init_instance(&params, &ajtai, &w, &e);
    let result = fold::verify_folded_instance(&params, &ajtai, &inst, &w, &e);
    assert!(result.is_err(), "should detect error norm violation");
    assert!(result.unwrap_err().contains("error norm"));
}

#[test]
fn test_fold_detects_commitment_mismatch() {
    let params = LovaParams::toy();
    let ajtai = AjtaiParams::new(params.m, params.n);

    let w = short_vector(params.n, 2);
    let e = short_vector(params.n, 2);
    let inst = fold::init_instance(&params, &ajtai, &w, &e);

    // Use wrong witness for verification
    let w_wrong = short_vector(params.n, 2);
    let result = fold::verify_folded_instance(&params, &ajtai, &inst, &w_wrong, &e);
    assert!(result.is_err(), "should detect commitment mismatch");
    assert!(result.unwrap_err().contains("witness commitment"));
}

use proptest::prelude::*;

proptest::proptest! {
    #[test]
    fn test_fold_compositionality(
        c1 in any::<i8>().prop_map(|x| x.clamp(-1, 1)),
        c2 in any::<i8>().prop_map(|x| x.clamp(-1, 1)),
        c3 in any::<i8>().prop_map(|x| x.clamp(-1, 1)),
    ) {
        let params = LovaParams::toy();
        let ajtai = AjtaiParams::new(params.m, params.n);

        // 3-step fold: (w1,e1) then (w2,e2) then (w3,e3)
        let w1 = short_vector(params.n, 2);
        let e1 = short_vector(params.n, 2);
        let w2 = short_vector(params.n, 2);
        let e2 = short_vector(params.n, 2);
        let w3 = short_vector(params.n, 2);
        let e3 = short_vector(params.n, 2);

        let inst1 = fold::init_instance(&params, &ajtai, &w1, &e1);
        let inst2 = fold::init_instance(&params, &ajtai, &w2, &e2);
        let inst3 = fold::init_instance(&params, &ajtai, &w3, &e3);

        // Fold (inst1, inst2) with challenge (c1, c2)
        let ch12 = Vector::from_vec(vec![
            Z2_64::from(c1 as i64),
            Z2_64::from(c2 as i64),
        ]);
        let (inst12, w12, e12) = fold::fold_instances(
            &params, &ajtai,
            &inst1, &w1, &e1,
            &inst2, &w2, &e2,
            &ch12,
        );

        // Fold (inst12, inst3) with challenge (c3, 1)
        let ch123 = Vector::from_vec(vec![
            Z2_64::from(c3 as i64),
            Z2_64::ONE,
        ]);
        let (inst_final, w_final, e_final) = fold::fold_instances(
            &params, &ajtai,
            &inst12, &w12, &e12,
            &inst3, &w3, &e3,
            &ch123,
        );

        prop_assert!(
            fold::verify_folded_instance(&params, &ajtai, &inst_final, &w_final, &e_final).is_ok(),
            "3-step fold verification failed"
        );

        // Verify linearity: w_final = c3 * (c1*w1 + c2*w2) + 1*w3
        let c1z = Z2_64::from(c1 as i64);
        let c2z = Z2_64::from(c2 as i64);
        let c3z = Z2_64::from(c3 as i64);
        for j in 0..params.n {
            let expected_w = c3z * (c1z * w1[j] + c2z * w2[j]) + w3[j];
            prop_assert_eq!(w_final[j], expected_w, "witness mismatch at {}", j);
        }
    }
}
