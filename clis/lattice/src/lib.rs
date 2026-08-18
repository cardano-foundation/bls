//! Library exports for the lattice CLI

use lattice_prover::commitment::AjtaiParams;
use lattice_prover::fold::{self, RelaxedInstance};
use lattice_prover::params::LovaParams;
use lattirust_arithmetic::linear_algebra::Vector;
use lattirust_arithmetic::ring::Z2_64;
use lattirust_arithmetic::traits::WithLinfNorm;
use rand::Rng;
use std::time::Instant;

/// Parameters for a Lova fold run.
#[derive(Debug, Clone)]
pub struct FoldParams {
    pub lova: LovaParams,
    pub ajtai: AjtaiParams,
}

/// Result of a single Lova fold step.
#[derive(Debug, Clone)]
pub struct FoldStepResult {
    pub step: usize,
    pub u: Z2_64,
    pub witness_norm: String,
    pub error_norm: String,
    pub elapsed_ms: f64,
}

/// Full result of a Lova fold run (all steps).
#[derive(Debug)]
pub struct FoldResult {
    pub params: LovaParams,
    pub steps: usize,
    pub fold_steps: Vec<FoldStepResult>,
    pub final_instance: RelaxedInstance,
    pub final_witness: Vector<Z2_64>,
    pub final_error: Vector<Z2_64>,
    pub total_fold_ms: f64,
    pub total_verify_ms: f64,
    pub proof_size_bytes: usize,
}

/// Deserialized Lova state (for verification).
#[derive(Debug)]
pub struct LovaState {
    pub params: LovaParams,
    pub instance: RelaxedInstance,
    pub witness: Vector<Z2_64>,
    pub error: Vector<Z2_64>,
}

/// Create default Lova parameters for a given step width.
pub fn run_params(m: usize, n: usize, rounds: usize) -> LovaParams {
    LovaParams {
        m,
        n,
        witness_chunk_size: n / 4,
        decompose_base: 2,
        decompose_digits: 64,
        witness_norm_bound: 1 << 31,
        error_norm_bound: 1 << 31,
        num_rounds: rounds,
    }
}

/// Run a Lova fold chain: fold `steps` witnesses and verify after each step.
pub fn run_fold_lova(params: &LovaParams, steps: usize) -> Result<FoldResult, String> {
    let ajtai = AjtaiParams::new(params.m, params.n);
    let fp = FoldParams {
        lova: params.clone(),
        ajtai,
    };

    let mut rng = rand::thread_rng();
    let mut fold_steps = Vec::with_capacity(steps);

    // Initialize first witness/error with small values
    let bound_w: i64 = 4;
    let bound_e: i64 = 4;
    let mut w = Vector::from_fn(params.n, |_, _| {
        Z2_64::from(rng.gen_range(-bound_w..=bound_w))
    });
    let mut e = Vector::from_fn(params.n, |_, _| {
        Z2_64::from(rng.gen_range(-bound_e..=bound_e))
    });
    let mut inst = fold::init_instance(params, &fp.ajtai, &w, &e);

    let t_fold_start = Instant::now();
    let mut total_verify_ms: f64 = 0.0;

    for step in 0..steps {
        let t_step = Instant::now();

        if step > 0 {
            // Generate new witness/error for this step with small values
            let w_new = Vector::from_fn(params.n, |_, _| {
                Z2_64::from(rng.gen_range(-bound_w..=bound_w))
            });
            let e_new = Vector::from_fn(params.n, |_, _| {
                Z2_64::from(rng.gen_range(-bound_e..=bound_e))
            });
            let inst_new = fold::init_instance(params, &fp.ajtai, &w_new, &e_new);

            // Fold with random ternary challenge
            let challenge = fold::sample_ternary_challenge(2);
            let (inst_prime, w_prime, e_prime) = fold::fold_instances(
                params, &fp.ajtai, &inst, &w, &e, &inst_new, &w_new, &e_new, &challenge,
            );

            inst = inst_prime;
            w = w_prime;
            e = e_prime;
        }

        let t_verify = Instant::now();
        fold::verify_folded_instance(params, &fp.ajtai, &inst, &w, &e)?;
        let verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;
        total_verify_ms += verify_ms;

        let step_ms = t_step.elapsed().as_secs_f64() * 1000.0;

        let witness_linf = w
            .as_slice()
            .chunks(params.witness_chunk_size)
            .map(|chunk| {
                let cv = Vector::from_vec(chunk.to_vec());
                cv.linf_norm()
            })
            .max()
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".to_string());
        let error_linf = e.linf_norm().to_string();

        fold_steps.push(FoldStepResult {
            step,
            u: inst.u,
            witness_norm: witness_linf,
            error_norm: error_linf,
            elapsed_ms: step_ms,
        });
    }

    let total_fold_ms = t_fold_start.elapsed().as_secs_f64() * 1000.0;

    // Estimate proof size: commitments (2 * m * 8 bytes) + witness (n * 8) + error (n * 8) + e_digits (k * n * 8)
    let proof_size_bytes =
        2 * params.m * 8 + params.n * 8 + params.n * 8 + params.decompose_digits * params.n * 8;

    Ok(FoldResult {
        params: params.clone(),
        steps,
        fold_steps,
        final_instance: inst,
        final_witness: w,
        final_error: e,
        total_fold_ms,
        total_verify_ms,
        proof_size_bytes,
    })
}

/// Run Lova verification on a folded state.
pub fn run_verify_lova(
    params: &LovaParams,
    instance: &RelaxedInstance,
    witness: &Vector<Z2_64>,
    error: &Vector<Z2_64>,
) -> Result<(), String> {
    let ajtai = AjtaiParams::from_seed(params.m, params.n, 0);
    fold::verify_folded_instance(params, &ajtai, instance, witness, error)
}
