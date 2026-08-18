//! R1CS-to-Lova benchmark binary.
//!
//! Loads Circom witnesses, converts them to Lova vectors via 4-limb BLS12-381
//! → Z_{2^64} decomposition, and runs Lova folding.
//!
//! Usage:
//!   cargo run --release --bin benchmark_lova_r1cs -- --steps-dir /tmp/opencode/bench/ed25519_steps --limit 32
//!   cargo run --release --bin benchmark_lova_r1cs -- --steps-dir /tmp/opencode/bench/eddsa_steps --limit 128

use lattice_prover::bls12_381_adapter::load_step_witnesses_as_limbs;
use lattice_prover::params::LovaParams;
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let steps_dir = args
        .iter()
        .position(|a| a == "--steps-dir")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            eprintln!("Usage: benchmark_lova_r1cs --steps-dir <DIR> [--limit N]");
            std::process::exit(1);
        });

    let limit = args
        .iter()
        .position(|a| a == "--limit")
        .and_then(|i| args.get(i + 1))
        .and_then(|s| s.parse().ok());

    // Load witnesses
    let t_load = Instant::now();
    let witnesses =
        load_step_witnesses_as_limbs(&steps_dir, limit).expect("failed to load witnesses");
    let load_ms = t_load.elapsed().as_secs_f64() * 1000.0;

    let n_signals = if let Some(first) = witnesses.first() {
        first.len() / 4 // 4 limbs per signal
    } else {
        eprintln!("No witnesses loaded");
        std::process::exit(1);
    };

    let n_limbs = witnesses[0].len();
    let steps = witnesses.len();

    eprintln!("=== R1CS-to-Lova benchmark ===");
    eprintln!("Steps directory: {}", steps_dir.display());
    eprintln!("Step witnesses:  {}", steps);
    eprintln!(
        "Signals/witness: {} ({} Z_{{2^64}} limbs)",
        n_signals, n_limbs
    );
    eprintln!("Load time:       {:.2} ms", load_ms);
    eprintln!();

    // Lova params: m and n must accommodate the limb vector.
    // BLS12-381 limbs can be up to ~2^63, so we need a generous bound.
    let m = n_limbs;
    let n = n_limbs;
    let params = LovaParams {
        m,
        n,
        witness_chunk_size: n / 4,
        decompose_base: 2,
        decompose_digits: 64,
        witness_norm_bound: u64::MAX,
        error_norm_bound: u64::MAX,
        num_rounds: steps,
    };

    eprintln!(
        "Lova params: m={}, n={}, decompose_digits=64",
        params.m, params.n
    );
    eprintln!(
        "Proof size estimate: {} bytes ({:.1} KiB)",
        2 * params.m * 8 + params.n * 8 + params.n * 8 + params.decompose_digits * params.n * 8,
        (2 * params.m * 8 + params.n * 8 + params.n * 8 + params.decompose_digits * params.n * 8)
            as f64
            / 1024.0
    );
    eprintln!();

    // Run Lova fold using the first witness as initial, rest as fold targets
    // We need to fold the witnesses sequentially (IVC chain)
    let t_fold = Instant::now();

    // For the adapter: we fold witnesses[0] as the initial state,
    // then fold witnesses[1..] one by one.
    use lattice_prover::commitment::AjtaiParams;
    use lattice_prover::fold;
    use lattirust_arithmetic::linear_algebra::Vector;
    use lattirust_arithmetic::ring::Z2_64;
    use rand::Rng;

    let ajtai = AjtaiParams::new(params.m, params.n);
    let mut rng = rand::thread_rng();

    // Initialize with first witness
    let bound_e: i64 = 4;
    let mut w = witnesses[0].clone();
    let mut e = Vector::from_fn(params.n, |_, _| {
        Z2_64::from(rng.gen_range(-bound_e..=bound_e))
    });
    let mut inst = fold::init_instance(&params, &ajtai, &w, &e);

    let mut total_verify_ms: f64 = 0.0;

    for step in 1..steps {
        let t_step = Instant::now();

        // Use next witness as the new step
        let w_new = witnesses[step].clone();
        let e_new = Vector::from_fn(params.n, |_, _| {
            Z2_64::from(rng.gen_range(-bound_e..=bound_e))
        });
        let inst_new = fold::init_instance(&params, &ajtai, &w_new, &e_new);

        // Fold
        let challenge = fold::sample_ternary_challenge(2);
        let (inst_prime, w_prime, e_prime) = fold::fold_instances(
            &params, &ajtai, &inst, &w, &e, &inst_new, &w_new, &e_new, &challenge,
        );

        inst = inst_prime;
        w = w_prime;
        e = e_prime;

        // Verify
        let t_verify = Instant::now();
        fold::verify_folded_instance(&params, &ajtai, &inst, &w, &e)
            .expect(&format!("step {} verification failed", step));
        let verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;
        total_verify_ms += verify_ms;

        let step_ms = t_step.elapsed().as_secs_f64() * 1000.0;
        if step <= 10 || step % 32 == 0 || step == steps - 1 {
            eprintln!(
                "  step {:4}: elapsed={:.2} ms, verify={:.2} ms",
                step, step_ms, verify_ms
            );
        }
    }

    let total_fold_ms = t_fold.elapsed().as_secs_f64() * 1000.0;
    let proof_size =
        2 * params.m * 8 + params.n * 8 + params.n * 8 + params.decompose_digits * params.n * 8;

    eprintln!();
    eprintln!("=== Results ===");
    eprintln!(
        "Fold total:  {:.2} ms (avg {:.2} ms/step)",
        total_fold_ms,
        total_fold_ms / (steps - 1) as f64
    );
    eprintln!(
        "Verify total:{:.2} ms (avg {:.2} ms/step)",
        total_verify_ms,
        total_verify_ms / (steps - 1) as f64
    );
    eprintln!(
        "Proof size:  {} bytes ({:.1} KiB)",
        proof_size,
        proof_size as f64 / 1024.0
    );
}
