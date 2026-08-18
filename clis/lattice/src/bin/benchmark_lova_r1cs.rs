//! R1CS-to-Lova benchmark binary.
//!
//! Loads Circom witnesses, converts them to Lova vectors, and runs Lova folding.
//! Supports two decomposition modes:
//!   - **4-limb** (default): BLS12-381 → 4 × Z_{2^64} limbs
//!   - **RNS** (`--rns`):    BLS12-381 → 8 × 32-bit RNS residues (smaller norms)
//!
//! Usage:
//!   # 4-limb mode (default)
//!   cargo run --release --bin benchmark_lova_r1cs -- --steps-dir /tmp/opencode/bench/eddsa_steps --limit 32
//!
//!   # RNS mode (8 residues per signal, smaller decompose_digits)
//!   cargo run --release --bin benchmark_lova_r1cs -- --steps-dir /tmp/opencode/bench/eddsa_steps --limit 32 --rns

use lattice_prover::params::LovaParams;
use lattice_prover::rns::{self, RnsConfig};
use lattirust_arithmetic::linear_algebra::Vector;
use lattirust_arithmetic::ring::Z2_64;
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
            eprintln!("benchmark_lova_r1cs — R1CS-to-Lova folding benchmark");
            eprintln!();
            eprintln!("Usage: benchmark_lova_r1cs --steps-dir <DIR> [OPTIONS]");
            eprintln!();
            eprintln!("Options:");
            eprintln!("  --steps-dir <DIR>   Directory containing .wtns step witnesses");
            eprintln!("  --limit <N>         Maximum number of steps to load (default: all)");
            eprintln!("  --rns               Use RNS decomposition (8×32-bit residues) instead of 4-limb");
            eprintln!();
            eprintln!("Examples:");
            eprintln!("  benchmark_lova_r1cs --steps-dir /tmp/opencode/bench/eddsa_steps --limit 32");
            eprintln!("  benchmark_lova_r1cs --steps-dir /tmp/opencode/bench/eddsa_steps --limit 32 --rns");
            std::process::exit(1);
        });

    let limit = args
        .iter()
        .position(|a| a == "--limit")
        .and_then(|i| args.get(i + 1).and_then(|s| s.parse().ok()));

    let use_rns = args.iter().any(|a| a == "--rns");

    let t_load = Instant::now();
    let (witnesses, n_signals, n_limbs, decompose_digits, norm_bound, mode) = if use_rns {
        let config = RnsConfig::mod_8x32();
        let k = config.residues_per_element();
        let witnesses = rns::load_step_witnesses_as_rns(&steps_dir, &config, limit)
            .expect("failed to load witnesses");
        let n_limbs = witnesses[0].len();
        let n_signals = n_limbs / k;
        (
            witnesses,
            n_signals,
            n_limbs,
            32usize,
            u64::MAX, // generous bound; decomposition keeps actual norms bounded
            "RNS (8x32-bit)",
        )
    } else {
        let witnesses =
            lattice_prover::bls12_381_adapter::load_step_witnesses_as_limbs(&steps_dir, limit)
                .expect("failed to load witnesses");
        let n_limbs = witnesses[0].len();
        let n_signals = n_limbs / 4;
        (witnesses, n_signals, n_limbs, 64usize, u64::MAX, "4-limb")
    };
    let load_ms = t_load.elapsed().as_secs_f64() * 1000.0;

    let steps = witnesses.len();

    eprintln!("=== R1CS-to-Lova benchmark ({}) ===", mode);
    eprintln!("Steps directory: {}", steps_dir.display());
    eprintln!("Step witnesses:  {}", steps);
    eprintln!(
        "Signals/witness: {} ({} Z_{{2^64}} values)",
        n_signals, n_limbs
    );
    eprintln!("Load time:       {:.2} ms", load_ms);
    eprintln!();

    let m = n_limbs;
    let n = n_limbs;

    let params = LovaParams {
        m,
        n,
        witness_chunk_size: n / 4,
        decompose_base: 2,
        decompose_digits,
        witness_norm_bound: norm_bound,
        error_norm_bound: norm_bound,
        num_rounds: steps,
    };

    eprintln!(
        "Lova params: m={}, n={}, decompose_digits={}",
        params.m, params.n, params.decompose_digits
    );
    eprintln!(
        "Norm bound:  {} ({})",
        params.witness_norm_bound,
        if use_rns { "32-bit RNS" } else { "64-bit limb" }
    );
    let proof_size =
        2 * params.m * 8 + params.n * 8 + params.n * 8 + params.decompose_digits * params.n * 8;
    eprintln!(
        "Proof size estimate: {} bytes ({:.1} KiB)",
        proof_size,
        proof_size as f64 / 1024.0
    );
    eprintln!();

    // Run Lova fold
    let t_fold = Instant::now();

    use lattice_prover::commitment::AjtaiParams;
    use lattice_prover::fold;
    use rand::Rng;

    let ajtai = AjtaiParams::new(params.m, params.n);
    let mut rng = rand::thread_rng();

    let bound_e: i64 = 4;
    let mut w = witnesses[0].clone();
    let mut e: Vector<Z2_64> = Vector::from_fn(params.n, |_, _| {
        Z2_64::from(rng.gen_range(-bound_e..=bound_e))
    });
    let mut inst = fold::init_instance(&params, &ajtai, &w, &e);

    let mut total_verify_ms: f64 = 0.0;

    for step in 1..steps {
        let t_step = Instant::now();

        let w_new = witnesses[step].clone();
        let e_new: Vector<Z2_64> = Vector::from_fn(params.n, |_, _| {
            Z2_64::from(rng.gen_range(-bound_e..=bound_e))
        });
        let inst_new = fold::init_instance(&params, &ajtai, &w_new, &e_new);

        let challenge = fold::sample_ternary_challenge(2);
        let (inst_prime, w_prime, e_prime) = fold::fold_instances(
            &params, &ajtai, &inst, &w, &e, &inst_new, &w_new, &e_new, &challenge,
        );

        inst = inst_prime;
        w = w_prime;
        e = e_prime;

        let t_verify = Instant::now();
        fold::verify_folded_instance(&params, &ajtai, &inst, &w, &e)
            .unwrap_or_else(|err| panic!("step {} verification failed: {}", step, err));
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

    eprintln!();
    eprintln!("=== Results ({}) ===", mode);
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
