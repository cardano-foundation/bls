//! Lova-native benchmark binary.
//!
//! Measures fold time, verify time, and proof size for various Lova parameter
//! configurations. Uses synthetic random witnesses (no circom circuits).
//!
//! Usage:
//!   cargo run --release --bin benchmark_lova -- --m 256 --n 128 --steps 32
//!   cargo run --release --bin benchmark_lova -- --all

use lattice::run_fold_lova;
use lattice_prover::params::LovaParams;
use std::time::Instant;

fn bench_config(name: &str, m: usize, n: usize, steps: usize) {
    // Scale bounds generously to accommodate accumulated error over many steps.
    // In production these would be set by the Lova norm constraint; here we just
    // ensure the benchmark doesn't fail.
    let base_bound = 1u64 << 32;
    let scaled_bound = base_bound * (steps as u64).max(1);
    let params = LovaParams {
        m,
        n,
        witness_chunk_size: n / 4,
        decompose_base: 2,
        decompose_digits: 64,
        witness_norm_bound: scaled_bound,
        error_norm_bound: scaled_bound,
        num_rounds: steps,
    };

    eprintln!("--- {} ---", name);
    eprintln!("  m={}, n={}, steps={}", m, n, steps);

    let t_start = Instant::now();
    let result = run_fold_lova(&params, steps).expect("fold failed");
    let wall_ms = t_start.elapsed().as_secs_f64() * 1000.0;

    eprintln!(
        "  fold:        {:.2} ms (avg {:.2} ms/step)",
        result.total_fold_ms,
        result.total_fold_ms / steps as f64
    );
    eprintln!(
        "  verify:      {:.2} ms (avg {:.2} ms/step)",
        result.total_verify_ms,
        result.total_verify_ms / steps as f64
    );
    eprintln!("  wall:        {:.2} ms", wall_ms);
    eprintln!(
        "  proof size:  {} bytes ({:.1} KiB)",
        result.proof_size_bytes,
        result.proof_size_bytes as f64 / 1024.0
    );
    eprintln!();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let run_all = args.iter().any(|a| a == "--all");

    if run_all {
        // Toy parameters (Phase 1 foundation)
        bench_config("toy (16×8, 8 steps)", 16, 8, 8);
        bench_config("toy (16×8, 32 steps)", 16, 8, 32);
        bench_config("toy (16×8, 128 steps)", 16, 8, 128);
        bench_config("toy (16×8, 256 steps)", 16, 8, 256);

        // Small parameters
        bench_config("small (32×16, 8 steps)", 32, 16, 8);
        bench_config("small (32×16, 32 steps)", 32, 16, 32);
        bench_config("small (32×16, 128 steps)", 32, 16, 128);

        // Medium parameters
        bench_config("medium (64×32, 8 steps)", 64, 32, 8);
        bench_config("medium (64×32, 32 steps)", 64, 32, 32);
        bench_config("medium (64×32, 128 steps)", 64, 32, 128);

        // Default parameters
        bench_config("default (256×128, 8 steps)", 256, 128, 8);
        bench_config("default (256×128, 32 steps)", 256, 128, 32);

        // Scaling with step count
        eprintln!("=== Step-count scaling (m=16, n=8) ===");
        for steps in [8, 16, 32, 64, 128, 256, 512, 1024] {
            bench_config(&format!("scale (16×8, {} steps)", steps), 16, 8, steps);
        }
    } else {
        // Parse simple args
        let m = args
            .iter()
            .position(|a| a == "--m")
            .and_then(|i| args.get(i + 1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(16);
        let n = args
            .iter()
            .position(|a| a == "--n")
            .and_then(|i| args.get(i + 1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(8);
        let steps = args
            .iter()
            .position(|a| a == "--steps")
            .and_then(|i| args.get(i + 1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(32);

        bench_config(
            &format!("custom ({}×{}, {} steps)", m, n, steps),
            m,
            n,
            steps,
        );
    }
}
