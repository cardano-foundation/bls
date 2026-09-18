//! Benchmark the two group-arithmetic backends head-to-head:
//!
//!   - **Cpu**: arkworks `VariableBaseMSM` + `multi_pairing` + radix-2 FFT
//!   - **Native**: the vendored blst FFI backend (`blst_p1s_mult_pippenger`
//!     / `blst_p2s_mult_pippenger` / `blst_miller_loop_n` + `blst_final_exp`
//!     / `bls_ntt_in_place`)
//!
//! For each size the two backends are fed *identical* deterministic fixtures
//! and the results are asserted equal before the timings are reported, so the
//! speedup column is for provably-equal output.
//!
//! The Cpu backend is measured twice: on the default rayon pool (all cores —
//! this is what `--backend cpu` actually uses) and on a single-threaded pool.
//! arkworks builds here without its `parallel` feature, so the two columns
//! are near-identical; blst/MSM and the NTT are single-threaded, so `native`
//! is the single-threaded contender.  The end-to-end prover recovers the
//! multithread gap by running the four independent MSMs in parallel.
//!
//! Runs min-of-3 timed measurements after a single warm-up.  All numbers
//! printed by this binary are **measured on this machine**.
//!
//! Usage (release build, native feature):
//!
//! ```text
//! cargo run --release --features native -p trusted-setup --bin benchmark_backend
//! cargo run --release --features native -p trusted-setup --bin benchmark_backend -- --max-msm 4194304
//! ```

use ark_bls12_381::{Bls12_381, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{UniformRand, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use rand::rngs::StdRng;
use rand::SeedableRng;
use rayon::ThreadPool;
use std::time::Instant;

use trusted_setup::backend::{
    native_msm_g1, native_msm_g2, native_ntt, native_pairing_batch_check,
};

/// Deterministic RNG so both backends always see the same fixtures.
struct BenchRng(StdRng);

impl BenchRng {
    fn new(seed: u64) -> Self {
        BenchRng(StdRng::seed_from_u64(seed))
    }
    fn fr(&mut self) -> Fr {
        Fr::rand(&mut self.0)
    }
    fn g1(&mut self) -> G1Affine {
        G1Projective::rand(&mut self.0).into_affine()
    }
    fn g2(&mut self) -> G2Affine {
        G2Projective::rand(&mut self.0).into_affine()
    }
}

fn time<F: FnMut()>(mut f: F) -> std::time::Duration {
    let t = Instant::now();
    f();
    t.elapsed()
}

/// Min-of-`runs` timed measurement after one warm-up pass.
fn timed<F: FnMut()>(runs: usize, mut f: F) -> std::time::Duration {
    f(); // warm-up
    let mut best = time(&mut f);
    for _ in 1..runs {
        let d = time(&mut f);
        if d < best {
            best = d;
        }
    }
    best
}

fn ms(d: std::time::Duration) -> f64 {
    d.as_secs_f64() * 1e3
}

fn ratio(cpu: std::time::Duration, native: std::time::Duration) -> String {
    if native.is_zero() {
        return "n/a".into();
    }
    let r = cpu.as_secs_f64() / native.as_secs_f64();
    if r >= 1.0 {
        format!("{r:.2}x")
    } else {
        format!("{r:.2}x (slower)")
    }
}

/// Single-threaded CPU timing: ark MSM restricted to one rayon thread.
fn timed_cpu_1t<F: FnMut() + Send>(pool: &ThreadPool, runs: usize, mut f: F) -> std::time::Duration {
    timed(runs, || {
        let _ = pool.install(|| (&mut f)());
    })
}

fn bench_g1_msm(sizes: &[usize]) {
    let pool1 = single_thread_pool();
    println!("── G1 multi-scalar multiplication ─────────────────────────────────────────");
    println!(
        "{:<12} {:>20} {:>20} {:>20} {:>12} {:>12}",
        "n points", "cpu (Nt)", "cpu (1t)", "native (1t)", "vs cpu Nt", "vs cpu 1t"
    );
    for &n in sizes {
        let mut rng = BenchRng::new(0x51E + n as u64);
        let bases: Vec<G1Affine> = (0..n).map(|_| rng.g1()).collect();
        let scalars: Vec<Fr> = (0..n).map(|_| rng.fr()).collect();

        let expected = G1Projective::msm_unchecked(&bases, &scalars).into_affine();
        let native_out = native_msm_g1(&bases, &scalars).expect("native G1 MSM failed");
        assert_eq!(expected, native_out, "G1 MSM parity check failed for n={n}");

        let runs = if n >= 1 << 18 { 1 } else { 3 };
        let cpu_nt = timed(runs, || {
            let _ = std::hint::black_box(G1Projective::msm(&bases, &scalars).expect("MSM length mismatch"));
        });
        let cpu_1t = timed_cpu_1t(&pool1, runs, || {
            let _ = std::hint::black_box(G1Projective::msm(&bases, &scalars).expect("MSM length mismatch"));
        });
        let native = timed(runs, || {
            let _ = std::hint::black_box(native_msm_g1(&bases, &scalars).expect("native G1 MSM failed"));
        });

        println!(
            "{} {:>17.1}ms {:>17.1}ms {:>17.1}ms {:>9} {:>9}",
            format!("{:?}", n),
            ms(cpu_nt),
            ms(cpu_1t),
            ms(native),
            ratio(cpu_nt, native),
            ratio(cpu_1t, native),
        );
    }
    println!();
}

fn bench_g2_msm(sizes: &[usize]) {
    let pool1 = single_thread_pool();
    println!("── G2 multi-scalar multiplication ─────────────────────────────────────────");
    println!(
        "{:<12} {:>20} {:>20} {:>20} {:>12} {:>12}",
        "n points", "cpu (Nt)", "cpu (1t)", "native (1t)", "vs cpu Nt", "vs cpu 1t"
    );
    for &n in sizes {
        let mut rng = BenchRng::new(0xA11CE + n as u64);
        let bases: Vec<G2Affine> = (0..n).map(|_| rng.g2()).collect();
        let scalars: Vec<Fr> = (0..n).map(|_| rng.fr()).collect();

        let expected = G2Projective::msm_unchecked(&bases, &scalars).into_affine();
        let native_out = native_msm_g2(&bases, &scalars).expect("native G2 MSM failed");
        assert_eq!(expected, native_out, "G2 MSM parity check failed for n={n}");

        let runs = if n >= 1 << 18 { 1 } else { 3 };
        let cpu_nt = timed(runs, || {
            let _ = std::hint::black_box(G2Projective::msm(&bases, &scalars).expect("MSM length mismatch"));
        });
        let cpu_1t = timed_cpu_1t(&pool1, runs, || {
            let _ = std::hint::black_box(G2Projective::msm(&bases, &scalars).expect("MSM length mismatch"));
        });
        let native = timed(runs, || {
            let _ = std::hint::black_box(native_msm_g2(&bases, &scalars).expect("native G2 MSM failed"));
        });

        println!(
            "{} {:>17.1}ms {:>17.1}ms {:>17.1}ms {:>9} {:>9}",
            format!("{:?}", n),
            ms(cpu_nt),
            ms(cpu_1t),
            ms(native),
            ratio(cpu_nt, native),
            ratio(cpu_1t, native),
        );
    }
    println!();
}

fn bench_pairing(sizes: &[usize]) {
    let pool1 = single_thread_pool();
    println!("── multi-pairing product (G1×G2) ──────────────────────────────────────────");
    println!(
        "{:<12} {:>20} {:>20} {:>20} {:>12} {:>12}",
        "n pairs", "cpu (Nt)", "cpu (1t)", "native (1t)", "vs cpu Nt", "vs cpu 1t"
    );
    for &n in sizes {
        let mut rng = BenchRng::new(0x3A17 + n as u64);
        let g1: Vec<G1Affine> = (0..n).map(|_| rng.g1()).collect();
        let g2: Vec<G2Affine> = (0..n).map(|_| rng.g2()).collect();

        // A product of random pairings is not the identity; both backends must
        // agree the batch is invalid (should we ever disagree, revert).
        let native = native_pairing_batch_check(&g1, &g2).expect("native pairing failed");
        let prepared1: Vec<_> = g1
            .iter()
            .map(|&p| ark_ec::pairing::prepare_g1::<Bls12_381>(p))
            .collect();
        let prepared2: Vec<_> = g2
            .iter()
            .map(|&q| ark_ec::pairing::prepare_g2::<Bls12_381>(q))
            .collect();
        let cpu = Bls12_381::multi_pairing(prepared1, prepared2).is_zero();
        assert_eq!(cpu, native, "pairing parity check failed for n={n}");
        assert!(!native, "a product of random pairings must not be one");

        let runs = if n >= 128 { 3 } else { 5 };
        let cpu_nt = timed(runs, || {
            let p1: Vec<_> = g1
                .iter()
                .map(|&p| ark_ec::pairing::prepare_g1::<Bls12_381>(p))
                .collect();
            let p2: Vec<_> = g2
                .iter()
                .map(|&q| ark_ec::pairing::prepare_g2::<Bls12_381>(q))
                .collect();
            let _ = std::hint::black_box(Bls12_381::multi_pairing(p1, p2));
        });
        let cpu_1t = timed_cpu_1t(&pool1, runs, || {
            let p1: Vec<_> = g1
                .iter()
                .map(|&p| ark_ec::pairing::prepare_g1::<Bls12_381>(p))
                .collect();
            let p2: Vec<_> = g2
                .iter()
                .map(|&q| ark_ec::pairing::prepare_g2::<Bls12_381>(q))
                .collect();
            let _ = std::hint::black_box(Bls12_381::multi_pairing(p1, p2));
        });
        let native_t = timed(runs, || {
            let _ = std::hint::black_box(native_pairing_batch_check(&g1, &g2).expect("native pairing failed"));
        });

        println!(
            "{} {:>17.1}ms {:>17.1}ms {:>17.1}ms {:>9} {:>9}",
            format!("{:?}", n),
            ms(cpu_nt),
            ms(cpu_1t),
            ms(native_t),
            ratio(cpu_nt, native_t),
            ratio(cpu_1t, native_t),
        );
    }
    println!();
}

fn bench_ntt(sizes: &[usize]) {
    let pool1 = single_thread_pool();
    println!("── radix-2 NTT (Fr, forward) ──────────────────────────────────────");
    println!(
        "{:<12} {:>20} {:>20} {:>20} {:>12} {:>12}",
        "n", "cpu (Nt)", "cpu (1t)", "native (1t)", "vs cpu Nt", "vs cpu 1t"
    );
    for &n in sizes {
        let mut rng = BenchRng::new(0xB17 + n as u64);
        let data: Vec<Fr> = (0..n).map(|_| rng.fr()).collect();
        let domain = Radix2EvaluationDomain::<Fr>::new(n).expect("radix-2 domain");

        let mut ark_v = data.clone();
        domain.fft_in_place(&mut ark_v);
        let mut native_v = data.clone();
        native_ntt(&mut native_v, false).expect("native NTT failed");
        assert_eq!(ark_v, native_v, "NTT parity check failed for n={n}");

        let runs = 3;
        let cpu_nt = timed(runs, || {
            let mut v = data.clone();
            domain.fft_in_place(&mut v);
            let _ = std::hint::black_box(v);
        });
        let cpu_1t = timed_cpu_1t(&pool1, runs, || {
            let mut v = data.clone();
            domain.fft_in_place(&mut v);
            let _ = std::hint::black_box(v);
        });
        let native = timed(runs, || {
            let mut v = data.clone();
            native_ntt(&mut v, false).expect("native NTT failed");
            let _ = std::hint::black_box(v);
        });

        println!(
            "{} {:>17.1}ms {:>17.1}ms {:>17.1}ms {:>9} {:>9}",
            format!("{:?}", n),
            ms(cpu_nt),
            ms(cpu_1t),
            ms(native),
            ratio(cpu_nt, native),
            ratio(cpu_1t, native),
        );
    }
    println!();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut max_msm = 16_384usize;
    if let Some(pos) = args.iter().position(|a| a == "--max-msm") {
        max_msm = args[pos + 1].parse().expect("--max-msm needs an integer");
    }

    let n_threads = rayon::current_num_threads();
    println!("benchmark_backend — CPU (arkworks) vs NATIVE (blst), native backend v{}", trusted_setup::backend::native_version());
    println!("CPU measured on the default rayon pool ({n_threads} threads) and on a 1-thread pool.");
    println!("All numbers measured on this machine (min-of-3 after warm-up, release build).\n");

    let sizes: Vec<usize> = if args.iter().any(|a| a == "--max-msm") {
        vec![1_000usize, 16_384, max_msm]
    } else {
        vec![1_000usize, 16_384]
    };

    let g1_only = args.iter().any(|a| a == "--g1-only");
    let g2_only = args.iter().any(|a| a == "--g2-only");
    let pairing_only = args.iter().any(|a| a == "--pairing-only");
    let ntt_only = args.iter().any(|a| a == "--ntt-only");

    if !g2_only && !pairing_only && !ntt_only {
        bench_g1_msm(&sizes);
    }
    if !g1_only && !pairing_only && !ntt_only {
        bench_g2_msm(&sizes);
    }
    if !g1_only && !g2_only && !ntt_only {
        bench_pairing(&[1usize, 4, 16, 64, 256, 1024]);
    }
    if !g1_only && !g2_only && !pairing_only {
        bench_ntt(&[1_024usize, 16_384, 131_072]);
    }
}

fn single_thread_pool() -> ThreadPool {
    rayon::ThreadPoolBuilder::new().num_threads(1).build().unwrap()
}