use ark_bls12_381::Fr;
use ark_poly::Polynomial;
use groth16_prover::engine::{DenseQapEngine, FftQapEngine, QapEngine};
use groth16_prover::r1cs::{L, R, O};

fn main() {
    println!("=== QAP Engine Comparison: Dense vs FFT ===\n");

    let dense = DenseQapEngine::new();
    let fft = FftQapEngine::new();

    println!("--- Building QAP polynomials ---");
    let (dense_us, dense_vs, dense_ws) = dense.build_qap(&L, &R, &O);
    let (fft_us, fft_vs, fft_ws) = fft.build_qap(&L, &R, &O);

    println!("Dense QAP (degree ≤ 2):");
    for i in 0..8 {
        println!("  u_{} degree = {}, coeffs = {:?}", i, dense_us[i].degree(),
            dense_us[i].coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    }

    println!("\nFFT QAP (padded to domain size 4):");
    for i in 0..8 {
        println!("  u_{} degree = {}, coeffs = {:?}", i, fft_us[i].degree(),
            fft_us[i].coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    }

    println!("\n--- Parity check: evaluate both at random points ---");
    let test_points = [Fr::from(5u64), Fr::from(7u64), Fr::from(11u64)];
    let mut all_match = true;
    for &x in &test_points {
        for i in 0..8 {
            let du = dense_us[i].evaluate(&x);
            let fu = fft_us[i].evaluate(&x);
            if du != fu {
                println!("  MISMATCH: u_{} at {}: dense={}, fft={}", i, x, du, fu);
                all_match = false;
            }
        }
    }
    if all_match {
        println!("  All evaluations match ✓");
    }

    println!("\n--- Target polynomial ---");
    let dense_t = dense.target_poly(3);
    let fft_t = fft.target_poly(3);
    println!("Dense T(x) degree = {}, coeffs = {:?}", dense_t.degree(),
        dense_t.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());
    println!("FFT  T(x) degree = {}, coeffs = {:?}", fft_t.degree(),
        fft_t.coeffs.iter().map(|c| c.to_string()).collect::<Vec<_>>());

    println!("\n--- Per-variable QAP at τ = 3 ---");
    let tau = Fr::from(3u64);
    let (dense_u_tau, dense_v_tau, dense_w_tau) = dense.evaluate_qap_at_tau(&L, &R, &O, tau);
    let (fft_u_tau, fft_v_tau, fft_w_tau) = fft.evaluate_qap_at_tau(&L, &R, &O, tau);

    println!("Wire | Dense u_s(τ) | FFT u_s(τ) | Match?");
    for i in 0..8 {
        let match_str = if dense_u_tau[i] == fft_u_tau[i] { "✓" } else { "✗" };
        println!("  {:4} | {:14} | {:12} | {}", i, dense_u_tau[i], fft_u_tau[i], match_str);
    }

    println!("\n--- Quotient parity check ---");
    let witness: Vec<Fr> = groth16_prover::r1cs::WITNESS.iter().map(|&v| Fr::from(v)).collect();
    let (dense_l, dense_r, dense_o, dense_h, dense_t_tau) =
        groth16_prover::engine::evaluate_witness_and_quotient(&dense, &L, &R, &O, &witness, tau);
    let (fft_l, fft_r, fft_o, fft_h, fft_t_tau) =
        groth16_prover::engine::evaluate_witness_and_quotient(&fft, &L, &R, &O, &witness, tau);

    println!("Dense: l(τ)={}, r(τ)={}, o(τ)={}, h(τ)={}, T(τ)={}",
        dense_l, dense_r, dense_o, dense_h, dense_t_tau);
    println!("FFT:   l(τ)={}, r(τ)={}, o(τ)={}, h(τ)={}, T(τ)={}",
        fft_l, fft_r, fft_o, fft_h, fft_t_tau);

    let l_match = dense_l == fft_l;
    let r_match = dense_r == fft_r;
    let o_match = dense_o == fft_o;
    let h_match = dense_h == fft_h;
    let t_match = dense_t_tau == fft_t_tau;

    println!("\nParity results:");
    println!("  l(τ)  match: {}", if l_match { "✓" } else { "✗" });
    println!("  r(τ)  match: {}", if r_match { "✓" } else { "✗" });
    println!("  o(τ)  match: {}", if o_match { "✓" } else { "✗" });
    println!("  h(τ)  match: {}", if h_match { "✓" } else { "✗" });
    println!("  T(τ)  match: {}", if t_match { "✓" } else { "✗" });

    if l_match && r_match && o_match && h_match && t_match {
        println!("\n✓ All parity checks passed. The dense and FFT paths produce identical values.");
    } else {
        println!("\n⚠ The dense and FFT paths produce DIFFERENT values at τ = 3.");
        println!("  This is EXPECTED and CORRECT — see explanation below.");
        println!();
        println!("Why they differ:");
        println!("  - Dense path interpolates QAP over the points {{0, 1, 2}}.");
        println!("  - FFT path interpolates QAP over the 4-th roots of unity.");
        println!("  - Both polynomials pass through the SAME gate values, but on DIFFERENT domains.");
        println!("  - Evaluating at the same τ gives different scalars, so proof A, B, C differ.");
        println!();
        println!("Important: each path is internally self-consistent.");
        println!("  - Dense proof verifies with dense target T(x) = x³ - 3x² + 2x.");
        println!("  - FFT proof verifies with FFT target T(x) = x⁴ - 1.");
        println!();
        println!("To align the two paths (bit-for-bit match), one side must adopt the other's domain.");
    }
}
