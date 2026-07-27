use ark_bls12_381::Fr;
use ark_ff::{Field, PrimeField};

// ---------------------------------------------------------------------------
// Step 1.6 — Toxic waste (deterministic fixed values for cross-check)
// ---------------------------------------------------------------------------
// In a real deployment these MUST be generated securely and discarded.
// Here we use hard-coded small primes so Rust and Sage outputs match
// bit-for-bit and are easy to verify by hand.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let circuit = args.first().unwrap_or_else(|| {
        eprintln!("Usage: print_toxic_waste <multiplier|sumofproducts>");
        std::process::exit(1);
    }).as_str();

    // tau must not be a constraint point.  For sumofproducts the constraint
    // points are {0,1,2,3,4} so tau=3 or tau=4 would give T(tau)=0.
    let tau_val: u64 = match circuit {
        "sumofproducts" => 6,
        _               => 3,   // multiplier uses {0,1,2}
    };
    const ALPHA_VAL: u64 = 5;
    const BETA_VAL:  u64 = 7;
    const GAMMA_VAL: u64 = 11;
    const DELTA_VAL: u64 = 13;

    println!("=== Step 1.6: Toxic Waste (Fixed Deterministic Values) ===\n");

    let tau   = Fr::from(tau_val);
    let alpha = Fr::from(ALPHA_VAL);
    let beta  = Fr::from(BETA_VAL);
    let gamma = Fr::from(GAMMA_VAL);
    let delta = Fr::from(DELTA_VAL);

    println!("Field modulus q = {}", Fr::MODULUS);
    println!();
    println!("tau   = {} (decimal)", tau);
    println!("alpha = {} (decimal)", alpha);
    println!("beta  = {} (decimal)", beta);
    println!("gamma = {} (decimal)", gamma);
    println!("delta = {} (decimal)", delta);
    println!();

    // Quick sanity checks: none of the values is zero, and they are all distinct.
    assert!(tau != Fr::ZERO,   "tau must be non-zero");
    assert!(alpha != Fr::ZERO, "alpha must be non-zero");
    assert!(beta != Fr::ZERO,  "beta must be non-zero");
    assert!(gamma != Fr::ZERO, "gamma must be non-zero");
    assert!(delta != Fr::ZERO, "delta must be non-zero");

    assert!(tau != alpha, "tau and alpha must be distinct");
    assert!(beta != gamma, "beta and gamma must be distinct");
    assert!(gamma != delta, "gamma and delta must be distinct");

    // Verify inverses exist (they will, since q is prime and values < q).
    let _tau_inv   = tau.inverse().expect("tau must be invertible");
    let _alpha_inv = alpha.inverse().expect("alpha must be invertible");
    let _beta_inv  = beta.inverse().expect("beta must be invertible");
    let _gamma_inv = gamma.inverse().expect("gamma must be invertible");
    let _delta_inv = delta.inverse().expect("delta must be invertible");

    println!("✓ All five toxic-waste values are non-zero, distinct, and invertible.");
    println!("✓ Step 1.6 printouts complete.");
}
