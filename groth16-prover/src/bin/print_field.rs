use ark_bls12_381::Fr;
use ark_ff::{Field, PrimeField};

fn main() {
    println!("=== Step 1.2: BLS12-381 Scalar Field Fr ===\n");
    println!("Fr modulus q = {}", Fr::MODULUS);

    let a = Fr::from(5u64);
    let b = Fr::from(7u64);

    println!("\nSample operations:");
    println!("  a = {}", a);
    println!("  b = {}", b);
    println!("  a + b = {}", a + b);
    println!("  a * b = {}", a * b);
    println!("  a^-1  = {}", a.inverse().unwrap());

    let c = Fr::from(123456789u64);
    let d = Fr::from(987654321u64);
    println!("\nLarger sample operations:");
    println!("  c = {}", c);
    println!("  d = {}", d);
    println!("  c + d = {}", c + d);
    println!("  c * d = {}", c * d);
    println!("  c^-1  = {}", c.inverse().unwrap());

    println!("\n✓ Field arithmetic cross-check values printed.");
}
