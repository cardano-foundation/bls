use groth16_prover::r1cs::*;

fn main() {
    println!("=== Step 1.1: R1CS Matrices and Witness ===\n");

    println!("Witness a = {:?}", WITNESS);

    println!("\nL matrix:");
    for row in &L {
        println!("  {:?}", row);
    }

    println!("\nR matrix:");
    for row in &R {
        println!("  {:?}", row);
    }

    println!("\nO matrix:");
    for row in &O {
        println!("  {:?}", row);
    }

    let witness = witness_to_fr(&WITNESS);
    println!("\nWitness as Fr elements:");
    for (i, w) in witness.iter().enumerate() {
        println!("  a[{}] = {}", i, w);
    }

    let la = matrix_mul_vec(&L, &witness);
    let ra = matrix_mul_vec(&R, &witness);
    let oa = matrix_mul_vec(&O, &witness);

    println!("\nL · a = {:?}", la.iter().map(|f| f.to_string()).collect::<Vec<_>>());
    println!("R · a = {:?}", ra.iter().map(|f| f.to_string()).collect::<Vec<_>>());
    println!("O · a = {:?}", oa.iter().map(|f| f.to_string()).collect::<Vec<_>>());

    println!("\nElement-wise (L·a) * (R·a):");
    for i in 0..la.len() {
        let prod = la[i] * ra[i];
        println!("  constraint {}: {} * {} = {} (O·a = {})",
            i, la[i], ra[i], prod, oa[i]
        );
    }

    match verify_r1cs(&witness) {
        Ok(()) => println!("\n✓ R1CS relation verified."),
        Err(e) => println!("\n✗ R1CS relation failed: {}", e),
    }
}
