use groth16_prover::r1cs::{select_circuit, matrix_mul_vec_dyn, verify_r1cs_circuit};

fn main() {
    let name = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: print_r1cs <multiplier|sumofproducts>");
        std::process::exit(1);
    });
    let circuit = select_circuit(&name);

    println!("=== Step 1.1: R1CS Matrices and Witness ===\n");
    println!("Circuit: {}", circuit.name);

    println!("\nWitness a = {:?}", circuit.witness.iter().map(|f| f.to_string()).collect::<Vec<_>>());

    println!("\nL matrix:");
    for row in &circuit.l {
        println!("  {:?}", row.iter().map(|f| f.to_string()).collect::<Vec<_>>());
    }

    println!("\nR matrix:");
    for row in &circuit.r {
        println!("  {:?}", row.iter().map(|f| f.to_string()).collect::<Vec<_>>());
    }

    println!("\nO matrix:");
    for row in &circuit.o {
        println!("  {:?}", row.iter().map(|f| f.to_string()).collect::<Vec<_>>());
    }

    println!("\nWitness as Fr elements:");
    for (i, w) in circuit.witness.iter().enumerate() {
        println!("  a[{}] = {}", i, w);
    }

    let la = matrix_mul_vec_dyn(&circuit.l, &circuit.witness);
    let ra = matrix_mul_vec_dyn(&circuit.r, &circuit.witness);
    let oa = matrix_mul_vec_dyn(&circuit.o, &circuit.witness);

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

    match verify_r1cs_circuit(&circuit) {
        Ok(()) => println!("\n✓ R1CS relation verified."),
        Err(e) => println!("\n✗ R1CS relation failed: {}", e),
    }
}
