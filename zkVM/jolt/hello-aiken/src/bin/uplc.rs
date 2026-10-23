use std::time::Instant;

pub fn main() {
    tracing_subscriber::fmt::init();

    let target_dir = std::env::temp_dir().join("jolt-guest-targets-uplc-aiken");
    let mut program = guest::compile_uplc_hello_hash_aiken(&target_dir.to_string_lossy());

    let t0 = Instant::now();
    let shared_preprocessing = guest::preprocess_shared_uplc_hello_hash_aiken(&mut program).unwrap();
    let prover_preprocessing = guest::preprocess_prover_uplc_hello_hash_aiken(shared_preprocessing);
    let verifier_preprocessing =
        guest::verifier_preprocessing_from_prover_uplc_hello_hash_aiken(&prover_preprocessing);
    println!("preprocessing time: {:.3}s", t0.elapsed().as_secs_f64());

    let prove = guest::build_prover_uplc_hello_hash_aiken(program, prover_preprocessing);
    let verify = guest::build_verifier_uplc_hello_hash_aiken(verifier_preprocessing);

    let t1 = Instant::now();
    let (output, proof, io_device) = prove();
    let prove_time = t1.elapsed();
    println!("prove time: {:.3}s", prove_time.as_secs_f64());

    jolt_sdk::serialize_and_print_size("proof", "/tmp/jolt-uplc-hello-aiken.proof", &proof).unwrap();
    let t2 = Instant::now();
    verify(output, io_device.panic, proof).expect("proof verification failed");
    println!("verify time: {:.3}s", t2.elapsed().as_secs_f64());

    println!("output (hex): {}", hex::encode(output));
}
