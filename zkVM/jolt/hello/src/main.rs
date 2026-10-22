use std::time::Instant;
use tracing::info;

pub fn main() {
    tracing_subscriber::fmt::init();

    let target_dir = std::env::temp_dir().join("jolt-guest-targets");
    let mut program = guest::compile_hello_world(&target_dir.to_string_lossy());

    let t0 = Instant::now();
    let shared_preprocessing = guest::preprocess_shared_hello_world(&mut program).unwrap();
    let prover_preprocessing = guest::preprocess_prover_hello_world(shared_preprocessing);
    let verifier_preprocessing =
        guest::verifier_preprocessing_from_prover_hello_world(&prover_preprocessing);
    info!("preprocessing time: {:.3}s", t0.elapsed().as_secs_f64());

    let prove_hello_world = guest::build_prover_hello_world(program, prover_preprocessing);
    let verify_hello_world = guest::build_verifier_hello_world(verifier_preprocessing);

    let t1 = Instant::now();
    let (output, proof, io_device) = prove_hello_world();
    let prove_time = t1.elapsed();
    info!("prove time: {:.3}s", prove_time.as_secs_f64());

    jolt_sdk::serialize_and_print_size("proof", "/tmp/jolt-hello.proof", &proof).unwrap();
    let t2 = Instant::now();
    verify_hello_world(output, io_device.panic, proof).expect("proof verification failed");
    info!("verify time: {:.3}s", t2.elapsed().as_secs_f64());

    info!("output (hex): {}", hex::encode(output));
}
