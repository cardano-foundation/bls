use std::time::Instant;
use tracing::info;

pub fn main() {
    tracing_subscriber::fmt::init();

    let master_hex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\
                      202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
                      404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";
    let master: [u8; 96] = hex::decode(master_hex).expect("valid fixture hex").try_into().unwrap();

    let target_dir = std::env::temp_dir().join("jolt-guest-targets-strong");
    let mut program = guest::compile_derive_cardano_strong(&target_dir.to_string_lossy());

    let t0 = Instant::now();
    let shared_preprocessing = guest::preprocess_shared_derive_cardano_strong(&mut program).unwrap();
    let prover_preprocessing = guest::preprocess_prover_derive_cardano_strong(shared_preprocessing);
    let verifier_preprocessing =
        guest::verifier_preprocessing_from_prover_derive_cardano_strong(&prover_preprocessing);
    info!("preprocessing time: {:.3}s", t0.elapsed().as_secs_f64());

    let prove_derive_cardano_strong =
        guest::build_prover_derive_cardano_strong(program, prover_preprocessing);
    let verify_derive_cardano_strong =
        guest::build_verifier_derive_cardano_strong(verifier_preprocessing);

    let t1 = Instant::now();
    let (output, proof, io_device) = prove_derive_cardano_strong(&master);
    let prove_time = t1.elapsed();
    info!("prove time: {:.3}s", prove_time.as_secs_f64());

    jolt_sdk::serialize_and_print_size("proof", "/tmp/jolt-strong.proof", &proof).unwrap();

    let t2 = Instant::now();
    verify_derive_cardano_strong(&master, output, io_device.panic, proof)
        .expect("proof verification failed");
    info!("verify time: {:.3}s", t2.elapsed().as_secs_f64());

    info!("output (hex): {}", hex::encode(output));

    let expected = "63658c2ec89f2fc978bd99c4ee00c6057d6a5b0baa29dc9d62beb4c5e511862c";
    assert_eq!(hex::encode(output), expected, "fixture mismatch");
    info!("fixture OK");
}
