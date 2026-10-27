use std::time::Instant;

fn main() {
    tracing_subscriber::fmt::init();

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: uplc <program.flat> [--data-bytes HEX]...");
        std::process::exit(2);
    }

    let flat = std::fs::read(&args[1]).unwrap_or_else(|error| {
        eprintln!("failed to read {}: {error}", args[1]);
        std::process::exit(2);
    });

    let mut data_args = Vec::new();
    let mut index = 2;
    while index < args.len() {
        match args[index].as_str() {
            "--data-bytes" => {
                let value = args.get(index + 1).unwrap_or_else(|| {
                    eprintln!("--data-bytes requires a hex value");
                    std::process::exit(2);
                });
                let bytes = uplc_guest::hex_decode(value).unwrap_or_else(|| {
                    eprintln!("invalid hex value: {value}");
                    std::process::exit(2);
                });
                data_args.push(uplc_guest::Data::B(bytes));
                index += 2;
            }
            other => {
                eprintln!("unknown argument: {other}");
                std::process::exit(2);
            }
        }
    }

    let input_blob = encode_input_blob(&flat, &data_args);

    let target_dir = std::env::temp_dir().join("jolt-guest-targets-uplc-aiken");
    let mut program = guest::compile_uplc_eval(&target_dir.to_string_lossy());

    let t0 = Instant::now();
    let shared_preprocessing = guest::preprocess_shared_uplc_eval(&mut program).unwrap();
    let prover_preprocessing = guest::preprocess_prover_uplc_eval(shared_preprocessing);
    let verifier_preprocessing =
        guest::verifier_preprocessing_from_prover_uplc_eval(&prover_preprocessing);
    println!("preprocessing time: {:.3}s", t0.elapsed().as_secs_f64());

    let prove = guest::build_prover_uplc_eval(program, prover_preprocessing);
    let verify = guest::build_verifier_uplc_eval(verifier_preprocessing);

    let t1 = Instant::now();
    let (output, proof, io_device) = prove(&input_blob);
    let prove_time = t1.elapsed();
    println!("prove time: {:.3}s", prove_time.as_secs_f64());

    jolt_sdk::serialize_and_print_size("proof", "/tmp/jolt-uplc-hello-aiken.proof", &proof).unwrap();
    let t2 = Instant::now();
    verify(&input_blob, output, io_device.panic, proof).expect("proof verification failed");
    println!("verify time: {:.3}s", t2.elapsed().as_secs_f64());

    println!("output (hex): {}", hex::encode(output));
}

fn encode_input_blob(flat: &[u8], args: &[uplc_guest::Data]) -> Vec<u8> {
    let mut out = Vec::new();
    push_u32(&mut out, flat.len() as u32);
    out.extend_from_slice(flat);
    push_u32(&mut out, args.len() as u32);
    for arg in args {
        let uplc_guest::Data::B(bytes) = arg else {
            panic!("only Data::B arguments are supported");
        };
        push_u32(&mut out, bytes.len() as u32);
        out.extend_from_slice(bytes);
    }
    out
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}
