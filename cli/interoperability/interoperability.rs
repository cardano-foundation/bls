use std::process::Command;

fn aiken_available() -> bool {
    Command::new("which")
        .arg("aiken")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn run_aiken_check(aiken_dir: &std::path::Path) {
    if !aiken_available() {
        panic!(
            "aiken is not installed. Please install aiken (https://aiken-lang.org) to run this test."
        );
    }

    let output = Command::new("aiken")
        .args(["check"])
        .current_dir(aiken_dir)
        .output()
        .expect("failed to run 'aiken check'");

    assert!(
        output.status.success(),
        "Aiken tests failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn aiken_project_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("interoperability")
        .join("sk_to_scalar")
}

#[test]
fn test_interoperability_sk_to_scalar() {
    // (a) Define a valid secret key for scalar S = 1
    //
    // Rust  BlsScalar::from_bytes_le  interprets bytes as little-endian.
    // Aiken bytearray_to_integer(True, ...) interprets bytes as big-endian.
    //
    // For the same scalar S = 1:
    //   Rust:  LE bytes  [1, 0, ..., 0]    -> sk_to_scalar -> BlsScalar(1)
    //   Aiken: BE bytes  [0, ..., 0, 1]    -> bytearray_to_integer(True, ...) -> Int(1)
    // Both produce the same scalar value 1.

    let sk_le: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    // (b) Rust: sk_to_scalar(LE_bytes) == BlsScalar(1)
    let scalar =
        bls12_381_aiken_cli::sk_to_scalar(&sk_le).expect("sk_to_scalar should succeed for S=1");

    assert_eq!(scalar, midnight_curves::BlsScalar::from(1u64));

    // (c) Aiken: bytearray_to_integer(True, BE_bytes) == 1
    //     Verified by the interop_scalar_s_1 test in the Aiken project.
    // (d) Both compute the same scalar value S = 1.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_sk_to_pk() {
    // (a) Define the same secret key (scalar S = 1)
    //
    // Rust:  LE bytes  [1, 0, ..., 0]    -> sk_to_pk -> pk_rust
    // Aiken: BE bytes  [0, ..., 0, 1]    -> internal_skToPk -> pk_aiken
    // Both compute 1 * G1 -> same compressed G1 public key.

    let sk_le: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    // (c) Rust: sk_to_pk(LE_bytes) produces the compressed G1 generator
    let pk_rust = bls12_381_aiken_cli::sk_to_pk(&sk_le).expect("sk_to_pk should succeed for S=1");

    // Expected compressed G1 public key for S=1 (the generator):
    //   97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
    let expected_pk: [u8; 48] = [
        151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140,
        79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26,
        239, 251, 58, 240, 10, 219, 34, 198, 187,
    ];

    assert_eq!(pk_rust, expected_pk.to_vec());

    // (d) Aiken: internal_skToPk(BE_bytes) produces the same pk.
    //     Verified by the interop_pk_s_1 test in the Aiken project.
    run_aiken_check(&aiken_project_dir());
}
