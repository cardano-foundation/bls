use std::process::Command;

fn aiken_available() -> bool {
    Command::new("which")
        .arg("aiken")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[test]
fn test_interoperability_sk_to_scalar() {
    // (a) Define a valid secret key (scalar S = 1)
    //
    // Note on endianness:
    //   Rust  BlsScalar::from_bytes_le  interprets bytes as little-endian.
    //   Aiken bytearray_to_integer(True, ...) interprets bytes as big-endian.
    //
    // To obtain the same scalar S = 1 in both environments we use:
    //   Rust:  LE bytes  [1, 0, ..., 0]   -> BlsScalar::from_bytes_le  -> S = 1
    //   Aiken: BE bytes  [0, ..., 0, 1]   -> bytearray_to_integer(True, ..) -> S = 1
    //
    // Both compute 1 * G1, yielding an identical public key.

    let sk_le: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    // (b) Invoke sk_to_scalar from lib.rs
    let scalar =
        bls12_381_aiken_cli::sk_to_scalar(&sk_le).expect("sk_to_scalar should succeed for S=1");

    assert_eq!(scalar, midnight_curves::BlsScalar::from(1u64));

    // Compute the public key from the Rust scalar: 1 * G1
    let pk_rust = bls12_381_aiken_cli::sk_to_pk(&sk_le).expect("sk_to_pk should succeed for S=1");

    // Expected compressed G1 public key for S=1 (the generator):
    //   97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb
    let expected_pk: [u8; 48] = [
        151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140,
        79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26,
        239, 251, 58, 240, 10, 219, 34, 198, 187,
    ];

    assert_eq!(pk_rust, expected_pk.to_vec());

    // (c) Invoke Aiken code with the corresponding big-endian key representation.
    let aiken_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("interoperability")
        .join("sk_to_scalar");

    if !aiken_available() {
        panic!(
            "aiken is not installed. Please install aiken (https://aiken-lang.org) to run this test."
        );
    }

    let output = Command::new("aiken")
        .args(["check"])
        .current_dir(&aiken_dir)
        .output()
        .expect("failed to run 'aiken check'");

    // (d) Results from (b) and (c) both compute the same public key.
    //     The Rust side verifies byte-exact pk matches above.
    //     The Aiken side (interop_pk_s_1) verifies its pk against the same
    //     hardcoded expected_pk.
    assert!(
        output.status.success(),
        "Aiken tests failed (see interop.ak for the matching test vectors):\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
