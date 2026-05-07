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

#[test]
fn test_interoperability_hash_to_group() {
    // (a) Define a dummy private key (S = 1), empty message, empty DST, empty aug.
    //
    // Rust:  LE bytes [1, 0, ..., 0] -> sk_to_scalar -> BlsScalar(1)
    //        then hash_to_curve(msg, dst, aug) -> G2 point -> 1 * G2 -> compress
    //
    // Aiken: BE bytes [0, ..., 0, 1] -> bytearray_to_integer -> Int(1)
    //        then bls12_381_g2_hash_to_group(msg, dst) -> G2 point
    //        -> bls12_381_g2_scalar_mul(1, point) -> bls12_381_g2_compress

    let sk_le: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };
    let msg = b"";
    let dst = b"";
    let aug = b"";

    // (b) Rust: hash_to_group
    let sig_rust = bls12_381_aiken_cli::hash_to_group(&sk_le, msg, dst, aug)
        .expect("hash_to_group should succeed for S=1");

    let expected_sig: [u8; 96] = [
        182, 147, 39, 180, 156, 124, 127, 206, 87, 47, 228, 190, 8, 55, 22, 248, 173, 93, 28, 152,
        108, 68, 18, 14, 129, 201, 198, 192, 54, 253, 70, 72, 69, 254, 36, 237, 56, 207, 206, 147,
        208, 244, 100, 119, 25, 241, 187, 94, 1, 120, 124, 132, 125, 239, 69, 146, 204, 84, 101,
        108, 3, 50, 143, 44, 239, 98, 218, 133, 43, 108, 214, 28, 203, 161, 68, 126, 148, 198, 169,
        114, 82, 120, 72, 127, 40, 243, 199, 25, 242, 78, 41, 142, 158, 9, 58, 163,
    ];

    assert_eq!(sig_rust, expected_sig.to_vec());

    // (c) Aiken: hash_to_group(BE_bytes, msg, dst) produces the same sig.
    //     Verified by the interop_hash_to_group test in the Aiken project.
    // (d) Both compute the same 96-byte compressed G2 signature.
    run_aiken_check(&aiken_project_dir());
}
