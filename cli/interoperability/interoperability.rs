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
        .join("aiken")
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

#[test]
fn test_interoperability_scalar_mul_g1() {
    // (a) Scalar S = 1 in little-endian for Rust
    let scalar_one_le: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    // (b) Compressed G1 generator (48 bytes)
    let g1_gen: [u8; 48] = [
        151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140,
        79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26,
        239, 251, 58, 240, 10, 219, 34, 198, 187,
    ];

    // (c) Rust: scalar_mul(G1, generator, scalar=1) should return the generator
    let result = bls12_381_aiken_cli::scalar_mul(
        &bls12_381_aiken_cli::CurveGroup::G1,
        &g1_gen,
        &scalar_one_le,
    )
    .expect("scalar_mul G1 should succeed for S=1");

    assert_eq!(result, g1_gen.to_vec());

    // (d) Aiken: bls12_381_g1_scalar_mul(1, generator) |> compress produces the same bytes.
    //     Verified by the interop_g1_scalar_mul_s_1 test in the Aiken project.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_scalar_mul_g2() {
    // (a) Scalar S = 1 in little-endian for Rust
    let scalar_one_le: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    // (b) Compressed G2 generator (96 bytes)
    let g2_gen: [u8; 96] = [
        147, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160, 136, 39, 79, 101, 89, 107, 208,
        208, 153, 32, 182, 26, 181, 218, 97, 187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148, 93,
        87, 229, 172, 125, 5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5, 39, 45,
        197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100, 122, 227, 209, 119, 11,
        172, 3, 38, 168, 5, 187, 239, 212, 128, 86, 200, 193, 33, 189, 184,
    ];

    // (c) Rust: scalar_mul(G2, generator, scalar=1) should return the generator
    let result = bls12_381_aiken_cli::scalar_mul(
        &bls12_381_aiken_cli::CurveGroup::G2,
        &g2_gen,
        &scalar_one_le,
    )
    .expect("scalar_mul G2 should succeed for S=1");

    assert_eq!(result, g2_gen.to_vec());

    // (d) Aiken: bls12_381_g2_scalar_mul(1, generator) |> compress produces the same bytes.
    //     Verified by the interop_g2_scalar_mul_s_1 test in the Aiken project.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_group_add_g1() {
    // (a) Compressed G1 generator (48 bytes)
    let g1_gen: [u8; 48] = [
        151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140,
        79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26,
        239, 251, 58, 240, 10, 219, 34, 198, 187,
    ];

    // (b) Rust: group_add(G1, generator, generator) = 2*generator
    let result =
        bls12_381_aiken_cli::group_add(&bls12_381_aiken_cli::CurveGroup::G1, &g1_gen, &g1_gen)
            .expect("group_add G1 should succeed");

    let expected: [u8; 48] = [
        165, 114, 203, 234, 144, 77, 103, 70, 136, 8, 200, 235, 80, 169, 69, 12, 151, 33, 219, 48,
        145, 40, 1, 37, 67, 144, 45, 10, 195, 88, 166, 42, 226, 143, 117, 187, 143, 28, 124, 66,
        195, 154, 140, 85, 41, 191, 15, 78,
    ];
    assert_eq!(result, expected.to_vec());

    // (c) Rust: group_add(G1, identity, generator) = generator
    let identity = {
        let mut b = vec![0xc0u8];
        b.extend(std::iter::repeat(0u8).take(47));
        b
    };
    let result =
        bls12_381_aiken_cli::group_add(&bls12_381_aiken_cli::CurveGroup::G1, &identity, &g1_gen)
            .expect("group_add G1 identity+generator should succeed");
    assert_eq!(result, g1_gen.to_vec());

    // (d) Aiken: bls12_381_g1_add(generator, generator) |> compress and
    //     bls12_381_g1_add(identity, generator) |> compress produce the same bytes.
    //     Verified by the interop_g1_add_* tests in the Aiken project.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_group_add_g2() {
    // (a) Compressed G2 generator (96 bytes)
    let g2_gen: [u8; 96] = [
        147, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160, 136, 39, 79, 101, 89, 107, 208,
        208, 153, 32, 182, 26, 181, 218, 97, 187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148, 93,
        87, 229, 172, 125, 5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5, 39, 45,
        197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100, 122, 227, 209, 119, 11,
        172, 3, 38, 168, 5, 187, 239, 212, 128, 86, 200, 193, 33, 189, 184,
    ];

    // (b) Rust: group_add(G2, generator, generator) = 2*generator
    let result =
        bls12_381_aiken_cli::group_add(&bls12_381_aiken_cli::CurveGroup::G2, &g2_gen, &g2_gen)
            .expect("group_add G2 should succeed");

    let expected: [u8; 96] = [
        170, 78, 222, 249, 193, 237, 127, 114, 159, 82, 14, 71, 115, 10, 18, 79, 215, 6, 98, 169,
        4, 186, 16, 116, 114, 129, 20, 209, 3, 30, 21, 114, 198, 200, 134, 246, 181, 126, 199, 42,
        97, 120, 40, 140, 71, 195, 53, 119, 22, 56, 83, 57, 87, 213, 64, 169, 210, 55, 15, 23, 204,
        126, 213, 134, 59, 192, 185, 149, 184, 130, 94, 14, 225, 234, 30, 30, 77, 0, 219, 174, 129,
        241, 75, 11, 243, 97, 27, 120, 201, 82, 170, 202, 184, 39, 160, 83,
    ];
    assert_eq!(result, expected.to_vec());

    // (c) Rust: group_add(G2, identity, generator) = generator
    let identity = {
        let mut b = vec![0xc0u8];
        b.extend(std::iter::repeat(0u8).take(95));
        b
    };
    let result =
        bls12_381_aiken_cli::group_add(&bls12_381_aiken_cli::CurveGroup::G2, &identity, &g2_gen)
            .expect("group_add G2 identity+generator should succeed");
    assert_eq!(result, g2_gen.to_vec());

    // (d) Aiken: bls12_381_g2_add(generator, generator) |> compress and
    //     bls12_381_g2_add(identity, generator) |> compress produce the same bytes.
    //     Verified by the interop_g2_add_* tests in the Aiken project.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_scalar_mul_g1_identity() {
    // (a) Scalar S = 1 in little-endian for Rust
    let scalar_one_le: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    // (b) G1 identity: first byte 0xc0, rest zeros
    let identity = {
        let mut b = vec![0xc0u8];
        b.extend(std::iter::repeat(0u8).take(47));
        b
    };

    // (c) Rust: scalar_mul(G1, identity, scalar=1) should return identity
    let result = bls12_381_aiken_cli::scalar_mul(
        &bls12_381_aiken_cli::CurveGroup::G1,
        &identity,
        &scalar_one_le,
    )
    .expect("scalar_mul G1 identity should succeed");

    assert_eq!(result, identity);

    // (d) Aiken: bls12_381_g1_scalar_mul(1, zero) |> compress produces the same bytes.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_scalar_mul_g2_identity() {
    // (a) Scalar S = 1 in little-endian for Rust
    let scalar_one_le: [u8; 32] = {
        let mut b = [0u8; 32];
        b[0] = 1;
        b
    };

    // (b) G2 identity: first byte 0xc0, rest zeros
    let identity = {
        let mut b = vec![0xc0u8];
        b.extend(std::iter::repeat(0u8).take(95));
        b
    };

    // (c) Rust: scalar_mul(G2, identity, scalar=1) should return identity
    let result = bls12_381_aiken_cli::scalar_mul(
        &bls12_381_aiken_cli::CurveGroup::G2,
        &identity,
        &scalar_one_le,
    )
    .expect("scalar_mul G2 identity should succeed");

    assert_eq!(result, identity);

    // (d) Aiken: bls12_381_g2_scalar_mul(1, zero) |> compress produces the same bytes.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_group_add_g1_identity_plus_identity() {
    // (a) G1 identity: first byte 0xc0, rest zeros
    let identity = {
        let mut b = vec![0xc0u8];
        b.extend(std::iter::repeat(0u8).take(47));
        b
    };

    // (b) Rust: group_add(G1, identity, identity) should return identity
    let result =
        bls12_381_aiken_cli::group_add(&bls12_381_aiken_cli::CurveGroup::G1, &identity, &identity)
            .expect("group_add G1 identity+identity should succeed");

    assert_eq!(result, identity);

    // (c) Aiken: bls12_381_g1_add(zero, zero) |> compress produces the same bytes.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_group_add_g2_identity_plus_identity() {
    // (a) G2 identity: first byte 0xc0, rest zeros
    let identity = {
        let mut b = vec![0xc0u8];
        b.extend(std::iter::repeat(0u8).take(95));
        b
    };

    // (b) Rust: group_add(G2, identity, identity) should return identity
    let result =
        bls12_381_aiken_cli::group_add(&bls12_381_aiken_cli::CurveGroup::G2, &identity, &identity)
            .expect("group_add G2 identity+identity should succeed");

    assert_eq!(result, identity);

    // (c) Aiken: bls12_381_g2_add(zero, zero) |> compress produces the same bytes.
    run_aiken_check(&aiken_project_dir());
}
