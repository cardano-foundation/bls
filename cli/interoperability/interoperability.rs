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
fn test_interoperability_compress_g1() {
    // (a) Compressed G1 generator (48 bytes)
    let g1_gen: [u8; 48] = [
        151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140,
        79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26,
        239, 251, 58, 240, 10, 219, 34, 198, 187,
    ];

    // (b) Rust: compress_point(G1, generator) should return the generator
    let result = bls12_381_aiken_cli::compress_point(&bls12_381_aiken_cli::CurveGroup::G1, &g1_gen)
        .expect("compress_point G1 should succeed");

    assert_eq!(result, g1_gen.to_vec());

    // (c) Aiken: bls12_381_g1_compress(generator) produces the same bytes.
    //     Verified by the interop_g1_compress_generator test in the Aiken project.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_compress_g2() {
    // (a) Compressed G2 generator (96 bytes)
    let g2_gen: [u8; 96] = [
        147, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160, 136, 39, 79, 101, 89, 107, 208,
        208, 153, 32, 182, 26, 181, 218, 97, 187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148, 93,
        87, 229, 172, 125, 5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5, 39, 45,
        197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100, 122, 227, 209, 119, 11,
        172, 3, 38, 168, 5, 187, 239, 212, 128, 86, 200, 193, 33, 189, 184,
    ];

    // (b) Rust: compress_point(G2, generator) should return the generator
    let result = bls12_381_aiken_cli::compress_point(&bls12_381_aiken_cli::CurveGroup::G2, &g2_gen)
        .expect("compress_point G2 should succeed");

    assert_eq!(result, g2_gen.to_vec());

    // (c) Aiken: bls12_381_g2_compress(g2.generator) produces the same bytes.
    //     Verified by the interop_g2_compress_generator test in the Aiken project.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_compress_g1_identity() {
    // (a) G1 identity: first byte 0xc0, rest zeros
    let identity = {
        let mut b = vec![0xc0u8];
        b.extend(std::iter::repeat(0u8).take(47));
        b
    };

    // (b) Rust: compress_point(G1, identity) should return identity
    let result =
        bls12_381_aiken_cli::compress_point(&bls12_381_aiken_cli::CurveGroup::G1, &identity)
            .expect("compress_point G1 identity should succeed");

    assert_eq!(result, identity);

    // (c) Aiken: bls12_381_g1_compress(zero) produces the same bytes.
    //     Verified by the interop_g1_compress_identity test in the Aiken project.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_compress_g2_identity() {
    // (a) G2 identity: first byte 0xc0, rest zeros
    let identity = {
        let mut b = vec![0xc0u8];
        b.extend(std::iter::repeat(0u8).take(95));
        b
    };

    // (b) Rust: compress_point(G2, identity) should return identity
    let result =
        bls12_381_aiken_cli::compress_point(&bls12_381_aiken_cli::CurveGroup::G2, &identity)
            .expect("compress_point G2 identity should succeed");

    assert_eq!(result, identity);

    // (c) Aiken: bls12_381_g2_compress(g2.zero) produces the same bytes.
    //     Verified by the interop_g2_compress_identity test in the Aiken project.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_uncompress_g1() {
    // (a) Compressed G1 generator (48 bytes)
    let g1_gen: [u8; 48] = [
        151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140,
        79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26,
        239, 251, 58, 240, 10, 219, 34, 198, 187,
    ];

    // (b) Rust: uncompress_point(G1, generator) then compress should round-trip
    let uncompressed =
        bls12_381_aiken_cli::uncompress_point(&bls12_381_aiken_cli::CurveGroup::G1, &g1_gen)
            .expect("uncompress_point G1 should succeed");
    assert_eq!(uncompressed.len(), 96);

    let recompressed =
        bls12_381_aiken_cli::compress_point(&bls12_381_aiken_cli::CurveGroup::G1, &uncompressed)
            .expect("compress_point G1 should succeed");
    assert_eq!(recompressed, g1_gen.to_vec());

    // (c) Aiken: bls12_381_g1_uncompress(generator) |> compress produces the same bytes.
    //     Verified by the interop_g1_uncompress_generator test in the Aiken project.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_uncompress_g2() {
    // (a) Compressed G2 generator (96 bytes)
    let g2_gen: [u8; 96] = [
        147, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160, 136, 39, 79, 101, 89, 107, 208,
        208, 153, 32, 182, 26, 181, 218, 97, 187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148, 93,
        87, 229, 172, 125, 5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5, 39, 45,
        197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100, 122, 227, 209, 119, 11,
        172, 3, 38, 168, 5, 187, 239, 212, 128, 86, 200, 193, 33, 189, 184,
    ];

    // (b) Rust: uncompress_point(G2, generator) then compress should round-trip
    let uncompressed =
        bls12_381_aiken_cli::uncompress_point(&bls12_381_aiken_cli::CurveGroup::G2, &g2_gen)
            .expect("uncompress_point G2 should succeed");
    assert_eq!(uncompressed.len(), 192);

    let recompressed =
        bls12_381_aiken_cli::compress_point(&bls12_381_aiken_cli::CurveGroup::G2, &uncompressed)
            .expect("compress_point G2 should succeed");
    assert_eq!(recompressed, g2_gen.to_vec());

    // (c) Aiken: bls12_381_g2_uncompress(generator) |> compress produces the same bytes.
    //     Verified by the interop_g2_uncompress_generator test in the Aiken project.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_uncompress_g1_identity() {
    // (a) G1 identity: first byte 0xc0, rest zeros
    let identity = {
        let mut b = vec![0xc0u8];
        b.extend(std::iter::repeat(0u8).take(47));
        b
    };

    // (b) Rust: uncompress_point(G1, identity) then compress should round-trip
    let uncompressed =
        bls12_381_aiken_cli::uncompress_point(&bls12_381_aiken_cli::CurveGroup::G1, &identity)
            .expect("uncompress_point G1 identity should succeed");
    assert_eq!(uncompressed.len(), 96);

    let recompressed =
        bls12_381_aiken_cli::compress_point(&bls12_381_aiken_cli::CurveGroup::G1, &uncompressed)
            .expect("compress_point G1 should succeed");
    assert_eq!(recompressed, identity);

    // (c) Aiken: bls12_381_g1_uncompress(identity) |> compress produces the same bytes.
    //     Verified by the interop_g1_uncompress_identity test in the Aiken project.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_uncompress_g2_identity() {
    // (a) G2 identity: first byte 0xc0, rest zeros
    let identity = {
        let mut b = vec![0xc0u8];
        b.extend(std::iter::repeat(0u8).take(95));
        b
    };

    // (b) Rust: uncompress_point(G2, identity) then compress should round-trip
    let uncompressed =
        bls12_381_aiken_cli::uncompress_point(&bls12_381_aiken_cli::CurveGroup::G2, &identity)
            .expect("uncompress_point G2 identity should succeed");
    assert_eq!(uncompressed.len(), 192);

    let recompressed =
        bls12_381_aiken_cli::compress_point(&bls12_381_aiken_cli::CurveGroup::G2, &uncompressed)
            .expect("compress_point G2 should succeed");
    assert_eq!(recompressed, identity);

    // (c) Aiken: bls12_381_g2_uncompress(identity) |> compress produces the same bytes.
    //     Verified by the interop_g2_uncompress_identity test in the Aiken project.
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

#[test]
fn test_interoperability_pairing_generators() {
    use blst::blst_fp12;
    use midnight_curves::bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};
    use midnight_curves::pairing::group::Group;
    use std::mem;

    // (a) Get G1 generator and G2 generator
    let g1 = G1Affine::from(G1Projective::generator());
    let g2 = G2Affine::from(G2Projective::generator());

    // (b) Compute pairing
    let gt = midnight_curves::bls12_381::pairing(&g1, &g2);
    let fp12: blst_fp12 = unsafe { mem::transmute(gt) };
    let gt_bytes = unsafe {
        std::slice::from_raw_parts(&fp12 as *const _ as *const u8, mem::size_of::<blst_fp12>())
    };

    // (c) Expected GT bytes for e(G1_gen, G2_gen)
    let expected_gt: [u8; 576] = [
        197, 133, 31, 160, 51, 228, 114, 25, 56, 37, 119, 253, 118, 43, 211, 151, 249, 205, 107,
        201, 111, 84, 206, 200, 20, 6, 212, 102, 115, 62, 246, 206, 128, 55, 132, 129, 39, 52, 17,
        166, 37, 216, 198, 63, 138, 68, 243, 19, 149, 105, 157, 46, 176, 49, 99, 210, 125, 126,
        121, 247, 130, 164, 104, 157, 146, 234, 57, 141, 36, 41, 155, 156, 170, 7, 49, 225, 162,
        28, 128, 244, 102, 176, 188, 189, 50, 7, 108, 161, 120, 4, 54, 186, 175, 164, 60, 8, 65,
        182, 22, 9, 219, 97, 226, 89, 13, 150, 62, 178, 244, 182, 22, 39, 69, 156, 189, 160, 16,
        91, 229, 200, 168, 237, 77, 156, 217, 11, 219, 11, 197, 170, 253, 87, 191, 158, 248, 140,
        94, 122, 119, 158, 146, 183, 214, 18, 53, 95, 225, 176, 136, 81, 200, 95, 101, 99, 9, 143,
        58, 110, 160, 52, 44, 214, 42, 224, 166, 38, 49, 219, 11, 153, 154, 125, 169, 90, 111, 252,
        16, 194, 137, 235, 245, 85, 47, 161, 137, 136, 111, 146, 58, 112, 35, 23, 120, 135, 130,
        113, 41, 143, 88, 147, 133, 117, 171, 17, 134, 91, 246, 67, 223, 159, 39, 236, 245, 170,
        131, 49, 246, 157, 201, 138, 225, 215, 115, 250, 176, 153, 76, 166, 166, 118, 225, 100, 31,
        143, 56, 88, 140, 167, 159, 23, 18, 239, 42, 202, 17, 10, 42, 103, 107, 241, 163, 42, 181,
        185, 17, 13, 110, 5, 157, 105, 208, 18, 68, 164, 165, 91, 26, 34, 119, 1, 29, 192, 41, 85,
        115, 108, 222, 206, 224, 102, 57, 195, 221, 159, 30, 167, 245, 5, 121, 198, 98, 176, 161,
        136, 10, 211, 4, 131, 252, 53, 93, 106, 197, 90, 13, 41, 31, 168, 166, 52, 200, 208, 199,
        7, 55, 218, 194, 48, 84, 205, 240, 10, 80, 128, 247, 127, 194, 240, 174, 46, 215, 226, 166,
        93, 36, 9, 86, 81, 27, 121, 118, 6, 46, 159, 19, 254, 24, 73, 35, 200, 209, 226, 244, 27,
        86, 60, 159, 69, 158, 76, 193, 227, 211, 185, 83, 94, 232, 163, 32, 0, 167, 33, 30, 18, 10,
        130, 204, 154, 197, 65, 131, 97, 175, 21, 177, 58, 153, 36, 140, 101, 149, 124, 185, 134,
        168, 28, 114, 56, 235, 115, 188, 52, 116, 71, 73, 215, 86, 82, 139, 74, 80, 234, 2, 25,
        164, 139, 109, 206, 134, 12, 248, 211, 163, 4, 170, 110, 104, 251, 135, 74, 166, 24, 38,
        207, 32, 185, 27, 231, 131, 187, 69, 57, 167, 146, 172, 119, 82, 42, 160, 70, 240, 148,
        159, 229, 14, 252, 247, 88, 96, 120, 243, 205, 88, 113, 246, 69, 249, 130, 27, 6, 193, 124,
        103, 229, 219, 159, 170, 71, 248, 3, 87, 230, 52, 97, 165, 219, 120, 128, 110, 138, 153,
        67, 154, 236, 215, 28, 102, 55, 153, 26, 154, 89, 170, 177, 68, 238, 66, 8, 47, 246, 160,
        201, 250, 223, 5, 182, 227, 155, 21, 142, 194, 63, 241, 74, 13, 186, 134, 12, 177, 255, 82,
        106, 160, 242, 15, 232, 108, 144, 26, 114, 72, 202, 148, 118, 20, 133, 176, 3, 62, 24, 131,
        117, 226, 228, 206, 64, 221, 175, 103, 245, 252, 165, 38, 229, 210, 150, 109, 154, 66, 34,
        31, 134, 73, 159, 126, 25,
    ];

    assert_eq!(gt_bytes.len(), 576);
    assert_eq!(gt_bytes, expected_gt);

    // (d) Aiken: bilinearity and identity pairing tests verify
    //     that Aiken's bls12_381_miller_loop and bls12_381_final_verify
    //     produce the same pairing results.
    run_aiken_check(&aiken_project_dir());
}

#[test]
fn test_interoperability_pairing_bilinearity_rust() {
    use midnight_curves::bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};
    use midnight_curves::pairing::group::Group;

    // (a) Compute e(2*G1, 3*G2)
    let g1 = G1Affine::from(G1Projective::generator());
    let g2 = G2Affine::from(G2Projective::generator());
    let scalar2 = midnight_curves::BlsScalar::from(2u64);
    let scalar3 = midnight_curves::BlsScalar::from(3u64);
    let scalar6 = midnight_curves::BlsScalar::from(6u64);

    let g1_2 = G1Affine::from(G1Projective::generator() * scalar2);
    let g2_3 = G2Affine::from(G2Projective::generator() * scalar3);
    let g1_6 = G1Affine::from(G1Projective::generator() * scalar6);

    let gt1 = midnight_curves::bls12_381::pairing(&g1_2, &g2_3);
    let gt2 = midnight_curves::bls12_381::pairing(&g1_6, &g2);

    // (b) Bilinearity: e(2*G1, 3*G2) should equal e(6*G1, G2)
    assert_eq!(gt1, gt2);

    // (c) Also verify e(G1, 6*G2) == e(6*G1, G2)
    let g2_6 = G2Affine::from(G2Projective::generator() * scalar6);
    let gt3 = midnight_curves::bls12_381::pairing(&g1, &g2_6);
    assert_eq!(gt2, gt3);
}

#[test]
fn test_interoperability_pairing_identity() {
    use midnight_curves::bls12_381::{G1Affine, G1Projective, G2Affine, G2Projective};
    use midnight_curves::pairing::group::prime::PrimeCurveAffine;
    use midnight_curves::pairing::group::Group;

    // (a) e(identity, G2) == e(G1, identity) == GT identity
    let g1 = G1Affine::from(G1Projective::generator());
    let g2 = G2Affine::from(G2Projective::generator());
    let g1_id = G1Affine::identity();
    let g2_id = G2Affine::identity();

    let gt_id_g1 = midnight_curves::bls12_381::pairing(&g1_id, &g2);
    let gt_id_g2 = midnight_curves::bls12_381::pairing(&g1, &g2_id);
    let gt_id_both = midnight_curves::bls12_381::pairing(&g1_id, &g2_id);

    assert_eq!(gt_id_g1, gt_id_g2);
    assert_eq!(gt_id_g1, gt_id_both);
}
