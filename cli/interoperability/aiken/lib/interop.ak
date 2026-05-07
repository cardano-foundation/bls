use aiken/builtin
use aiken/crypto/bls12_381/g1.{generator, zero}
use aiken/crypto/bls12_381/g2

fn internal_skToPk(sk: ByteArray) -> ByteArray {
  let s = builtin.bytearray_to_integer(True, sk)
  expect s != 0
  builtin.bls12_381_g1_scalar_mul(s, generator)
    |> builtin.bls12_381_g1_compress
}

test interop_scalar_s_1() {
  let sk: ByteArray = #[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
  let s = builtin.bytearray_to_integer(True, sk)
  s == 1
}

test interop_pk_s_1() {
  let sk: ByteArray = #[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
  let expected_pk: ByteArray = #[151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140, 79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26, 239, 251, 58, 240, 10, 219, 34, 198, 187]
  let pk = internal_skToPk(sk)
  pk == expected_pk
}

fn hash_to_group(sk: ByteArray, message: ByteArray, dst: ByteArray) -> ByteArray {
  let s = builtin.bytearray_to_integer(True, sk)
  expect s != 0
  builtin.bls12_381_g2_hash_to_group(message, dst)
    |> builtin.bls12_381_g2_scalar_mul(s, _)
    |> builtin.bls12_381_g2_compress
}

test interop_hash_to_group() {
  let sk: ByteArray = #[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
  let expected_sig: ByteArray = #[182, 147, 39, 180, 156, 124, 127, 206, 87, 47, 228, 190, 8, 55, 22, 248, 173, 93, 28, 152, 108, 68, 18, 14, 129, 201, 198, 192, 54, 253, 70, 72, 69, 254, 36, 237, 56, 207, 206, 147, 208, 244, 100, 119, 25, 241, 187, 94, 1, 120, 124, 132, 125, 239, 69, 146, 204, 84, 101, 108, 3, 50, 143, 44, 239, 98, 218, 133, 43, 108, 214, 28, 203, 161, 68, 126, 148, 198, 169, 114, 82, 120, 72, 127, 40, 243, 199, 25, 242, 78, 41, 142, 158, 9, 58, 163]
  let sig = hash_to_group(sk, "", "")
  sig == expected_sig
}

test interop_g1_scalar_mul_s_1() {
  let result = builtin.bls12_381_g1_scalar_mul(1, generator)
    |> builtin.bls12_381_g1_compress
  let expected: ByteArray = #[151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140, 79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26, 239, 251, 58, 240, 10, 219, 34, 198, 187]
  result == expected
}

test interop_g2_scalar_mul_s_1() {
  let result = builtin.bls12_381_g2_scalar_mul(1, g2.generator)
    |> builtin.bls12_381_g2_compress
  let expected: ByteArray = #[147, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160, 136, 39, 79, 101, 89, 107, 208, 208, 153, 32, 182, 26, 181, 218, 97, 187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148, 93, 87, 229, 172, 125, 5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5, 39, 45, 197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100, 122, 227, 209, 119, 11, 172, 3, 38, 168, 5, 187, 239, 212, 128, 86, 200, 193, 33, 189, 184]
  result == expected
}

test interop_g1_add_generator_plus_generator() {
  let result = builtin.bls12_381_g1_add(generator, generator)
    |> builtin.bls12_381_g1_compress
  let expected: ByteArray = #[165, 114, 203, 234, 144, 77, 103, 70, 136, 8, 200, 235, 80, 169, 69, 12, 151, 33, 219, 48, 145, 40, 1, 37, 67, 144, 45, 10, 195, 88, 166, 42, 226, 143, 117, 187, 143, 28, 124, 66, 195, 154, 140, 85, 41, 191, 15, 78]
  result == expected
}

test interop_g2_add_generator_plus_generator() {
  let result = builtin.bls12_381_g2_add(g2.generator, g2.generator)
    |> builtin.bls12_381_g2_compress
  let expected: ByteArray = #[170, 78, 222, 249, 193, 237, 127, 114, 159, 82, 14, 71, 115, 10, 18, 79, 215, 6, 98, 169, 4, 186, 16, 116, 114, 129, 20, 209, 3, 30, 21, 114, 198, 200, 134, 246, 181, 126, 199, 42, 97, 120, 40, 140, 71, 195, 53, 119, 22, 56, 83, 57, 87, 213, 64, 169, 210, 55, 15, 23, 204, 126, 213, 134, 59, 192, 185, 149, 184, 130, 94, 14, 225, 234, 30, 30, 77, 0, 219, 174, 129, 241, 75, 11, 243, 97, 27, 120, 201, 82, 170, 202, 184, 39, 160, 83]
  result == expected
}

test interop_g1_add_identity_plus_generator() {
  let result = builtin.bls12_381_g1_add(zero, generator)
    |> builtin.bls12_381_g1_compress
  let expected: ByteArray = #[151, 241, 211, 167, 49, 151, 215, 148, 38, 149, 99, 140, 79, 169, 172, 15, 195, 104, 140, 79, 151, 116, 185, 5, 161, 78, 58, 63, 23, 27, 172, 88, 108, 85, 232, 63, 249, 122, 26, 239, 251, 58, 240, 10, 219, 34, 198, 187]
  result == expected
}

test interop_g2_add_identity_plus_generator() {
  let result = builtin.bls12_381_g2_add(g2.zero, g2.generator)
    |> builtin.bls12_381_g2_compress
  let expected: ByteArray = #[147, 224, 43, 96, 82, 113, 159, 96, 125, 172, 211, 160, 136, 39, 79, 101, 89, 107, 208, 208, 153, 32, 182, 26, 181, 218, 97, 187, 220, 127, 80, 73, 51, 76, 241, 18, 19, 148, 93, 87, 229, 172, 125, 5, 93, 4, 43, 126, 2, 74, 162, 178, 240, 143, 10, 145, 38, 8, 5, 39, 45, 197, 16, 81, 198, 228, 122, 212, 250, 64, 59, 2, 180, 81, 11, 100, 122, 227, 209, 119, 11, 172, 3, 38, 168, 5, 187, 239, 212, 128, 86, 200, 193, 33, 189, 184]
  result == expected
}

test interop_g1_scalar_mul_identity() {
  let result = builtin.bls12_381_g1_scalar_mul(1, zero)
    |> builtin.bls12_381_g1_compress
  let expected: ByteArray = #[192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  result == expected
}

test interop_g2_scalar_mul_identity() {
  let result = builtin.bls12_381_g2_scalar_mul(1, g2.zero)
    |> builtin.bls12_381_g2_compress
  let expected: ByteArray = #[192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  result == expected
}

test interop_g1_add_identity_plus_identity() {
  let result = builtin.bls12_381_g1_add(zero, zero)
    |> builtin.bls12_381_g1_compress
  let expected: ByteArray = #[192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  result == expected
}

test interop_g2_add_identity_plus_identity() {
  let result = builtin.bls12_381_g2_add(g2.zero, g2.zero)
    |> builtin.bls12_381_g2_compress
  let expected: ByteArray = #[192, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
  result == expected
}
