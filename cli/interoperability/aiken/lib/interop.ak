use aiken/builtin
use aiken/crypto/bls12_381/g1.{generator}

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
