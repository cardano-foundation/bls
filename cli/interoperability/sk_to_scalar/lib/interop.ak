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
