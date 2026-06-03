use kdf/kdf.{HashAlgo}
use kdf/hkdf/hkdf

test extract_sha256_test_case_1() {
  let ikm = #"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  let salt = #"000102030405060708090a0b0c"
  let prk = hkdf.extract(Sha256, salt, ikm)
  prk == #"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
}

test expand_sha256_test_case_1() {
  let prk = #"077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
  let info = #"f0f1f2f3f4f5f6f7f8f9"
  let okm = hkdf.expand(Sha256, prk, info, 42)
  okm == #"3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
}

test extract_sha256_test_case_3_zero_salt() {
  let ikm = #"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"
  let prk = hkdf.extract(Sha256, #"", ikm)
  prk == #"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
}

test expand_sha256_test_case_3() {
  let prk = #"19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
  let okm = hkdf.expand(Sha256, prk, #"", 42)
  okm == #"8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
}
