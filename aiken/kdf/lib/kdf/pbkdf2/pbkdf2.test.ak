use aiken/builtin
use aiken/primitive/bytearray
use kdf/pbkdf2/pbkdf2

// PRF used for all tests:  PRF(P, X) = sha256(P || X)
fn sha256_prf(pwd: ByteArray, data: ByteArray) -> ByteArray {
  builtin.sha2_256(bytearray.concat(pwd, data))
}

// -------------------------------------------------------------------
// Reference vectors generated with Python (sha256(P || X) PRF).
// -------------------------------------------------------------------

test pbkdf2_1_block_1_iter() {
  let result =
    pbkdf2.pbkdf2(sha256_prf, "password", "salt", 1, 32)
  result == #"4ade8a4c5397bdb867dbb7e253b4d4562388cdbf599713aaecd87fa7f3202044"
}

test pbkdf2_1_block_2_iter() {
  let result =
    pbkdf2.pbkdf2(sha256_prf, "password", "salt", 2, 32)
  result == #"eb81bb537eb16b0b73d0ad1ed9fb8727a6138a8c7c4b69496028e39d2ea0375a"
}

test pbkdf2_1_block_4096_iter() {
  let result =
    pbkdf2.pbkdf2(sha256_prf, "password", "salt", 4096, 32)
  result == #"8ab288ebdb68a28109ad3d26acaa83d6bd2a093b9382b08abb8db10203870500"
}

test pbkdf2_truncated_last_block() {
  let result =
    pbkdf2.pbkdf2(sha256_prf, "password", "salt", 1, 16)
  result == #"4ade8a4c5397bdb867dbb7e253b4d456"
}

test pbkdf2_2_blocks() {
  let result =
    pbkdf2.pbkdf2(sha256_prf, "password", "salt", 1, 64)
  result == #"4ade8a4c5397bdb867dbb7e253b4d4562388cdbf599713aaecd87fa7f32020444a3ba78bfe77a3e4ff33a7e6c4d4bfe254fc3723e188831bf61d14584f98a9b3"
}

test pbkdf2_long_password_salt_4096() {
  let result =
    pbkdf2.pbkdf2(
      sha256_prf,
      "passwordPASSWORD",
      "saltSALTsaltSALTsalt",
      4096,
      24,
    )
  result == #"d2bb3abaee88a46a300fc76618eb2a2c25f094741096be73"
}
