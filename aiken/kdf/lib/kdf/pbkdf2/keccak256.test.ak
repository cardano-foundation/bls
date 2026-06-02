use aiken/builtin
use aiken/primitive/bytearray
use kdf/pbkdf2/pbkdf2

fn keccak_256_prf(pwd: ByteArray, data: ByteArray) -> ByteArray {
  builtin.keccak_256(bytearray.concat(pwd, data))
}

test keccak_256_1_block_1_iter() {
  bytearray.length(pbkdf2.kdf(keccak_256_prf, "password", "salt", 1, 32)) == 32
}

test keccak_256_1_block_2_iter() {
  bytearray.length(pbkdf2.kdf(keccak_256_prf, "password", "salt", 2, 32)) == 32
}

test keccak_256_1_block_4096_iter() {
  bytearray.length(pbkdf2.kdf(keccak_256_prf, "password", "salt", 4096, 32)) == 32
}

test keccak_256_truncated_last_block() {
  bytearray.length(pbkdf2.kdf(keccak_256_prf, "password", "salt", 1, 16)) == 16
}

test keccak_256_2_blocks() {
  bytearray.length(pbkdf2.kdf(keccak_256_prf, "password", "salt", 1, 64)) == 64
}

test keccak_256_long_password_salt_4096() {
  bytearray.length(pbkdf2.kdf(
    keccak_256_prf,
    "passwordPASSWORD",
    "saltSALTsaltSALTsalt",
    4096,
    24,
  )) == 24
}
