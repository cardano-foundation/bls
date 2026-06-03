use kdf/kdf.{HashAlgo}
use kdf/pbkdf2/pbkdf2

test sha256_1_block_1_iter() {
  pbkdf2.kdf(Sha256, "password", "salt", 1, 32) == #"4ade8a4c5397bdb867dbb7e253b4d4562388cdbf599713aaecd87fa7f3202044"
}

test sha256_1_block_2_iter() {
  pbkdf2.kdf(Sha256, "password", "salt", 2, 32) == #"eb81bb537eb16b0b73d0ad1ed9fb8727a6138a8c7c4b69496028e39d2ea0375a"
}

test sha256_1_block_4096_iter() {
  pbkdf2.kdf(Sha256, "password", "salt", 4096, 32) == #"8ab288ebdb68a28109ad3d26acaa83d6bd2a093b9382b08abb8db10203870500"
}

test sha256_truncated_last_block() {
  pbkdf2.kdf(Sha256, "password", "salt", 1, 16) == #"4ade8a4c5397bdb867dbb7e253b4d456"
}

test sha256_2_blocks() {
  pbkdf2.kdf(Sha256, "password", "salt", 1, 64) == #"4ade8a4c5397bdb867dbb7e253b4d4562388cdbf599713aaecd87fa7f32020444a3ba78bfe77a3e4ff33a7e6c4d4bfe254fc3723e188831bf61d14584f98a9b3"
}

test sha256_long_password_salt_4096() {
  pbkdf2.kdf(
    Sha256,
    "passwordPASSWORD",
    "saltSALTsaltSALTsalt",
    4096,
    24,
  ) == #"d2bb3abaee88a46a300fc76618eb2a2c25f094741096be73"
}
