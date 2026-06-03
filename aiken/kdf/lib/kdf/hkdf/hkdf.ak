use aiken/builtin
use aiken/primitive/bytearray
use kdf/kdf.{HashAlgo}

// -------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------

/// Map a HashAlgo to its corresponding hash function.
fn hash_from_algo(algo: HashAlgo) -> fn(ByteArray) -> ByteArray {
  when algo is {
    Sha256 -> fn(data) { builtin.sha2_256(data) }
    Sha3_256 -> fn(data) { builtin.sha3_256(data) }
    Keccak256 -> fn(data) { builtin.keccak_256(data) }
    Blake2b_224 -> fn(data) { builtin.blake2b_224(data) }
    Blake2b_256 -> fn(data) { builtin.blake2b_256(data) }
  }
}

pub fn hmac(algo: HashAlgo, key: ByteArray, msg: ByteArray) -> ByteArray {
  let block_size = 64
  let hash = hash_from_algo(algo)

  let i_key = xor_bytearray(True, key, replicate_byte(block_size, 0x36))

  let o_key = xor_bytearray(True, key, replicate_byte(block_size, 0x5c))

  hash(append_bytearray(o_key, hash(append_bytearray(i_key, msg))))
}
