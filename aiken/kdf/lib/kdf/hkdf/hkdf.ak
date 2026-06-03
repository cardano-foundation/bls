use aiken/builtin
use aiken/primitive/bytearray

// -------------------------------------------------------------------
// Public types
// -------------------------------------------------------------------


// -------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------


// -------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------

pub fn hmac_sha256(key: ByteArray, msg: ByteArray) -> ByteArray {
  let block_size = 64

  let i_key = xor_bytearray(True, key, replicate_byte(block_size, 0x36))

  let o_key = xor_bytearray(True, key, replicate_byte(block_size, 0x5c))

  sha2_256(append_bytearray(o_key, sha2_256(append_bytearray(i_key, msg))))
}