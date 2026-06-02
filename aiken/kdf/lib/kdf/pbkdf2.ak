use aiken/builtin
use aiken/primitive/bytearray

// -------------------------------------------------------------------
// Public API
// -------------------------------------------------------------------

/// PBKDF2 as specified in RFC 8018, Section 5.2.
///
/// The PRF is supplied by the caller.  For example, using the
/// SHA-256 builtin available in Aiken / Plutus V3:
///
/// ```aiken
/// fn(pwd, data) { builtin.sha2_256(bytearray.concat(pwd, data)) }
/// ```
///
/// Parameters:
/// - `prf`        – pseudorandom function `fn(ByteArray, ByteArray) -> ByteArray`
/// - `password`   – password or private key (octet string)
/// - `salt`       – salt (octet string)
/// - `count`      – iteration count, must be > 0
/// - `dk_len`     – intended length in octets of the derived key
///
/// Returns the derived key as a `ByteArray`.
pub fn pbkdf2(
  prf: fn(ByteArray, ByteArray) -> ByteArray,
  password: ByteArray,
  salt: ByteArray,
  count: Int,
  dk_len: Int,
) -> ByteArray {
  let h_len = bytearray.length(prf(#"", #""))

  if count <= 0 {
    fail @"iteration count must be a positive integer"
  } else if dk_len > 4294967295 * h_len {
    fail @"derived key too long"
  } else {
    let l = (dk_len + h_len - 1) / h_len
    let r = dk_len - (l - 1) * h_len
    derive_blocks(prf, password, salt, count, h_len, l, r, 1, #"")
  }
}

// -------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------

/// Compute a single block  Ti = F(P, S, c, i).
fn f(
  prf: fn(ByteArray, ByteArray) -> ByteArray,
  password: ByteArray,
  salt: ByteArray,
  count: Int,
  index: Int,
) -> ByteArray {
  let u1 =
    prf(
      password,
      bytearray.concat(salt, bytearray.from_int_big_endian(index, 4)),
    )
  f_iter(prf, password, count - 1, u1, u1)
}

/// Iterate Uj and accumulate the XOR sum.
fn f_iter(
  prf: fn(ByteArray, ByteArray) -> ByteArray,
  password: ByteArray,
  remaining: Int,
  prev: ByteArray,
  acc: ByteArray,
) -> ByteArray {
  if remaining <= 0 {
    acc
  } else {
    let next = prf(password, prev)
    f_iter(
      prf,
      password,
      remaining - 1,
      next,
      builtin.xor_bytearray(True, acc, next),
    )
  }
}

/// Concatenate blocks T1..Tl, trimming the last block to `r` octets.
fn derive_blocks(
  prf: fn(ByteArray, ByteArray) -> ByteArray,
  password: ByteArray,
  salt: ByteArray,
  count: Int,
  h_len: Int,
  l: Int,
  r: Int,
  i: Int,
  acc: ByteArray,
) -> ByteArray {
  if i > l {
    acc
  } else {
    let ti = f(prf, password, salt, count, i)
    let ti_trimmed = if i == l { bytearray.take(ti, r) } else { ti }
    derive_blocks(
      prf,
      password,
      salt,
      count,
      h_len,
      l,
      r,
      i + 1,
      bytearray.concat(acc, ti_trimmed),
    )
  }
}
