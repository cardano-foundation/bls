# KDF (Key Derivation Function)

A key derivation function generates DETERMINISTICALLY a derived key from a base key and
additional parameters. Its goal is to take some source of initial
keying material and derive from it one or more cryptographically strong secret keys.
In a password-based key derivation function, the
base key is a password, and the additional parameters are an iteration count and a salt value.
The base key could also be a private key.

There are many standards focusing on KDF, namely [HKDF](https://datatracker.ietf.org/doc/html/rfc5869) and
[PBKDF2](https://datatracker.ietf.org/doc/html/rfc8018).

# PBKDF2

The library provides an Aiken-based implementation of the PBKDF2 scheme as outlined in
[RFC 8018, Section 5.2](https://datatracker.ietf.org/doc/html/rfc8018#page-11).

## Module

- `kdf/pbkdf2/pbkdf2` – generic PBKDF2 implementation.

## Usage

```aiken
use aiken/builtin
use aiken/primitive/bytearray
use kdf/pbkdf2/pbkdf2

let dk = pbkdf2.kdf(
  fn(pwd, data) { builtin.sha2_256(bytearray.concat(pwd, data)) },
  "my_password",
  "my_salt",
  4096,
  32,
)
```

The function is generic over the pseudorandom function (`prf`).  The example above uses
`sha2_256` because that is one of the hash builtins exposed as a Plutus V3 builtin
in Aiken v1.1.21.  If a future Plutus version exposes additional hashes (or any other
hash), you only need to change the closure passed as the first argument.

## Budget considerations

PBKDF2 is intentionally expensive (the whole point of the iteration count is to slow down
brute-force attacks).  On-chain budgets are finite, so iteration counts and derived-key
lengths must be chosen carefully.

Rough numbers from the test suite (Plutus V3 / Aiken v1.1.21).  All figures are for a single
block of output (dkLen == hLen) unless noted otherwise.

### SHA-2 (`builtin.sha2_256`, hLen = 32)

| Iterations | dkLen | CPU units | Memory |
|-----------|-------|-----------|--------|
| 1         | 32    | ~6.75 M   | ~20.4 K |
| 2         | 32    | ~8.15 M   | ~24.7 K |
| 4 096     | 32    | ~5.74 B   | ~17.7 M |
| 4 096     | 24    | ~5.83 B   | ~17.7 M |

### Blake2b (`builtin.blake2b_256`, hLen = 32)

| Iterations | dkLen | CPU units | Memory |
|-----------|-------|-----------|--------|
| 1         | 32    | ~6.56 M   | ~20.4 K |
| 2         | 32    | ~7.82 M   | ~24.7 K |
| 4 096     | 32    | ~5.16 B   | ~17.7 M |
| 4 096     | 24    | ~5.20 B   | ~17.7 M |

### Blake2b (`builtin.blake2b_224`, hLen = 28)

| Iterations | dkLen | CPU units | Memory |
|-----------|-------|-----------|--------|
| 1         | 28    | ~6.58 M   | ~20.4 K |
| 2         | 28    | ~7.84 M   | ~24.7 K |
| 4 096     | 28    | ~5.19 B   | ~17.7 M |
| 4 096     | 24    | ~5.22 B   | ~17.7 M |

**Key observation:** Blake2b is consistently cheaper than SHA-256.  For a single block with
1–2 iterations the saving is modest (~2–4 %).  At 4 096 iterations the difference becomes
significant: Blake2b-256 costs roughly **5.16 B CPU units** vs **5.74 B** for SHA-256, a
saving of about **10 %**.

A single block with a modest iteration count (e.g. 1–10) costs only a few million CPU
units and is easily affordable on-chain.  However, **4 096 iterations already consumes**
**roughly 5.2–5.8 billion CPU units**, which is a large fraction of the total transaction
budget.  If you need to run PBKDF2 inside a validator, tune `count` and `dk_len` to stay
within the remaining budget after your other script logic.

For reference, Cardano protocol parameters currently allow roughly **10 billion CPU units**
per transaction (subject to change with protocol updates).  Keep in mind that this budget
must be shared across all scripts, minting policies, and certificate validations in the
same transaction.

## Hash availability note

The following hash builtins were tested against this Aiken / Plutus V3 version:

| Builtin | Status | hLen |
|---------|--------|------|
| `builtin.sha2_256` | ✅ Available | 32 |
| `builtin.blake2b_256` | ✅ Available | 32 |
| `builtin.blake2b_224` | ✅ Available | 28 |

Because the PRF is passed as a closure, the implementation itself is completely generic.
Swapping to a different hash only requires changing the first argument when calling `kdf`.
