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

let dk = pbkdf2.pbkdf2(
  fn(pwd, data) { builtin.sha2_256(bytearray.concat(pwd, data)) },
  "my_password",
  "my_salt",
  4096,
  32,
)
```

The function is generic over the pseudorandom function (`prf`).  The example above uses
`sha2_256` because SHA-512 is not available as a Plutus V3 builtin.  If a future Plutus
version exposes SHA-512 (or any other hash), you only need to change the closure passed
as the first argument.

## Budget considerations

PBKDF2 is intentionally expensive (the whole point of the iteration count is to slow down
brute-force attacks).  On-chain budgets are finite, so iteration counts and derived-key
lengths must be chosen carefully.

Rough numbers from the test suite (Plutus V3 / Aiken v1.1.21):

| Iterations | dkLen | CPU units | Memory |
|-----------|-------|-----------|--------|
| 1         | 32    | ~6.7 M    | ~20 K  |
| 2         | 32    | ~8.1 M    | ~24 K  |
| 4 096     | 32    | ~5.7 B    | ~17 M  |
| 4 096     | 24    | ~5.8 B    | ~17 M  |

A single block with a modest iteration count (e.g. 1–10) costs only a few million CPU
units and is easily affordable on-chain.  However, **4 096 iterations already consumes**
**roughly 5.7 billion CPU units**, which is a large fraction of the total transaction
budget.  If you need to run PBKDF2 inside a validator, tune `count` and `dk_len` to stay
within the remaining budget after your other script logic.

For reference, Cardano protocol parameters currently allow roughly **10 billion CPU units**
per transaction (subject to change with protocol updates).  Keep in mind that this budget
must be shared across all scripts, minting policies, and certificate validations in the
same transaction.
