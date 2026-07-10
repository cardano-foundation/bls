# KDF & Key Generation

This library provides **Key Derivation Functions (KDF)** for on-chain execution on Cardano,
together with a thin key-generation layer built on top of those KDFs.

## What is a KDF?

A Key Derivation Function takes some initial keying material — a password, a shared secret,
or random bytes — and deterministically produces one or more cryptographically strong secret keys.
KDFs are foundational for wallet key hierarchies, session-key agreement, and password-based encryption.

> **Critical security warning.** Everything passed into an on-chain script—redeemers, datums, script arguments—is **permanently visible on the blockchain**. If you supply a password or a salt to `gen_keys_pbkdf2` or `gen_keys_hkdf` inside a validator, anyone can read the transaction, extract the password and salt, and re-run the same KDF off-chain. This means the on-chain KDF functions are **not suitable for password hashing in production**. They are intended for narrow use cases: testing, deriving keys from values that are *already* public or committed (e.g., a Diffie-Hellman shared secret computed off-chain by both parties), or educational examples. If you need to hash a human password, do it **off-chain** in the wallet or application layer, and only submit the resulting public key or hash on-chain.

## What this library offers

| Layer | Module | Purpose |
|---|---|---|
| **KDF primitives** (the core) | `kdf/hkdf/hkdf`, `kdf/pbkdf2/pbkdf2` | RFC-compliant HKDF and PBKDF2 implementations |
| **Key generation** (built on KDF) | `kdf/keys` | Private / public key pair generation that **runs the KDF primitives internally**, then maps the derived material onto the **BLS12-381** curve using Aiken's native primitives (`builtin.bls12_381_*`) |

Both KDF modules share a common `HashAlgo` enum defined in `kdf/kdf`:

```aiken
use kdf/kdf.{HashAlgo}
```

Variants: `Sha256`, `Sha3_256`, `Keccak256`, `Blake2b_224`, `Blake2b_256`.

### Supported standards

- **[HKDF](https://datatracker.ietf.org/doc/html/rfc5869)** (RFC 5869) — fast, HMAC-based Extract-then-Expand; ideal for high-entropy inputs
- **[PBKDF2](https://datatracker.ietf.org/doc/html/rfc8018)** (RFC 8018 §5.2) — intentionally slow, iteration-based; ideal for password hardening

---

# Key generation (`kdf/keys`)

The `kdf/keys` module provides a high-level interface for generating private / public key pairs from arbitrary input material.  It currently supports the **BLS12-381** curve on the **G1 prime field**.

## Quick start

### Generate a key pair with PBKDF2

```aiken
use kdf/keys

let (sk, pk) = keys.gen_keys_pbkdf2(
  salt: "my_salt",
  ikm:  "my_password",
)
```

**Defaults chosen by `gen_keys_pbkdf2`:**
- Scheme: `PBKDF2`
- Hash: `Sha256`
- Iterations: `10` (safe for on-chain budgets, ~160 M CPU units)
- Curve: `BLS12_381`
- Output length: **32 bytes**

### Generate a key pair with HKDF

```aiken
use kdf/keys

let (sk, pk) = keys.gen_keys_hkdf(
  salt: "my_salt",
  ikm:  "high_entropy_secret",
)
```

**Defaults chosen by `gen_keys_hkdf`:**
- Scheme: `HKDF`
- Hash: `Sha256`
- Info: empty
- Curve: `BLS12_381`
- Output length: **32 bytes**

### Full-control generation

If the defaults do not fit your use-case, use `gen_keys_detail` to tune every parameter:

```aiken
use kdf/keys.{PBKDF2, HKDF, BLS12_381}
use kdf/kdf.{Sha256}

let (sk, pk) = keys.gen_keys_detail(
  PBKDF2,
  BLS12_381,
  Sha256,
  salt:   "salt",
  ikm:    "password",
  count:  5,            -- PBKDF2 only
  info:   #"",          -- HKDF only
)
```

### Other public helpers

```aiken
use kdf/keys.{BLS12_381}

-- Reduce arbitrary bytes to a valid BLS12-381 private key
let sk = keys.to_pk(BLS12_381, #"deadbeef...")

-- Derive the corresponding public key from a secret key
let pk = keys.pk_from_sk(BLS12_381, sk)

-- BLS12-381 specific helpers (exposed for advanced use)
let sk2 = keys.to_pk_bls12_381(#"deadbeef...", 32)
let pk2 = keys.pk_from_sk_bls12_381(sk2)
```

---

# HKDF

An Aiken-based implementation of [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)
(HMAC-based Extract-and-Expand Key Derivation Function).

## Module

- `kdf/hkdf/hkdf` – single public function `kdf`.

## Usage

```aiken
use kdf/kdf.{HashAlgo}
use kdf/hkdf/hkdf

let okm = hkdf.kdf(
  HashAlgo::Sha256,
  salt: "my_salt",
  ikm:  "input_key_material",
  info: "application_context",
  length: 32,
)
```

`kdf` internally performs **Extract** (salt + IKM → PRK) followed by **Expand**
(PRK + info → OKM).  The salt and info are both optional; pass empty bytearrays
if you do not need them.

## Budget considerations

HKDF is much lighter than PBKDF2 because it does **not** iterate.  Each call performs
exactly two HMAC operations for Extract plus one HMAC per output block for Expand.

<details>
<summary>Click to expand budget tables</summary>

### SHA-256

| Operation                | Length | CPU units | Memory  |
|--------------------------|--------|-----------|---------|
| Extract only             | 32     | ~7.4 M    | ~22.6 K |
| Expand only (1 block)    | 32     | ~7.4 M    | ~22.6 K |
| Full KDF (extract+expand)| 32     | ~14.8 M   | ~45.2 K |
| Full KDF (extract+expand)| 42     | ~22.2 M   | ~67.8 K |
| Full KDF (extract+expand)| 82 (2 blocks)| ~29.6 M | ~90.4 K |

### Blake2b-256

| Operation                | Length | CPU units | Memory  |
|--------------------------|--------|-----------|---------|
| Full KDF (extract+expand)| 32     | ~14.5 M   | ~45.2 K |
| Full KDF (extract+expand)| 42     | ~21.8 M   | ~67.8 K |

### Keccak-256

| Operation                | Length | CPU units | Memory  |
|--------------------------|--------|-----------|---------|
| Full KDF (extract+expand)| 32     | ~25.0 M   | ~45.4 K |

</details>

**Key observation:** HKDF costs grow linearly with output length (one extra HMAC
per `HashLen` block).  A 32-byte output using SHA-256 costs only ~15 M CPU units,
which is negligible on-chain.  Even an 82-byte output (2 blocks, SHA-256) is still
under ~30 M CPU units.  This makes HKDF suitable for validator scripts where you
need to derive session keys or child keys from a shared secret.

## Test vectors

<details>
<summary>Click to expand RFC 5869 Appendix A test vectors</summary>

| Test case | salt length | info length | L  | Description |
|-----------|-------------|-------------|-----|-------------|
| A.1       | 13 bytes    | 10 bytes    | 42 | Basic case |
| A.2       | 80 bytes    | 80 bytes    | 82 | Long inputs/outputs |
| A.3       | 0 bytes     | 0 bytes     | 42 | Zero-length salt/info |

</details>

---

# PBKDF2

An Aiken-based implementation of the PBKDF2 scheme as outlined in
[RFC 8018, Section 5.2](https://datatracker.ietf.org/doc/html/rfc8018#page-11).

## Module

- `kdf/pbkdf2/pbkdf2` – single public function `kdf`.

## Usage

```aiken
use kdf/kdf.{HashAlgo}
use kdf/pbkdf2/pbkdf2

let dk = pbkdf2.kdf(
  HashAlgo::Sha256,
  "my_password",
  "my_salt",
  4096,
  32,
)
```

The hash algorithm is selected via the `HashAlgo` enum; the implementation
is completely generic.  Swapping to a different hash only requires changing
the first argument.

## Budget considerations

PBKDF2 is intentionally expensive (the whole point of the iteration count is to slow down
brute-force attacks).  On-chain budgets are finite, so iteration counts and derived-key
lengths must be chosen carefully.

<details>
<summary>Click to expand budget tables</summary>

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

### SHA-3 (`builtin.sha3_256`, hLen = 32)

| Iterations | dkLen | CPU units | Memory |
|-----------|-------|-----------|--------|
| 1         | 32    | ~9.24 M   | ~20.4 K |
| 2         | 32    | ~12.04 M  | ~24.7 K |
| 4 096     | 32    | ~11.46 B  | ~17.7 M |
| 4 096     | 24    | ~11.72 B  | ~17.7 M |

### Keccak-256 (`builtin.keccak_256`, hLen = 32)

| Iterations | dkLen | CPU units | Memory |
|-----------|-------|-----------|--------|
| 1         | 32    | ~10.93 M  | ~20.6 K |
| 2         | 32    | ~14.53 M  | ~24.9 K |
| 4 096     | 32    | ~14.75 B  | ~17.7 M |
| 4 096     | 24    | ~15.02 B  | ~17.7 M |

</details>

**Key observation:** At 4096 iterations, Blake2b-256 is the cheapest at ~5.16 B CPU units,
followed by Blake2b-224 (~5.19 B), SHA-256 (~5.74 B), SHA3-256 (~11.46 B), and Keccak-256
(~14.75 B).  Keccak-256 is roughly **2.9× more expensive** than Blake2b-256 and about
**2.6× more expensive** than SHA-256.  SHA3-256 is roughly **2× more expensive** than
SHA-256.  At low iteration counts (1–2) the differences are smaller but still significant:
Keccak-256 costs ~10.9 M vs ~6.6 M for Blake2b-256.

A single block with a modest iteration count (e.g. 1–10) costs only a few million CPU
units and is easily affordable on-chain.  However, **4 096 iterations already consumes**
**roughly 5–15 billion CPU units** depending on the hash chosen, which is a large fraction
of the total transaction budget.  If you need to run PBKDF2 inside a validator, tune both
`count` and the choice of hash to stay within the remaining budget after your other script
logic.

For reference, Cardano protocol parameters currently allow roughly **10 billion CPU units**
per transaction (subject to change with protocol updates).  Keep in mind that this budget
must be shared across all scripts, minting policies, and certificate validations in the
same transaction.

## Test vectors

<details>
<summary>Click to expand test vector coverage</summary>

The canonical PBKDF2 test vectors are defined in [RFC 6070](https://www.rfc-editor.org/rfc/rfc6070.txt)
(Josefsson, "PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2) Test Vectors").
Those vectors use HMAC-SHA1 as the PRF.  SHA-1 is **not** exposed as a Plutus V3 builtin,
so the exact RFC 6070 outputs cannot be reproduced here.  Instead, the test suite uses
analogous cases with the same passwords, salts, and iteration counts but computes
SHA-256-based outputs (the PRF is `sha2_256(password || data)` rather than `HMAC-SHA1`).

The test suite covers:

| Case | password | salt | iterations | dkLen | Notes |
|------|----------|------|------------|-------|-------|
| 1-block, 1 iter | "password" | "salt" | 1 | 32 | Basic |
| 1-block, 2 iter | "password" | "salt" | 2 | 32 | RFC 6070 analog |
| 1-block, 4096 iter | "password" | "salt" | 4096 | 32 | RFC 6070 analog |
| Truncated | "password" | "salt" | 1 | 16 | Last block trimmed |
| 2 blocks | "password" | "salt" | 1 | 64 | Multiple blocks |
| Long P/S, 4096 iter | "passwordPASSWORD" | "saltSALTsaltSALTsalt" | 4096 | 24 | RFC 6070 analog |
| NUL bytes | #"7061737300776f7264" | #"7361006c74" | 4096 | 16 | RFC 6070 case 6 analog |

</details>

---

# Choosing between HKDF and PBKDF2

<details>
<summary>Click to expand comparison table</summary>

| | HKDF | PBKDF2 |
|---|---|---|
| **Purpose** | Derive keys from high-entropy secrets (DH shared secrets, random seeds, etc.) | Derive keys from low-entropy passwords |
| **RFC** | [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869) | [RFC 8018 §5.2](https://datatracker.ietf.org/doc/html/rfc8018#page-11) |
| **Algorithm** | HMAC-based Extract-then-Expand | HMAC iteration with salt |
| **Speed** | Fast — only a few HMAC calls | Slow by design — iteration count controls cost |
| **Parameters** | `salt`, `ikm`, `info`, `length` | `password`, `salt`, `count`, `dk_len` |
| **On-chain cost (32-byte output, SHA-256)** | ~15 M CPU | ~5.74 B CPU at 4096 iterations |
| **On-chain feasible?** | ✅ Yes, trivially affordable | ⚠️ Only at low iteration counts (≤10) |
| **When to use** | Session-key derivation, child-key derivation from a master secret | Password-based key derivation, wallet encryption |

</details>

**Rule of thumb:**
- If your input is a **password or human-memorable secret**, use **PBKDF2** (but keep
  iteration counts low on-chain, or move the computation off-chain).
- If your input is already a **pseudorandom or high-entropy key** (e.g. a Diffie-Hellman
  shared secret, a CSPRNG output, a pre-master secret), use **HKDF**.  It is orders of
  magnitude cheaper and provides better security guarantees for key separation via
  the `info` parameter.

---

# Argon2 (not implemented)

We investigated adding [Argon2](https://www.rfc-editor.org/rfc/rfc9106.txt)
(RFC 9106, Biryukov et al., "Argon2 Memory-Hard Function") as a third KDF.  The conclusion
is that **Argon2 is fundamentally incompatible with on-chain execution on Cardano**.

## Why Argon2 cannot run on-chain

### 1. Memory-hard by design

Argon2's security relies on consuming large amounts of RAM.  The RFC's **minimum
recommended** settings are:

<details>
<summary>Click to expand memory requirements</summary>

| Profile | Memory | Passes | Lanes |
|---------|--------|--------|-------|
| Backend server auth | 4 GiB | t=1 | p=8 |
| Hard-drive encryption | 6 GiB | t=1 | p=4 |
| "Low memory" option | 64 MiB | t=3 | p=4 |
| Smallest test vector | 32 KiB | t=3 | p=4 |

</details>

Cardano's on-chain memory budget is roughly **14–17 MB per transaction total**
(shared across all scripts, minting policies, etc.).  Even the smallest test vector
(32 KiB) is non-trivial.  The 64 MiB "low memory" option is **4× the entire transaction
budget**.  The 4 GiB standard option is **300× the budget**.

### 2. BLAKE2b-512 is required, only blake2b_256 is available

Argon2's internal hash function is BLAKE2b with **64-byte outputs** (the full
BLAKE2b-512).  Plutus V3 only exposes:
- `builtin.blake2b_224` → 28 bytes
- `builtin.blake2b_256` → 32 bytes

Implementing BLAKE2b-512 from scratch in Aiken would require:
- Implementing the full BLAKE2b permutation (the same one used in Argon2's `GB` function)
- 64-bit arithmetic (which Plutus does not natively support — see below)
- This alone is a **multi-week project**

### 3. 64-bit arithmetic is mandatory

Argon2's `GB()` function (the core round function inside permutation P) performs:

```
a = (a + b + 2 * trunc(a) * trunc(b)) mod 2^64
d = (d XOR a) >>> 32
c = (c + d + 2 * trunc(c) * trunc(d)) mod 2^64
b = (b XOR c) >>> 24
...
```

Plutus/Aiken has **arbitrary-precision integers**, but:
- No native 64-bit type
- No built-in 64-bit bitwise operations
- No `>>> n` (right rotation) — only bitwise XOR and left-shift-like operations via bytearrays

Every 64-bit addition, multiplication, XOR, and rotation would need to be
**emulated using bytearray operations** (converting Int → 8-byte bytearray, operating,
converting back).  This is extremely expensive.

### 4. Data-dependent memory access

Argon2d/Argon2id compute block indices based on the **contents of previously computed
blocks**.  This means:
- You cannot skip blocks or compute them out of order
- You must store the entire memory matrix in state
- Random access into a large bytearray matrix is costly in Plutus

### 5. Parallelism vs. single-threaded execution

Argon2 uses `p` parallel lanes that synchronize between slices.  Aiken/Plutus is
**single-threaded**.  We'd need to compute lanes sequentially, further increasing
execution time.

## On-chain feasibility

<details>
<summary>Click to expand feasibility breakdown</summary>

| Component | On-chain feasible? |
|-----------|-------------------|
| 64-bit arithmetic emulation | Very expensive |
| BLAKE2b-512 implementation | N/A (no native support) |
| Permutation P / GB() | Extremely expensive |
| Compression function G | Extremely expensive |
| Memory matrix management | Budget-exceeded |
| Full Argon2 algorithm | **Completely unusable** |

</details>

Even if fully implemented, Argon2 with the **smallest viable parameters** (8 KiB memory,
1 lane, 1 pass) would likely:
- Exceed the memory budget
- Consume billions of CPU units
- Provide **no meaningful security** (8 KiB is trivially attacked)

## Balloon hashing (not implemented)

We also briefly investigated **[Balloon hashing](https://eprint.iacr.org/2016/027)** (Bonneau et al., 2016) as a simpler
alternative to Argon2.  Like Argon2, Balloon hashing is a **memory-hard** function:
it fills a large buffer with pseudorandom blocks and mixes them iteratively.

While its structure is conceptually simpler than Argon2 (single-buffer rather than
a multi-lane matrix), it suffers from the **same fundamental incompatibility**:
- It requires a large memory buffer (hundreds of KiB to GiB) to provide any security
- It needs a cryptographic hash as a building block (SHA-256 or BLAKE2b)
- It performs data-dependent random accesses into the buffer

A minimal Balloon hashing instance with a 64 KiB buffer and 3 rounds would already
consume a significant fraction of the on-chain memory budget while offering only
marginal resistance to hardware-accelerated attacks.  Like Argon2, it belongs
**off-chain**.

## Verdict

**Memory-hard KDFs (Argon2, Balloon hashing, Catena, etc.) should NOT be implemented
as on-chain KDFs in Aiken.**  They are fundamentally incompatible with Cardano's
execution model, which is designed for deterministic, low-memory, low-CPU scripts.

If you need a memory-hard function for a Cardano-related application, the correct
architecture is:
1. **Off-chain computation** — compute the KDF in the wallet or application layer
2. **On-chain verification** — verify a pre-image or signature derived from the output

For on-chain key derivation, **HKDF** (fast, low memory, secure for high-entropy inputs)
and **PBKDF2** with very low iteration counts (expensive but manageable for small inputs)
are the only viable options in the current Plutus V3 environment.
