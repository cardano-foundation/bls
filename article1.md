## BLS12-381 powerhouse available for users

## BLS12-381 elliptic curve

BLS12-381 is a special type of elliptic curve designed for modern cryptography. Like the curve used in Bitcoin (secp256k1), it lets you create public/private key pairs, sign messages, and verify signatures. The main difference is that BLS12-381 is **pairing-friendly**, which unlocks powerful mathematical tricks that ordinary curves cannot do.

### What does "pairing-friendly" mean?

In simple terms, a pairing is a magical calculator that takes two points from different groups on the curve and combines them into a single number in a third group. That number has a special property: if you scale the original points by secret factors, the result scales in a predictable way. This property is called **homomorphism**. It allows you to check relationships between keys without ever revealing the secrets themselves.

Non-pairing curves like Bitcoin's secp256k1 are fast and battle-tested for simple signatures, but they cannot compute these pairings at all. Pairing-friendly curves pay a small performance overhead for ordinary operations in exchange for the ability to run these advanced checks.

### How does it compare to other curves?

- **Bitcoin / Ethereum (EOA):** secp256k1 is fast and simple, but limited to standard signatures and verification. It has no pairing support.
- **Ethereum (pre-Dencun):** BN254 (also called alt_bn128) is another pairing-friendly curve used in Ethereum's early zero-knowledge proofs. It is faster than BLS12-381 for some operations, but has a lower security level (roughly 100 bits vs 128 bits).
- **BLS12-381:** Used in Ethereum's consensus layer (beacon chain), Cardano, and several modern ZK-proof systems. It offers a stronger 128-bit security level while still being efficient enough for production use.

### What can you do with it?

Because of the pairing property, BLS12-381 enables things that are impossible or extremely inefficient on standard curves:

- **BLS signatures:** A signature scheme where signatures are tiny, public keys are small, and multiple signatures can be aggregated into a single signature. This is ideal for blockchain consensus and multi-signature wallets. (See the **BLS** section below.)
- **Zero-knowledge proofs:** Proving that you know a secret or that a computation was done correctly without revealing the underlying data. Used in zk-SNARKs and other privacy systems. (See the **Proof systems** section below.)
- **Verifiable random functions (VRF):** Producing a random number that anyone can verify came from a specific key, without being able to predict it in advance. (See the **VRF** section below.)
- **Identity-based encryption:** Encrypting a message using just an email address or username as a public key, removing the need for complex certificate infrastructure.
- **Short non-interactive proofs:** Efficiently proving that a set of transactions, a state transition, or a secret value is valid, which is crucial for scaling blockchains. (See the **Proof systems** section below.)

In short, BLS12-381 is the engine behind many of the next-generation privacy, scaling, and consensus features in the blockchain world. It trades a small amount of raw speed for a massive increase in cryptographic superpowers.

## Aiken elliptic curve API

Cardano's Plutus core already contains low-level **built-in primitives** for BLS12-381. That means any smart-contract language running on Cardano can, in principle, perform scalar multiplication, point addition, hashing-to-curve, and pairing checks directly on-chain. Aiken exposes these primitives through a clean, type-safe standard-library interface, so you do not have to juggle raw byte arrays manually.

The full API is documented in the [Aiken standard library](https://aiken-lang.github.io/stdlib/aiken/crypto.html) under `aiken/crypto/bls12_381`. The two main entry points are:

- **`aiken/crypto/bls12_381/g1`** – operations on the smaller, faster G1 group (48 bytes compressed).
- **`aiken/crypto/bls12_381/g2`** – operations on the larger G2 group (96 bytes compressed).

In addition, the `aiken/builtin` module exposes the raw Plutus builtins such as `bls12_381_g1_scalar_mul`, `bls12_381_g2_hash_to_group`, `bls12_381_miller_loop`, and `bls12_381_final_verify`. The standard-library wrappers simply make these safer and more ergonomic.

### What the primitives look like in code

Here is a minimal example that derives a G1 public key from a 32-byte secret:

```aiken
use aiken/builtin
use aiken/crypto/bls12_381/g1.{generator}

fn sk_to_pk(sk: ByteArray) -> ByteArray {
  // 1. Convert the secret bytes to an integer
  let s = builtin.bytearray_to_integer(True, sk)
  expect s != 0

  // 2. Multiply the G1 generator by that scalar
  let pk_point = builtin.bls12_381_g1_scalar_mul(s, generator)

  // 3. Compress the point so it fits neatly in a Datum or Redeemer
  builtin.bls12_381_g1_compress(pk_point)
}
```

**What is happening, step by step:**

1. **Secret to scalar** – `sk` is just a random byte string. We interpret it as a big integer and make sure it is non-zero.
2. **Scalar multiplication** – `bls12_381_g1_scalar_mul` performs the actual elliptic-curve multiplication `s * G1`. This is the fundamental operation that turns a secret into a public point.
3. **Compression** – uncompressed G1 points are 96 bytes; compressed points are only 48 bytes. Compression drops the redundant coordinate and keeps the single byte that tells us whether the y-coordinate is positive or negative. On-chain, every byte counts, so you almost always compress before storing a point in a Datum.

The same pattern works for G2, except G2 points are twice as large (192 bytes uncompressed, 96 bytes compressed). That makes G1 the natural choice for any data you need to store permanently on-chain, such as public keys or aggregated public keys. G2 is then used for signatures or as the second argument in a pairing check. This is the so-called **minimal public key size** variant of BLS. The original paper proposed the opposite arrangement (**minimal signature size**), but for smart contracts the public key size variant is usually preferred because public keys are long-lived data while signatures are often only transient.

### Hashing a message to a curve point

Another primitive you will use constantly is **hash-to-curve**. Instead of hashing a message to a plain integer, you hash it directly to a valid point on the curve. This is essential for BLS signatures and VRFs.

```aiken
use aiken/builtin.{bls12_381_g2_hash_to_group, bls12_381_g2_scalar_mul, bls12_381_g2_compress}
use aiken/crypto/bls12_381/g2

fn hash_and_sign(sk: ByteArray, message: ByteArray, dst: ByteArray) -> ByteArray {
  let s = builtin.bytearray_to_integer(True, sk)
  expect s != 0

  // Hash the message to a point in G2
  let h_point = bls12_381_g2_hash_to_group(message, dst)

  // Signature = secret * hash_point
  let sig_point = bls12_381_g2_scalar_mul(s, h_point)

  bls12_381_g2_compress(sig_point)
}
```

The `dst` parameter is a **domain separation tag** (a public string like `"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"`). It guarantees that hashes meant for signatures never collide with hashes meant for VRFs or other protocols, even if the underlying message is identical.

### Pairing checks – the superpower

Pairings are what make BLS12-381 special. In Aiken, a pairing check is a two-step dance: the **Miller loop** followed by **final verification**.

```aiken
use aiken/builtin.{
  bls12_381_g1_scalar_mul, bls12_381_g2_scalar_mul,
  bls12_381_miller_loop, bls12_381_final_verify,
}
use aiken/crypto/bls12_381/g1.{generator as g1_gen}
use aiken/crypto/bls12_381/g2.{generator as g2_gen}

/// Check bilinearity: e(2*G1, 3*G2) == e(6*G1, G2)
test bilinearity_demo() {
  let a_g1 = bls12_381_g1_scalar_mul(2, g1_gen)
  let b_g2 = bls12_381_g2_scalar_mul(3, g2_gen)
  let ab_g1 = bls12_381_g1_scalar_mul(6, g1_gen)

  bls12_381_final_verify(
    bls12_381_miller_loop(a_g1, b_g2),
    bls12_381_miller_loop(ab_g1, g2_gen),
  )
}
```

**Why two steps?** The Miller loop is the heavy computation that produces an intermediate object (a so-called *Miller-loop result*). `bls12_381_final_verify` compares two of these results and returns `True` only if they are equal. If you need to verify multiple pairings at once, you can multiply the intermediate results together with `bls12_381_mul_miller_loop_result` and run a single final verify at the end. This is exactly how BLS signature aggregation saves gas: one final verify replaces many independent checks.

### Building higher-level protocols

These primitives are the Lego bricks. The sections below show complete, working structures built from them:

- **BLS** – how to aggregate public keys and signatures, then verify them with a single pairing check.
- **VRF** – how to prove a random number was generated by a specific key without revealing the key, using hash-to-curve, scalar multiplication, and challenge generation.
- **KDF** – how to derive BLS12-381 keys from passwords or seeds using PBKDF2 and HKDF, while keeping the scalar inside the valid prime field.
- **Proof systems** – how to use pairings to verify that a secret satisfies a polynomial equation, which is the core idea behind zk-SNARKs.

## BLS

## KDF

## VRF

## Proof systems