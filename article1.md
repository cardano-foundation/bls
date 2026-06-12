## Aiken BLS12-381 primitives - wide possibilities available

**Table of Contents**

- [BLS12-381 elliptic curve](#bls12-381-elliptic-curve)
- [Aiken elliptic curve API](#aiken-elliptic-curve-api)
- [BLS](#bls)
- [KDF](#kdf)
- [VRF](#vrf)
- [Proof systems](#proof-systems)

---

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

BLS stands for **Boneh-Lynn-Shacham**, the three cryptographers who invented the scheme in the seminal paper *"Short Signatures from the Weil Pairing."* At its heart, BLS is a signature scheme built on top of pairing-friendly elliptic curves like BLS12-381. It does everything a normal signature scheme does—sign messages, verify them, create key pairs—but it adds a superpower that no other mainstream scheme can match: **aggregation**.

### Why BLS matters

In traditional schemes like ECDSA or EdDSA, if one hundred people sign a document, you must store one hundred separate signatures and verify each one individually. The cost grows linearly. BLS changes this entirely. Because signatures are points on the curve, they can be added together just like numbers. One hundred signatures become a single 96-byte signature, and verification takes a single pairing check regardless of how many signers were involved. This is not just a nice optimization; it is a qualitative change in what is possible.

- **Blockchain consensus** – Ethereum 2.0 uses BLS for validator attestations because thousands of validators can sign the same block, and the network only needs to gossip and verify one aggregated signature.
- **Multi-signature wallets** – A group of owners can sign a transaction, and the on-chain script checks one small signature instead of iterating through a list.
- **Voting and governance** – Thousands of votes can be compressed into a single proof that everyone signed, making tallying trivial.

### Standardization and the ilap/bls library

The BLS signature scheme is actively standardized by the IETF in [draft-irtf-cfrg-bls-signature](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature). This draft defines two group-size variants:

- **Minimal signature size** – public keys in G2, signatures in G1. Signatures are tiny (48 bytes), but public keys are large (96 bytes).
- **Minimal public key size** – public keys in G1, signatures in G2. Public keys are small (48 bytes), but signatures are larger (96 bytes).

For almost every blockchain use case, the minimal public key size variant is preferred because public keys are stored on-chain long-term (in Datums, UTxOs, or state), while signatures are usually transient. The IETF draft also defines three signing modes to handle different trust assumptions.

Rather than writing all the pairing logic by hand, you can use **[ilap/bls](https://github.com/ilap/bls)**, an Aiken library that implements the full IETF draft on top of the Plutus BLS12-381 builtins. It exposes three scheme modules, all using the minimal-public-key-size variant:

| Module | Purpose | When to use |
|--------|---------|-------------|
| `bls/g1/basic` | Standard BLS | All public keys are trusted or pre-validated |
| `bls/g1/aug` | Message-augmented BLS | Public keys are untrusted; the signer's key is prepended to the message |
| `bls/g1/pop` | Proof-of-Possession BLS | Public keys are registered with a PoP proof that the owner knows the secret key |

All three share the same core operations: `sk_to_pk`, `sign`, `verify`, `aggregate`, and `aggregate_verify`. The only difference is how the message is prepared before hashing and how the aggregation verifier handles duplicate messages.

### The three modes in detail

**Basic mode** is the simplest. You sign the raw message, and `aggregate_verify` rejects the transaction if any two messages are identical. This prevents a subtle attack where a malicious participant crafts a fake public key that cancels out honest keys, allowing them to forge an aggregate signature. The defense in Basic mode is blunt but effective: if every message is unique, the attack is impossible.

**Augmented (Aug) mode** is more flexible. Instead of signing the raw message, the signer prepends their own public key: `sign(sk, pk || message)`. This binds the signature to the key, so even if two messages are identical, the hash inputs are different because the keys differ. Rogue-key attacks are mitigated without banning duplicate messages. The trade-off is a slightly larger message hash and the need to know the public key at signing time.

**Proof-of-Possession (PoP) mode** is the strongest. Before a public key is ever used in aggregation, the owner must produce a special signature `sign(sk, pk)` and register it on-chain. Anyone can verify this PoP with a single pairing check. Once the key is validated, the user can sign any number of identical messages safely, because the registration step proved that the key was generated honestly. PoP is ideal for stake pools, committee members, or any fixed set of participants that register once and sign many times.

### Signature aggregation: many messages, many signers

The first pattern is signature aggregation, where each party signs a different message. Their signatures are added together into one 96-byte value. The verifier computes one Miller-loop product per message and runs a single final verification. This pattern is demonstrated in the workspace project `aiken/signature-aggregation-case`.

```aiken
use bls/g1/basic as basic_bls

fn three_party_signature_aggregation() {
  // Each party generates a key pair from secret material
  let sk1 = key_gen(secret1, "")
  let pk1 = basic_bls.sk_to_pk(sk1)
  // ... same for sk2, pk2 and sk3, pk3

  // Each party signs a unique message
  let sig1 = basic_bls.sign(sk1, "Hello from party 1!")
  let sig2 = basic_bls.sign(sk2, "Hello from party 2!")
  let sig3 = basic_bls.sign(sk3, "Hello from party 3!")

  // Anyone can aggregate the signatures offline
  let sig_aggr = basic_bls.aggregate([sig1, sig2, sig3])

  // On-chain: one verification for all three distinct messages
  basic_bls.aggregate_verify(
    [pk1, pk2, pk3],
    ["Hello from party 1!", "Hello from party 2!", "Hello from party 3!"],
    sig_aggr,
  )
}
```

**What is happening under the hood?**

The verifier iterates over the `(pk, message)` pairs, hashes each message to a G2 point, runs a Miller loop between the public key (G1) and the hash point (G2), and multiplies all the intermediate results together. It then runs one final Miller loop between the G1 generator and the aggregated signature. If the two final products match, every signature is valid. The cost is roughly one pairing per message, but the signatures themselves are compressed into a single value.

Because the messages are distinct, Basic mode is safe. But what if the messages are the same? In that case, a rogue-key attacker could construct a fake public key that cancels out honest keys, then forge an aggregate signature using only one honest signature. This is exactly why Basic mode bans duplicate messages in `aggregate_verify`.

If you need to sign the same message, switch to **Augmented mode**. The `aiken/signature-aggregation-case` project shows this in action:

```aiken
use bls/g1/aug as aug_bls

fn three_party_same_message_aggregation() {
  let sig1 = aug_bls.sign(sk1, "Hello from all parties!")
  let sig2 = aug_bls.sign(sk2, "Hello from all parties!")
  let sig3 = aug_bls.sign(sk3, "Hello from all parties!")

  let sig_aggr = aug_bls.aggregate([sig1, sig2, sig3])

  // Now duplicate messages are safe because each hash includes the signer's key
  aug_bls.aggregate_verify(
    [pk1, pk2, pk3],
    ["Hello from all parties!", "Hello from all parties!", "Hello from all parties!"],
    sig_aggr,
  )
}
```

Finally, **PoP mode** adds a registration step. Before any aggregation happens, each signer proves they control their private key by producing a PoP signature over their own public key. The `aiken/signature-aggregation-case` project tests this flow as well:

```aiken
use bls/g1/pop as pop_bls

fn pop_registration() {
  let pop1 = pop_bls.pop_prove(sk1)
  let pop2 = pop_bls.pop_prove(sk2)
  let pop3 = pop_bls.pop_prove(sk3)

  // On-chain: verify each PoP before accepting the key for aggregation
  expect pop_bls.pop_verify(pk1, pop1)
  expect pop_bls.pop_verify(pk2, pop2)
  expect pop_bls.pop_verify(pk3, pop3)

  // After registration, all three can sign the same message safely
  let sig1 = pop_bls.sign(sk1, "Hello from all parties!")
  let sig2 = pop_bls.sign(sk2, "Hello from all parties!")
  let sig3 = pop_bls.sign(sk3, "Hello from all parties!")

  let sig_aggr = pop_bls.aggregate([sig1, sig2, sig3])
  pop_bls.aggregate_verify([pk1, pk2, pk3], ["Hello from all parties!", "Hello from all parties!", "Hello from all parties!"], sig_aggr)
}
```

### Public-key aggregation: same message, constant cost

The second pattern is even more powerful for on-chain use. When every party signs the same message, we can aggregate the **public keys** themselves—not just the signatures. The verifier only needs **two** pairing evaluations total, no matter how many signers exist. This is demonstrated in the workspace project `aiken/publickey-aggregation-case`.

The project provides a small helper module (`bls-extra/core`) that exposes `aggregate_publickeys` and `aggregate_publickey_verify`:

```aiken
use bls_extra/core as bls_extra_core

fn public_key_aggregation_demo() {
  // Two parties sign the same message
  let sig1 = basic_bls.sign(sk1, "Hello from party!")
  let sig3 = basic_bls.sign(sk3, "Hello from party!")

  // Aggregate the signatures (still one 96-byte value)
  let sig13_aggr = basic_bls.aggregate([sig1, sig3])

  // Aggregate the public keys into a single 48-byte value
  let pk13_aggr = bls_extra_core.aggregate_publickeys([pk1, pk3])

  // Verify with only two pairings total, regardless of signer count
  bls_extra_core.aggregate_publickey_verify(pk13_aggr, ["Hello from party!"], sig13_aggr, api.Basic)
}
```

**What is happening under the hood?**

Public-key aggregation is nothing more than point addition in G1. Each 48-byte compressed key is uncompressed, added to a running sum, and the result is compressed again. The underlying implementation uses the same `g1_add` primitive we saw earlier:

```aiken
fn aggregate_publickeys(publickeys: List<PublicKey>) -> PublicKeyAggregated {
  aggregate_g1(publickeys)
}
```

At verification time, the aggregated public key is paired with the hashed message, and the aggregated signature is paired with the G1 generator. A single `final_verify` confirms every signature. For a committee of ten, a hundred, or even a thousand members, the on-chain cost stays constant.

**Important limitation:** public-key aggregation only works cleanly with **Basic mode** and identical messages. In Augmented mode, each signature is computed over `pk_i || message`, so the hash inputs differ per signer. Aggregating the public keys and hashing `pk_agg || message` produces a different hash than the individual signatures, so the pairing equation no longer balances. The `aiken/publickey-aggregation-case` project explicitly demonstrates that this fails. PoP mode suffers from the same problem because each signature is bound to the individual public key. For public-key aggregation, stick to Basic mode with the same message for every signer.

### Rogue-key attacks and why the modes matter

Aggregation is powerful, but it introduces a subtle risk. Suppose an attacker claims a public key `pk_rogue = pk_1 + pk_2 - pk_3`, where `pk_1` and `pk_2` are honest keys. The attacker never knew the secret for `pk_3`, but by choosing `pk_rogue` this way, they can cancel out the honest keys. If all three sign the same message, the aggregate signature can be verified with just `sig_3` alone, even though the attacker never produced `sig_1` or `sig_2`.

The `aiken/signature-aggregation-case` project demonstrates this exact attack:

```aiken
let rogue_pk3 = construct_rogue_key(pk1, pk2, pk3)
let sig3 = basic_bls.sign(sk3, message)

// Only sig3 is needed to verify! sig1 and sig2 could be omitted
let sigs_aggr_predicate = core_bls.core_aggregate_verify([pk1, pk2, rogue_pk3], [message, message, message], sig3, api.Basic)
```

The three modes defend against this differently:

- **Basic** bans duplicate messages in `aggregate_verify`, so the attack is blocked at the API level. The `aiken/publickey-aggregation-case` project shows that `aggregate_publickey_verify` also rejects duplicate messages in Basic mode.
- **Aug** prepends the public key to the message, so the hash is unique per signer even when the underlying message is identical. The rogue-key attack fails because `sig_3` was computed over `pk_3 || message`, not `pk_rogue || message`.
- **PoP** forces a registration step where the signer proves they control the private key, making rogue-key construction impossible in the first place.

For a fixed stake pool or committee, PoP is usually the cleanest. For a dynamic wallet where participants change every transaction, Aug is more convenient. For a trusted multi-sig where all keys are generated together, Basic is sufficient and cheapest.

### Summary

BLS signatures turn the expensive problem of multi-party verification into a constant-cost operation. The `ilap/bls` library packages the entire IETF draft into three Aiken modules that handle key generation, signing, aggregation, and all the pairing arithmetic behind the scenes. The workspace projects `aiken/signature-aggregation-case` and `aiken/publickey-aggregation-case` show the two complementary patterns in practice: signature aggregation for many messages, and public-key aggregation for the same message. Whether you need a simple two-of-three wallet, a thousand-validator consensus layer, or a governance vote with thousands of participants, the pattern is the same: aggregate, compress, and verify once.

## KDF

In everyday cryptography, you rarely start with a perfectly random 32-byte secret. More often, you have a password, a seed phrase, a shared secret from a handshake, or some other piece of keying material that is not yet curve-ready. A **Key Derivation Function (KDF)** bridges this gap: it takes arbitrary input and deterministically produces a cryptographically strong key that fits inside the prime field of your chosen curve. The workspace project `aiken/kdf` provides two RFC-compliant KDFs—HKDF and PBKDF2—together with a thin layer that maps the derived bytes directly onto BLS12-381 key pairs.

### Why KDFs matter on-chain

On-chain scripts often need to derive keys from information that lives inside the transaction itself: a password supplied in a redeemer, a shared secret from a Diffie-Hellman exchange, or a master seed stored in a datum. Doing this naively—for example, by interpreting the raw bytes directly as a scalar—can produce a value outside the valid prime field, or worse, leak information about the original secret. A proper KDF fixes both problems: it expands or strengthens the input, then reduces the result modulo the curve order so the output is guaranteed to be a valid private key.

The `aiken/kdf` project offers two complementary tools for this job:

- **HKDF** ([RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)) – fast, HMAC-based Extract-then-Expand. Ideal when your input is already high-entropy (a random seed, a shared secret, another key).
- **PBKDF2** ([RFC 8018 §5.2](https://datatracker.ietf.org/doc/html/rfc8018#page-11)) – intentionally slow, iteration-based. Ideal when your input is a password or human-memorable secret and you need to raise the cost of brute-force attacks.

Both are built entirely from Aiken/Plutus builtins, so they execute natively on-chain without any foreign code.

### Deriving a BLS12-381 key pair with HKDF

The simplest path is `gen_keys_hkdf`, a one-line helper that runs HKDF internally and then converts the 32-byte output into a valid BLS12-381 private key and its corresponding compressed public key:

```aiken
use kdf/keys

fn derive_wallet_key() {
  let (sk, pk) = keys.gen_keys_hkdf(
    salt: "my_salt",
    ikm:  "high_entropy_secret",
  )

  // sk is a 32-byte private key, already reduced modulo the curve prime
  // pk is a 48-byte compressed public key in G1
  (sk, pk)
}
```

**What is happening, step by step:**

1. **HKDF Extract** – the salt and input keying material (`ikm`) are fed through HMAC to produce a pseudorandom key (`PRK`). This concentrates the entropy and isolates the output from the raw input.
2. **HKDF Expand** – the `PRK` is expanded to 32 bytes with an optional info string (empty by default). Each output block is another HMAC call, so the cost grows linearly with the number of blocks.
3. **Field reduction** – the 32-byte output is interpreted as a big integer and reduced modulo the BLS12-381 prime field order. This guarantees a valid scalar even if the raw HKDF output is larger than the field.
4. **Public key derivation** – the scalar multiplies the G1 generator, and the resulting point is compressed to 48 bytes.

**On-chain cost:** A 32-byte HKDF output using SHA-256 costs roughly **15 M CPU units**, which is negligible inside a typical transaction budget. Even an 82-byte output (two blocks) stays under **30 M CPU units**. This makes HKDF the default choice for session-key derivation, child-key derivation, or any scenario where the input is already strong.

### Deriving a BLS12-381 key pair with PBKDF2

When the input is a password, HKDF is not enough: passwords are low-entropy and vulnerable to dictionary attacks. PBKDF2 solves this by adding iterations—each iteration is a hash call, and the total cost is tuned to make brute-force attacks expensive:

```aiken
use kdf/keys

fn derive_password_key() {
  let (sk, pk) = keys.gen_keys_pbkdf2(
    salt: "my_salt",
    ikm:  "my_password",
  )

  // Same guarantees: 32-byte sk, 48-byte compressed pk
  (sk, pk)
}
```

**What is happening, step by step:**

1. **Salted hash iteration** – PBKDF2 mixes the password and salt, then hashes the result repeatedly. The `count` parameter controls how many times. Each round feeds the output of the previous round back into the hash, so an attacker must pay the same iteration cost for every guess.
2. **Block derivation** – if the desired key length exceeds the hash output size (32 bytes for SHA-256), PBKDF2 derives multiple blocks and concatenates them.
3. **Field reduction and key derivation** – the same `to_pk_bls12_381` and `pk_from_sk_bls12_381` steps from HKDF are applied, producing a valid curve key pair.

**On-chain cost:** The default `gen_keys_pbkdf2` uses **10 iterations** with SHA-256, costing roughly **160 M CPU units**. This is still well within a typical transaction budget, but it is already far more expensive than HKDF. The traditional off-chain recommendation of 4096 iterations would consume roughly **5.7 B CPU units**—more than half the total transaction budget—so it is generally reserved for off-chain use. If you need PBKDF2 on-chain, keep the iteration count low and choose the fastest hash (Blake2b-256 is roughly 2.9× cheaper than Keccak-256 at high counts).

### Full control with `gen_keys_detail`

If the defaults do not fit your use-case, `gen_keys_detail` exposes every parameter:

```aiken
use kdf/keys.{PBKDF2, HKDF, BLS12_381}
use kdf/kdf.{Sha256, Blake2b_256}

fn custom_derivation() {
  // Low-count PBKDF2 with Blake2b for minimal on-chain cost
  let (sk, pk) = keys.gen_keys_detail(
    PBKDF2,
    BLS12_381,
    Blake2b_256,
    salt:   "salt",
    ikm:    "password",
    count:  5,
    info:   #"",
  )

  // Or HKDF with an explicit info string for domain separation
  let (sk2, pk2) = keys.gen_keys_detail(
    HKDF,
    BLS12_381,
    Sha256,
    salt:   "salt",
    ikm:    "high_entropy_secret",
    count:  0,
    info:   "wallet-child-key-42",
  )

  (sk, pk)
}
```

**What is happening, step by step:**

1. **Scheme selection** – `PBKDF2` or `HKDF` determines the core algorithm.
2. **Hash selection** – `Sha256`, `Sha3_256`, `Keccak256`, `Blake2b_224`, or `Blake2b_256`. The choice affects both speed and, for PBKDF2, the per-iteration cost.
3. **Salt and IKM** – the salt prevents rainbow-table attacks; the IKM is the raw secret or password.
4. **Count** – PBKDF2 iteration count (ignored for HKDF).
5. **Info** – HKDF context string (ignored for PBKDF2). This is the standard way to derive multiple independent keys from the same master secret without leaking relationships between them.

### What you cannot do on-chain: memory-hard KDFs

The `aiken/kdf` project investigated Argon2 and Balloon hashing, two modern memory-hard KDFs designed to resist GPU and ASIC attacks. The conclusion was clear: **they are fundamentally incompatible with on-chain execution**.

- **Memory requirements:** Argon2's minimum recommended settings use 64 MiB to 4 GiB of RAM. Cardano's entire on-chain memory budget per transaction is roughly 14–17 MB.
- **Missing primitives:** Argon2 requires BLAKE2b-512 (64-byte outputs), but Plutus only exposes 224-bit and 256-bit variants. It also requires 64-bit arithmetic with bitwise rotations, which must be emulated using bytearray operations at enormous cost.
- **Data-dependent access:** Argon2's memory layout is computed on-the-fly based on previous block contents, making random access into a large buffer mandatory. On-chain, every byte of state costs execution units.

The practical rule is simple: if you need memory-hard password hashing, do it **off-chain** in the wallet or application layer, then verify the result on-chain with a signature or hash comparison.

### Summary

The `aiken/kdf` project gives you two reliable, RFC-compliant paths from raw secrets to BLS12-381 keys:

- **HKDF** for high-entropy inputs: fast, cheap, and domain-separable via the `info` string.
- **PBKDF2** for passwords: slow by design, but keep iteration counts modest (≤10) to stay within the on-chain budget.

Both are pure Aiken, built entirely from Plutus builtins, and produce deterministic 32-byte private keys and 48-byte compressed public keys ready for the BLS, VRF, or proof-system operations described in the sections below.

## VRF

A **Verifiable Random Function (VRF)** is the public-key cousin of a keyed hash. Only the holder of a secret key can compute the hash, but anyone with the public key can verify that the hash was computed correctly. The output is deterministic—same key and input always produce the same result—but to anyone without the secret, it looks perfectly random. The workspace project `aiken/vrf` implements the standard ECVRF scheme over BLS12-381 G2 entirely in Aiken, using nothing but Plutus builtins.

The API is small and regular: you derive a key pair from secret material, generate a proof for an input, and anyone can verify that proof to recover the same pseudorandom output. The proof is 144 bytes (96 bytes for a compressed G2 point, 16 bytes for a challenge, 32 bytes for a Schnorr-style response). The final hash output is a standard 32-byte value.

### Why VRFs matter on-chain

VRFs solve a class of problems that ordinary hashing cannot:

- **Predictability vs. verifiability:** A hash like `sha2_256(secret || input)` is deterministic, but nobody can verify it without learning the secret. A VRF proves the output came from a specific key without revealing the key.
- **Uniqueness:** For any given public key and input, there is exactly one valid output. The prover cannot cherry-pick or grind alternative results.
- **Non-interactivity:** The prover sends a single message `(input, proof)`. No challenge-response rounds are needed.

These properties make VRFs ideal for lotteries, leader selection, private data structures, and any protocol that needs randomness or hiding with public verifiability.

### Case 1: Privacy-protected data structures

When you store data in a public hash-based structure—say a Merkle tree or a hash map—using a regular hash like `sha2_256(record_name)` leaks information. An attacker can enumerate common names, compute their hashes, and check which positions exist in the tree. This is called an **enumeration attack**.

A VRF replaces the regular hash with a pseudorandom output that only the data owner can compute. The owner derives a "private address" for each record from the record name and their secret key. Outsiders see only random-looking values and cannot link them to anything.

```aiken
use vrf/core as vrf

fn store_private_records() {
  let secret = "prover_secret_key"
  let (sk, pk) = vrf.keys_from_secret(secret)

  // Private records the owner wants to store
  let record_1 = "alice_payment_100"
  let record_2 = "bob_escrow_250"
  let record_3 = "charlie_refund_50"

  // Only the prover can compute the address for each record
  let pi_1 = vrf.prove(sk, record_1, "ECVRF_")
  let Some(beta_1) = vrf.proof_to_hash(pi_1)

  let pi_2 = vrf.prove(sk, record_2, "ECVRF_")
  let Some(beta_2) = vrf.proof_to_hash(pi_2)

  let pi_3 = vrf.prove(sk, record_3, "ECVRF_")
  let Some(beta_3) = vrf.proof_to_hash(pi_3)

  // On-chain: store (beta_i, encrypted_payload_i) in a public Merkle tree
  // Only the owner knows which beta corresponds to which record
}
```

**What is happening, step by step:**

1. **Key generation** – `keys_from_secret` derives a 32-byte secret scalar and a 96-byte compressed public key in G2. It uses HKDF internally to ensure the scalar is uniformly distributed and non-zero.
2. **Proof generation** – `prove` hashes the record name to a point on G2, multiplies it by the secret scalar, and wraps the result in a Schnorr-style proof that binds the output to the public key.
3. **Hash extraction** – `proof_to_hash` converts the proof into a fixed 32-byte pseudorandom value. This is the "address" of the record.
4. **Storage** – the contract stores `(beta, encrypted_payload)` pairs. Without the secret key, no one can compute `beta` from the record name, so enumeration is impossible.

Later, to prove that a record exists, the owner simply reveals the original name and the proof:

```aiken
fn prove_membership(pk, record_name, pi) {
  // Anyone can verify and recover the exact same beta
  let Some(beta_verified) = vrf.verify(pk, record_name, pi, "ECVRF_", False)
  // Check that beta_verified is present in the public Merkle tree
}
```

If the verifier passes, the record is confirmed without ever revealing the other records or their positions.

### Case 2: Non-interactive randomness beacon

Many protocols need a source of randomness that is simultaneously unpredictable, verifiable, and non-interactive. Centralized beacons require trust. Commit-reveal schemes require two rounds and can be aborted. A VRF solves all of this in a single message.

The pattern is simple: a trusted operator publishes their public key in advance. For each round, they use a public input—say a block hash or a round number—as the VRF input. They compute the proof privately, then publish `(input, proof, hash)`. Anyone can verify the proof and recover the same hash.

```aiken
use vrf/core as vrf

fn run_randomness_beacon() {
  let operator_secret = "operator_secret_key"
  let (sk, pk) = vrf.keys_from_secret(operator_secret)

  // Round 1: input is a public block hash
  let round_1_input = "block_12345_hash"
  let pi_1 = vrf.prove(sk, round_1_input, "ECVRF_")
  let Some(beta_1) = vrf.proof_to_hash(pi_1)

  // Round 2: different input produces a different, unpredictable output
  let round_2_input = "block_12346_hash"
  let pi_2 = vrf.prove(sk, round_2_input, "ECVRF_")
  let Some(beta_2) = vrf.proof_to_hash(pi_2)

  // Operator publishes (pk, round_input, beta, pi) for each round
  // Anyone can verify:
  let verified_1 = vrf.verify(pk, round_1_input, pi_1, "ECVRF_", False)
  let verified_2 = vrf.verify(pk, round_2_input, pi_2, "ECVRF_", False)

  // verified_1 == Some(beta_1) and verified_2 == Some(beta_2)
  // beta_1 != beta_2, and neither was predictable before the input was known
}
```

**What is happening, step by step:**

1. **Key setup** – the operator generates a long-term key pair and publishes the public key. The secret never leaves their secure environment.
2. **Private computation** – when a round's public input is known (e.g., a block hash is mined), the operator computes `prove(sk, input, salt)`. The proof is a 144-byte value that cryptographically binds the input, the output, and the public key.
3. **Hash extraction** – `proof_to_hash` extracts the 32-byte pseudorandom output `beta`. Before the input was known, `beta` was indistinguishable from random to anyone without the secret.
4. **Publication** – the operator publishes a single tuple `(input, beta, proof)`. No interaction is needed.
5. **Verification** – anyone runs `verify(pk, input, proof, salt, False)`. If it returns `Some(beta)`, the operator did not cheat. If it returns `None`, the proof is invalid.

Because the input is public and fixed, the operator cannot grind on it to produce a favorable output. They get exactly one shot per round.

### Other use cases

Beyond the two cases above, the `aiken/vrf` project tests several other patterns that are worth mentioning:

- **Leader selection** – In proof-of-stake consensus, each stakeholder privately computes their VRF output for the current epoch. If the output falls below a threshold proportional to their stake, they are selected as the slot leader. Only the winner reveals their proof, preventing pre-slot DDoS attacks.
- **Proof of prior possession** – A party can prove they knew a secret at a specific time by using the secret itself as the VRF input. The resulting proof is self-bound: it only verifies against that exact secret, and it does not leak the secret itself.
- **Passwordless authentication** – A server stores `(pk, last_beta)`. The client proves knowledge of their password-derived key by producing a VRF proof, without ever sending the password.

### Summary

The `aiken/vrf` project provides a complete, RFC-compliant ECVRF implementation over BLS12-381 G2 using only Aiken and Plutus builtins. The API is minimal: `keys_from_secret`, `prove`, `verify`, and `proof_to_hash`. With these four functions, you can build privacy-preserving data structures, verifiable randomness beacons, leader-selection protocols, and non-interactive proofs of knowledge. The key insight is always the same: the prover computes a private, deterministic, pseudorandom output; the verifier checks it publicly; and neither the secret nor the output is forgeable.

## Proof systems