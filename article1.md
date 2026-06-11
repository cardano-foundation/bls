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

## BLS

## KDF

## VRF

## Proof systems