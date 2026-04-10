# Verifiable Random Functions

### High level description

A Verifiable Random Function (VRF) is a cryptographic primitive that provides a deterministic, verifiable hash output from an input. It is the public-key version of a keyed hash - only the holder of the secret key can compute the hash, but anyone with the public key can verify the correctness of the hash.

**Key properties:**
- **Uniqueness**: For any fixed public key and input, only one valid proof exists for a given hash output
- **Collision resistance**: It is infeasible to find two different inputs that produce the same hash output
- **Pseudorandomness**: The hash output appears random to anyone who doesn't know the secret key

**Use cases:**
- **Privacy-protected data structures**: Prevent enumeration attacks on hash-based data structures (e.g., private UTXO sets in blockchains)
- **Leader selection**: Randomly select leaders in consensus protocols without revealing the winner until after selection
- **Proof of prior possession**: Demonstrate knowledge of a secret without revealing it
- **Non-interactive randomness**: Generate verifiable randomness for lotteries or gaming applications

**Basic workflow:**

Import the library:
```
use vrf/core as vrf
```

1. **Key Generation**: Generate a secret key (SK) and public key (PK) pair
   ```
   (sk, pk) = vrf.keys_from_secret(secret_keying_material)
   ```

2. **Prove**: Compute the proof for a given input
   ```
   pi = vrf.prove(sk, alpha, salt)
   // alpha is the input, salt is encode_to_curve_salt (e.g., "ECVRF_")
   ```

3. **Proof to Hash**: Extract the hash output from the proof (optional)
   ```
   Some(beta) = vrf.proof_to_hash(pi)
   // Returns Some(beta) if proof is valid, None otherwise
   ```

4. **Verify**: Anyone can verify the proof using the public key
   ```
   Some(beta) = vrf.verify(pk, alpha, pi, salt, validate_key_flag)
   // Returns Some(beta) if valid, None if invalid
   ```

The relationship: `VRF_hash(SK, alpha) = VRF_proof_to_hash(VRF_prove(SK, alpha))`

VRF is standarized in [standard](https://www.rfc-editor.org/rfc/rfc9381.html#name-vrf-algorithms).

What is important we have standarized for [RSA](https://www.rfc-editor.org/rfc/rfc9381.html#name-rsa-full-domain-hash-vrf-rs) and [elliptic curves](https://www.rfc-editor.org/rfc/rfc9381.html#name-elliptic-curve-vrf-ecvrf).
In elliptic curves BLS12-381 is not present. Here we show that **we CAN implement VRF using aiken bls12-381 primitives** and how it could be implemented.

## Building and testing

```sh
aiken check
```

## Resources on Aiken

Find more on the [Aiken's user manual](https://aiken-lang.org).

