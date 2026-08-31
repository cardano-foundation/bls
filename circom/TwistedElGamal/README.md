# Twisted ElGamal — confidential transfers

Twisted ElGamal encryption circuits for confidential (private-amount)
transfers.  These can be folded with Nova to produce small, quickly
verifiable proofs (see `aiken/selective-disclosure/README.md` Step 2).

## What Twisted ElGamal gives us

Twisted ElGamal is ElGamal with the plaintext "twisted" into the exponent:

```
E = r * G       (ephemeral)
C = m * H + r * PK   (commitment)
```

- **G, H** — two independent JubJub generators (here `H = 2·G`, deterministic).
- **PK = sk·G** — recipient public key.
- **Decryption**: `m·H = C − sk·E`, then recover the small message `m` by
  brute-forcing the safe-space discrete log.
- **Additive homomorphism**: `Enc(m1) + Enc(m2) = Enc(m1 + m2)`.

Homomorphy is what lets a verifier check ciphertext relations
(`C_new = C_old − C_transfer`) using only point additions — the zero-knowledge
circuit only has to prove the *integer* arithmetic and range constraints.

### Why JubJub?

The circuit field is the BLS12-381 scalar field (`r`).  On a Cardano chain we
would like to verify against BLS12-381 G1, but doing so in-circuit requires
**non-native field arithmetic** (G1 coordinates live in GF(p), not GF(r)).
JubJub is a twisted Edwards curve **over GF(r)**, so all the standard Circom
edwards/scalar-mul templates work natively.  The on-chain verifier can still
use BLS12-381 G1 group operations for the (native) group law; the mapping is
documented in the parent README.

## Circuits

| File | What it proves |
|------|----------------|
| [`twisted_elgamal.circom`](twisted_elgamal.circom) | Knowledge of `(m, r)` such that `E = rG`, `C = mH + rPK`. Also a `TwistedElGamalDecrypt` template for `C − sk·E == m·H`. |
| [`limb_decompose.circom`](limb_decompose.circom) | Split a message into `nLimbs × u16` limbs; each limb is range-bounded to `[0, 2^16)` — the primitive enabling **selective disclosure**. |
| [`transfer.circom`](transfer.circom) | Single monolithic transfer: `newBalance == oldBalance − amount`, `amount` and `newBalance` range-checked to `[0, 2^16)`. |
| [`twisted_elgamal_nova.circom`](twisted_elgamal_nova.circom) | **Nova IVC step** — processes one `u16` limb per step and accumulates `state_out = state_in + (new_limb − old_limb)`, with both limbs range-checked. `n_pub_in == n_pub_out == 1`. |

## Design notes / caveats

- **Message space**: the plaintext is recovered by brute-forcing `m·H`, so the
  message must be small (here `u16` limbs per ciphertext).  The scheme is
  intended for confidential *values* (balances/amounts), not arbitrary data.
- **H derivation**: here `H = 2·G`.  Deployments must replace this with a
  hash-to-curve-derivation so that `log_G(H)` is unknown — otherwise the
  generator trapdoor weakens the hiding guarantee.
- **Range via `Num2Bits`**: each limb is decomposed with `Num2Bits(16)`, which
  constrains every bit to `{0,1}` and thereby bounds the limb to `[0, 2^16)`,
  so no separate range-proof template is required.

## Compile

```bash
cd circom/TwistedElGamal

# The `-l` flags point at the Circomlib include directories (bitify, mux3, …).
circom twisted_elgamal.circom --r1cs --wasm --sym --prime bls12381 \
  -l ../EdDSAJubJub/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits

# likewise for: limb_decompose, transfer, twisted_elgamal_nova
```

`--prime bls12381` **must** match the Rust prover / Nova verifier curve.

## Size

| Circuit | Non-linear constraints |
|---------|----------------------|
| `twisted_elgamal` | 10,206 |
| `limb_decompose` (8 limbs) | 128 |
| `transfer` | 32 |
| `twisted_elgamal_nova` (1 step) | 32 |

## Nova e2e

The Nova step circuit (`twisted_elgamal_nova`) compresses a multi-limb
transfer into a single fold proof.  Compile it with the command above, then
use the `nova-slim` CLI as described in
[`aiken/selective-disclosure/README.md`](../../aiken/selective-disclosure/README.md)
Step 2.
