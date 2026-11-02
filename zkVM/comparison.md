# Comparison: Groth16, NovaSlim, and zkVM for CardanoKeyOwnershipStrong

This document compares three ways to prove the `CardanoKeyOwnershipStrong`
statement — knowledge of a 96-byte Cardano master `XPrv` that derives the payment
public key at `m/1852H/1815H/0H/0/0`.

The reference workload is the fixed fixture from
[`circom/CardanoKeyOwnershipStrong`](../circom/CardanoKeyOwnershipStrong):

- `master = bytes(range(96))`
- expected `apk = 63658c2ec89f2fc978bd99c4ee00c6057d6a5b0baa29dc9d62beb4c5e511862c`

| Approach | Location | Status |
|---|---|---|
| Circom + Groth16 | `circom/CardanoKeyOwnershipStrong/cardano_ed25519_ownership_strong.circom` | circuit compiles, witness feasible, **ceremony infeasible** on 32 GiB host |
| Circom + Nova / NovaSlim | `circom/CardanoKeyOwnershipStrong/cardano_ed25519_ownership_strong_nova.circom` + `../nova-slim` | Nova fold works (5.2 h single-core); NovaSlim integration pending |
| zkVM (OpenVM) | `zkVM/openvm/cardano-key-ownership-strong` | compiles to zkVM ELF; host test passes; full proof TBD |

## Statement

All three approaches prove the same relation:

> I know `master` (96 bytes) such that `DeriveCIP1852(master)` compresses to the
> public `apk`.
>
> The derivation is the standard BIP32-Ed25519 / CIP-1852 chain:
> `m / 1852H / 1815H / 0H / 0 / 0`.

The public output is the 32-byte compressed Ed25519 public key; everything else
(the master seed and all intermediate extended keys) stays private.

## High-level comparison

| Criterion | Groth16 (monolith) | Nova / NovaSlim (Circom folding) | zkVM (OpenVM) |
|---|---|---|---|
| **Arithmetization** | R1CS, single circuit | R1CS, 6 uniform folded steps | RV32IM zkVM guest |
| **Backend proof** | Groth16 SNARK | NIFS folding + sumcheck / NovaSlim compression | STARK-based zkVM |
| **Trusted setup** | Per-circuit ceremony | Transparent | Transparent |
| **Statement language** | Circom | Circom | Rust (any no-std code) |
| **Reusable tooling** | `snarkjs` / custom CLI | `nova` CLI / NovaSlim Aiken verifier | OpenVM SDK + `cargo openvm` |
| **Proof size** | ~200 B | Nova IVC bundle ~180 KiB; NovaSlim ~0.4–42 KiB | App proof + aggregation (MB-scale before aggregation) |
| **Verification cost** | ~3.5 s off-chain; cheap on-chain with pairing | Nova off-chain; NovaSlim on-chain ~377K mem / 141M CPU | zkVM verifier; on-chain wrap not yet implemented |
| **Prover time** | ~2.5 min prove (if ceremony existed) | ~5.2 h single-core fold (6 × 5.93M constraints) | TBD; host execution <1 s |
| **Hardware needs** | ≥32 GiB RAM for ceremony | Moderate RAM; CPU-bound | Moderate RAM; CPU-bound |
| **Audit surface** | Circom + Groth16 + trusted setup | Circom + Nova / NovaSlim protocol | OpenVM guest + zkVM STARK prover |

## Groth16

The monolithic circuit is in
[`cardano_ed25519_ownership_strong.circom`](../circom/CardanoKeyOwnershipStrong/cardano_ed25519_ownership_strong.circom).

- **Circuit size:** ~15.8M constraints.
- **Witness generation:** feasible (~2 min 15 s, 1.9 GiB peak).
- **Trusted-setup ceremony:** **infeasible** on the measurement host (`pure`,
  Intel Core i7-7500U, 2C/4T, 32 GiB RAM). Dense run peaked at 29.1 GiB RSS and
  was OOM-killed; sparse run also failed.
- **Proof size:** ~192 B.
- **When to use it:** only if a trusted setup can be run on a much larger
  machine, and tiny proof size / fast on-chain verification are required.
- **Verdict for `strong`:** not practical on modest hardware because the
  ceremony dominates.

## Nova / NovaSlim (Circom folding)

The step circuit is in
[`cardano_ed25519_ownership_strong_nova.circom`](../circom/CardanoKeyOwnershipStrong/cardano_ed25519_ownership_strong_nova.circom).

- **Step size:** ~5.93M constraints.
- **Steps:** 6 uniform folds (seed → 1852H → 1815H → 0H → role → index → final).
- **Witness generation:** ~2 min per step.
- **Fold time:** ≈ 18,700 s (~5.2 h) single-core on `pure`.
- **Ceremony:** none.
- **IVC proof bundle:** ~180 KiB.
- **NovaSlim potential:**
  - proof-mode ladder from ~0.4 KiB (slim, batch-proving model) to ~42 KiB
    (level-1 + norm-jl).
  - Aiken / Plutus V3 verifier exists and has been measured for a VRF stand-in
    circuit at ~377K memory / 141M CPU.
  - The Cardano BIP32-Ed25519 step circuit is being ported from the Circom
    implementation.
- **When to use it:** the best transparent, Cardano-native path for on-chain
  verification once NovaSlim integration is complete.
- **Verdict for `strong`:** the only Circom-based path that runs end-to-end on
  the measurement host.

## zkVM (OpenVM)

The implementation is in
[`zkVM/openvm/cardano-key-ownership-strong`](./openvm/cardano-key-ownership-strong).

- **Guest language:** Rust, reusing `openvm-sha2::Sha512`, `curve25519-dalek`,
  and `num-bigint` for the BIP32-Ed25519 arithmetic.
- **Trust setup:** none.
- **Host execution:** the fixed fixture derives the correct `apk` in <1 s and
  passes the assertion.
- **zkVM build:** compiles to an OpenVM ELF and transpiles successfully.
- **Proving:** not yet benchmarked; expected to be CPU-heavy because the guest
  performs many SHA-512 hashes and an Ed25519 scalar multiplication per
  derivation step.
- **Proof size / verifier:** OpenVM app proofs are large; they must be
  aggregated before they become competitive with NovaSlim. There is no Aiken
  verifier for OpenVM proofs yet.
- **When to use it:** fastest to implement and easiest to audit for Rust teams;
  useful for off-chain custody proofs, benchmarks, and prototyping. Not yet a
  Cardano on-chain solution.
- **Verdict for `strong`:** excellent development velocity and portability, but
  on-chain deployment requires more infrastructure (proof aggregation + Plutus
  verifier).

## Summary

| Goal | Best candidate |
|---|---|
| Tiny proof, fast on-chain verification, hardware available for ceremony | Groth16 (monolith) |
| Transparent, Cardano-native on-chain verification | **NovaSlim** once the step circuit is integrated |
| Fastest implementation, easiest audit, off-chain / prototyping | **OpenVM zkVM** |
| Reference end-to-end proof today on modest hardware | **Nova (Impl 10)** |

The three implementations are complementary:

- Use the **Circom + Nova** path as the current reference benchmark and the
  basis for NovaSlim.
- Use the **OpenVM zkVM** path to iterate quickly, cross-check the derivation
  semantics, and explore zkVM-specific optimizations.
- Use **Groth16** only if a large trusted-setup ceremony becomes feasible and
  the smallest possible proof is required.
