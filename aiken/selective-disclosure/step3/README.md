# Step 3 — Privacy Pool: runnable e2e scripts

Reproducible, copy-paste e2e for **shielded transfers** (privacy pool: 1-in /
2-out spend with Merkle membership + nullifier uniqueness + range + value
conservation). Two proof paths:

- `groth16_e2e.sh` — one monolithic `privacy_pool.circom` proof (~7.1K
  constraints at depth 4, `--sparse` ceremony/prove).
- `novaslim_e2e.sh` — the input note's commitment walked through the Merkle
  tree one level per Nova step, folding the leaf into the pool's root.

## Run

```bash
./groth16_e2e.sh                 # depth 4
./novaslim_e2e.sh                # depth 4 (4 Merkle-level steps)
```

Overrides: `DEPTH=` (both). Artifacts in `/tmp/sd_step3_{groth16,novaslim}/`
(`OUT=` to override).

## Prerequisites

- `circom`, `snarkjs`, Python 3.
- `--prime bls12381` (must match the Rust prover).
- NovaSlim CLI at [`nova-slim`](../../../nova-slim) (build `cargo build --release`).

## On-chain

| Path | On-chain verifier | Datum / redeemer |
|------|-------------------|------------------|
| Groth16 | `aiken/groth16` gate (pairing check) | datum = `vk`, redeemer = `proof` + public `(merkle_root, nullifier_hash, out_commitment_1, out_commitment_2, fee)` |
| NovaSlim | [`nova-slim/cardano/nova-slim-verifier`](../../../nova-slim/cardano/nova-slim-verifier) | datum = `NifsBundle`, redeemer = `SlimProof` |

Groth16 emits `pp_vk.ak`; NovaSlim emits `pp.ivc.cbor` + `pp_slim.proof.cbor`.

## Representative timing (dev machine)

| Phase | Groth16 | NovaSlim (4 steps) |
|-------|---------|--------------------|
| witness prep | 0.3 s | 0.3 s |
| compile | 1 s | 0.4 s |
| witness | 0.8 s | 8.4 s (4 steps) |
| trusted setup | 5.8 s | — (transparent) |
| prove / fold+compress | 2.5 s | 2.7 + 4.5 s |
| verify | 0.05 s | 0.01 s |
| **proof size** | **192 B** | **610 B** |
