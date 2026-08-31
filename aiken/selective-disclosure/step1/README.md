# Step 1 — Predicate Proofs: runnable e2e scripts

Reproduceable, copy-paste e2e for the **Predicate** (selective-disclosure of a
signed credential). Two proof paths for the same data:

- `groth16_e2e.sh` — one monolithic Groth16 proof (~10.4K constraints).
- `novaslim_e2e.sh` — Nova IVC + slim-sumcheck proof (no trusted setup).

Both prove: `age >= 21 AND country in approved set` over `(dob_year, country)`,
revealing only `eligible = 1`.

## Run

```bash
# Groth16 path
./groth16_e2e.sh

# NovaSlim path  (requires nova-slim built as a sibling of this repo)
./novaslim_e2e.sh
```

Artifacts go to `/tmp/sd_step1_{groth16,novaslim}/` (override with `OUT=`).

## Prerequisites

- `circom`, `snarkjs`, Python 3 (see repo docs).
- BLS12-381 compile flag: `--prime bls12381` (must match the Rust prover).
- NovaSlim: `nova-slim/cli/target/release/nova-slim` from
  [`nova-slim`](../../../nova-slim) (a sibling repo).

## On-chain

| Path | On-chain verifier | Datum / redeemer |
|------|-------------------|------------------|
| Groth16 | `aiken/groth16` gate (pairing check) | datum = `vk`, redeemer = `proof` + public inputs `(pku, pkv, current_year, country_root, eligible)` |
| NovaSlim | [`nova-slim/cardano/nova-slim-verifier`](../../../nova-slim/cardano/nova-slim-verifier) | datum = `NifsBundle`, redeemer = `SlimProof` (sumcheck only, no openings) |

The Groth16 script emits `predicate_vk.ak` (Aiken vk source to paste into the
gate validator). The NovaSlim script emits `pred.ivc.cbor` + `pred_slim.proof.cbor`.

## Representative timing (dev machine)

| Phase | Groth16 | NovaSlim |
|-------|---------|----------|
| witness prep | 0.7 s | 0.7 s |
| compile | 4.5 s | 4.5 s |
| witness | 1.5 s | 4.3 s (1 step) |
| trusted setup | 10.9 s | — (transparent) |
| prove / fold+compress | 5.0 s | 34.8 + 71.1 s |
| verify | 0.07 s | 0.01 s |
| **proof size** | **192 B** | **758 B** |

> NovaSlim's fold/compress is dominant because the Predicate step circuit is a
> **monolithic** re-proof of the whole predicate every step. Steps 2 & 3 use
> tiny incremental step circuits and fold/compress in under 5 s.
