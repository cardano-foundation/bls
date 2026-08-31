# Step 2 — Twisted ElGamal: runnable e2e scripts

Reproducible, copy-paste e2e for **confidential (amount-hiding) transfers**.
Two proof paths for the same transfer:

- `groth16_e2e.sh` — one monolithic `transfer.circom` proof (32 constraints).
- `novaslim_e2e.sh` — the transfer decomposed into u16 limbs, folded one limb
  per step with Nova; the chain accumulates to `-amount` (value conservation).

Both prove, without revealing amounts: `newBalance == oldBalance - amount`,
`amount ∈ [0, 2^16)`, `newBalance >= 0`.

## Run

```bash
./groth16_e2e.sh                 # default 100 -> 70 (amount 30)
./novaslim_e2e.sh                # default 100000 -> 99750 (amount 250, 8 limbs)
```

Overrides: `OLD=` `NEW=` (both scripts), `NLIMBS=` (NovaSlim). Artifacts in
`/tmp/sd_step2_{groth16,novaslim}/` (`OUT=` to override).

## Prerequisites

- `circom`, `snarkjs`, Python 3.
- `--prime bls12381` (must match the Rust prover).
- NovaSlim CLI at [`nova-slim`](../../../nova-slim) (build `cargo build --release`).

The NovaSlim path uses the new multi-limb generator
[`circom/TwistedElGamal/gen_teg_steps.py`](../../../circom/TwistedElGamal/gen_teg_steps.py)
(modeled on the Privacy Pool's `gen_nova_privpool_steps.py`).

## On-chain

| Path | On-chain verifier | Datum / redeemer |
|------|-------------------|------------------|
| Groth16 | `aiken/groth16` gate (pairing check) | datum = `vk`, redeemer = `proof` + public `(oldBalance, newBalance)` |
| NovaSlim | [`nova-slim/cardano/nova-slim-verifier`](../../../nova-slim/cardano/nova-slim-verifier) | datum = `NifsBundle`, redeemer = `SlimProof` |

Groth16 emits `transfer_vk.ak`; NovaSlim emits `teg.ivc.cbor` + `teg_slim.proof.cbor`.

## Representative timing (dev machine)

| Phase | Groth16 | NovaSlim (8 limbs) |
|-------|---------|--------------------|
| compile | 0.2 s | 0.2 s |
| witness | 0.9 s | 15.1 s (8 steps) |
| trusted setup | 0.2 s | — (transparent) |
| prove / fold+compress | 0.06 s | 0.3 + 0.4 s |
| verify | 0.05 s | 0.01 s |
| **proof size** | **192 B** | **462 B** |
