# F5 — Multi-User Private Pools: Groth16 end-to-end demo

The reproducible multi-user demonstration of **F5** on the *current* Groth16
stack (Impl 7, single-proof verify). This is the "demo first" phase: before we
upgrade the pool to batched/aggregated verification (next Groth16 impl), we
show the full multi-user flow working end-to-end today and measure it.

## What it does

`gen_multi_input.py` builds a scenario through the faithful pool simulation in
`../pool` (same Poseidon/tree as `circom/PrivacyPool`):

1. `USERS` users each deposit a note into the shared pool (leaves in the
   Poseidon Merkle tree).
2. `USERS` users each submit a 1-in / 2-out spend (`deposit` → `spend`), each
   against the *live* pool root at the time of their transaction, updating root
   and nullifier log as they go.
3. Every spend becomes one Groth16 proof via the trusted-setup/groth16 CLIs
   (witness → `ceremony-dev --sparse` → `prove --sparse` → `verify`).

The pool bookkeeping guarantees conservation, no-double-spend and path
correctness by construction (validated by the 25 tests in `../pool`).

## Usage

```bash
# defaults: depth 4, 4 users/spends, seed 42, output /tmp/f5_groth16
bash aiken/f5/demo/f5_e2e_groth16.sh

# customize
OUT=/tmp/f5_users8 USERS=8 SPENDS=8 DEPTH=5 SEED=7 \
  bash aiken/f5/demo/f5_e2e_groth16.sh
```

Capacity rule: `USERS + 2*SPENDS <= 2^DEPTH` (each spend inserts two output
leaves).

## Measured (this machine — Intel dev box, 4 cores / 26 GB)

Size: 7,087 constraints, **192 bytes** per proof (BLS12-381 compressed).

| phase (per user unless noted) | wall | Max RSS |
|---|---|---|
| witness (snarkjs, 4 users avg) | 1.63 s | 64.1 MiB |
| dev ceremony (once, `--sparse`) | 8.28 s | 25.5 MiB |
| prove (`--sparse`, per user avg) | 3.99 s | 20.0 MiB |
| verify (per user avg) | 0.08 s | 4.5 MiB |

Total for 4 users / 4 spends: **~31.1 s** (ceremony + 4×(witness+prove+verify)).

## Artifacts

| file | meaning |
|---|---|
| `$OUT/user_NNN.proof` | Groth16 proof for user N |
| `$OUT/user_NNN.pub` | public inputs in circuit order `[root, nh, oc1, oc2, fee]` |
| `$OUT/pp_vk.ak` | exported verifying key for `aiken/groth16` |
| `$OUT/scenario.json` | ordering, final root, spent nullifier hashes, per-user publics |
| `$OUT/timings.tsv` | `<user> <phase> <wall_s> <maxrss_KiB>` |

## What comes next

* Benchmarks: sweep users/transactions × {witness, ceremony, prove, verify,
  proof size, memory}.
* Next Groth16 impl: batch pairing verification + proof aggregation (Impl 11
  in `groth16-prover/README.md`), then re-run the **same** e2e and compare.