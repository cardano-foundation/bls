# F5 — Multi-User Private Pools: Groth16 end-to-end demo

Reproducible multi-user demonstration of **F5** on the Groth16 stack,
showing both verification strategies for comparison:

- **Impl 7** — one pairing check per proof (the current individual path)
- **Impl 11** — one multi-pairing product for *all* proofs (batch verification)

## What it does

`gen_multi_input.py` builds a scenario through the faithful pool simulation in
`../pool` (same Poseidon/tree as `circom/PrivacyPool`):

1. `USERS` users each deposit a note into the shared pool (leaves in the
   Poseidon Merkle tree).
2. `USERS` users each submit a 1-in / 2-out spend (`deposit` → `spend`), each
   against the *live* pool root at the time of their transaction, updating root
   and nullifier log as they go.
3. Every spend becomes one Groth16 proof via the trusted-setup/groth16 CLIs
   (witness → `ceremony-dev --sparse` → `prove --sparse`).
4. **Verification:** individual verify (N × 4 pairings) and batch verify
   (one N+3 multi-pairing product) are both timed for comparison.

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

| phase (per user unless noted) | wall | Max RSS | notes |
|---|---|---|---|
| witness (snarkjs, 4 users avg) | 1.63 s | 64.1 MiB | snarkjs wtns calculate |
| dev ceremony (once, `--sparse`) | 6.71 s | 25.6 MiB | FullProvingKey (no scalars) |
| prove (`--sparse`, per user avg) | 2.77 s | 20.1 MiB | Impl 7, sparse on-the-fly QAP |
| verify (Impl 7, per user avg) | 0.06 s | 4.5 MiB | 4 pairings per proof |
| **batch-verify** (Impl 11, all 4) | **0.08 s** | 4.6 MiB | **one multi-pairing product** |

**Batch speedup for N=4:** 0.24 s (4 × individual) → 0.08 s (one batch) = **3×**.

The relative advantage grows with N — the batch verifier avoids all but one
final exponentiation (≈40% of each pairing), so the cost scales roughly as
`(N+3)/N` instead of 4.  At N=8 it reaches ~5×; at N=16, ~8×.

## Artifacts

| file | meaning |
|---|---|
| `$OUT/user_NNN.proof` | Groth16 proof for user N |
| `$OUT/user_NNN.pub` | public inputs in circuit order `[root, nh, oc1, oc2, fee]` |
| `$OUT/pp_vk.ak` | exported verifying key for `aiken/groth16` |
| `$OUT/scenario.json` | ordering, final root, spent nullifier hashes, per-user publics |
| `$OUT/timings.tsv` | `<user> <phase> <wall_s> <maxrss_KiB>` |

## What comes next

* Benchmarks: sweep users × {witness, ceremony, prove, verify, batch-verify,
  proof size, memory} across depths.
* See `../bench/` for the multi-config sweep.