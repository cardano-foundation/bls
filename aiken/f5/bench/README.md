# F5 — benchmarks (current Groth16 impl)

`bench_f5_groth16.sh` sweeps the multi-user pool over the *current* Groth16
pipeline — the one shipped in `groth16-prover` (Impl 7). Every config is driven
through the exact same e2e script the demo uses, so the numbers below are what
the F5 pool costs today, unchanged, before we upgrade verification.

Configs are `depth:users[:spends]` (defaults `4:1 6:4 6:8 6:16`). Because the
stock `privacy_pool.circom` hardcodes depth 4, the bench materializes an
otherwise-identical depth-varied circuit via `gen_circuit_depth.py` so the tree
can hold all users + their output leaves (`USERS + 2*SPENDS <= 2^DEPTH`).

```bash
# defaults, output /tmp/f5_bench (results.tsv + results.md + per-config artifacts)
bash aiken/f5/bench/bench_f5_groth16.sh

# custom sweep
CONFIGS="4:1 6:4 6:8 6:16" OUT_DIR=/tmp/f5_bench bash aiken/f5/bench/bench_f5_groth16.sh
```

## Measured (this machine — Intel dev box, 4 cores / 26 GB)

Proof size is constant: **192 bytes** (compressed BLS12-381). Each table shows
wall-clock totals per phase for that config; Max RSS is recorded per phase in
`results.tsv` (witness ~63-65 MiB, ceremony ~25-30 MiB, prove ~20-26 MiB,
verify ~4.5-4.8 MiB).

| config | users | spends | depth | constraints | witness | ceremony | prove | verify | total |
|---|---|---|---|---|---|---|---|---|---|
| d4_u1 | 1 | 1 | 4 | 7087 | 1.4s | 7.6s | 3.8s | 0.1s | 12.8s |
| d6_u4 | 4 | 4 | 6 | 8365 | 5.4s | 10.0s | 22.7s | 0.3s | 38.3s |
| d6_u8 | 8 | 8 | 6 | 8365 | 9.9s | 9.8s | 45.7s | 0.7s | 66.1s |
| d6_u16 | 16 | 16 | 6 | 8365 | 21.1s | 10.0s | 90.0s | 1.1s | 122.3s |

(witness/prove/verify are totals across all proofs of the config; ceremony runs
once per config.)

## Reading the numbers

* **Ceremony is constant** (~7.6-10 s) regardless of user count — the trusted
  setup is done once for the whole pool and the cost does not grow with users.
* **Witness, prove, verify scale linearly** in the number of spends
  (16 users ≈ 16x a single user), and prove dominates.
* **Prove dominates the re-scaling economy**: the pool's hot path on the prover
  side is proof *generation*, which batching does not reduce — batching (next
  Groth16 impl) collapses the *verifier* cost: N single verifies
  (≈ 16 × 0.07 s here) into one batched/aggregated verify.

This is the "before" column. After the next Groth16 implementation we re-run
the **same** sweep and table gains an "aggregated/batched" column.

## Reproducing

Artifacts are all under `$OUT_DIR/<config>/`:
`e2e.log`, `timings.tsv`, plus the per-user proofs/public inputs, `pp_vk.ak`
and `scenario.json` from the e2e. `results.tsv` is the machine-readable source
of the table above.