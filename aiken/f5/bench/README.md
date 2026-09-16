# F5 — benchmarks (Groth16 proving + Impl 11 batch verification)

`bench_f5_groth16.sh` sweeps the multi-user pool over the Groth16 pipeline in
`groth16-prover` (Impl 7 proving; Impl 11 batched verification). Every config is
driven through the exact same e2e script the demo uses, so the numbers below are
what the F5 pool costs:

- **witness / ceremony / prove** — unchanged production paths
- **verify** — the "before": one `groth16 verify` process per proof (4 pairings
  each)
- **batch-verify** — the "after": a single `groth16 verify-batch` process that
  checks all proofs with **one multi-pairing product** (Impl 11)

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
verify ~4.5-4.9 MiB).

| config | users | spends | depth | constraints | witness | ceremony | prove | verify | batch-verify | speedup | total |
|---|---|---|---|---|---|---|---|---|---|---|---|
| d4_u1 | 1 | 1 | 4 | 7087 | 1.0s | 6.9s | 3.2s | 0.1s | 0.1s | 1.2x | 11.3s |
| d6_u4 | 4 | 4 | 6 | 8365 | 3.9s | 8.6s | 17.8s | 0.2s | 0.1s | 2.6x | 30.5s |
| d6_u8 | 8 | 8 | 6 | 8365 | 6.9s | 8.0s | 34.0s | 0.4s | 0.1s | 4.3x | 49.3s |
| d6_u16 | 16 | 16 | 6 | 8365 | 12.5s | 7.2s | 63.1s | 0.7s | 0.2s | 4.1x | 83.8s |

(witness/prove/verify/batch-verify are totals across all proofs of the config;
ceremony runs once per config.)

## Reading the numbers

* **Ceremony is constant** (~7.2-8.6 s) regardless of user count — the trusted
  setup is done once for the whole pool and the cost does not grow with users.
* **Witness, prove, verify scale linearly** in the number of spends
  (16 users ≈ 16x a single user), and prove dominates.
* **Prove dominates the pool economy**: proof *generation* is the hot path and
  batching does not reduce it. Batching collapses the *verifier* cost.
* **Batch verify on the verifier side (Impl 11):**
  * N single verifies run `4N` full pairings (each with its own final
    exponentiation, plus per-process VK load); the batched verifier runs one
    multi-Miller-loop over `N+3` pairs with a **single** final exponentiation.
  * Math-only, batch-verify is `4N → N+3` pairings (≈3.8x at N=16) **and** one
    final exponentiation instead of `4N`.
  * The measured wall-clock speedup here is **2.6x-4.3x at N=4-16** — the
    end-to-end numbers also amortize per-proof process startup + verifying-key
    deserialisation, exactly the real-world relayer/bundler win of checking many
    spends in one process.

This table is the "before/after" capture for the F5 verification upgrade:
individual verify vs Impl 11 batch verify on the same proofs.

## Reproducing

Artifacts are all under `$OUT_DIR/<config>/`:
`e2e.log`, `timings.tsv`, plus the per-user proofs/public inputs, `pp_vk.ak`
and `scenario.json` from the e2e. `results.tsv` is the machine-readable source
of the table above.