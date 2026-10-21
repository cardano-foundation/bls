# Nova IVC On-Chain Verifier + SD Predicate Gate (Aiken)

Aiken (Plutus V3) implementation that verifies **slim Nova IVC proofs** produced
by the Rust [`nova-slim`](https://github.com/paweljakubas/nova-slim/blob/master/README.md) on Cardano, plus a reusable
**Selective-Disclosure (SD) Predicate Gate** built on top of it.

Toolchain: **aiken v1.1.19** (see `aiken.toml`).

> **The prover is upstream.** The cutting-edge Nova implementation — **NovaSlim** (NIFS folding, transparent sumcheck compression, ~0.4 KiB on-chain proofs, no trusted setup, no pairings) — is maintained in its own repository: **[`paweljakubas/nova-slim`](https://github.com/paweljakubas/nova-slim)**. This package is the on-chain (Plutus V3) counterpart of the proofs that repository produces; the in-tree [`clis/nova`](../../clis/nova/) CLI and [`nova-prover`](../../nova-prover/) crate are the matching snapshot of the prover side.

> **This verifier targets the transparent path.** The Aiken verifiers here check the *slim sumcheck* proof (Implementation 11) — the one produced by `nova compress --slim` and by the upstream `nova-slim` CLI. The in-tree `nova compress` default is the paper-faithful Groth16 compression (Implementation 9, one pairing), whose on-chain counterpart lives in [`aiken/groth16`](../groth16/); the transparent path is one flag away (`--sumcheck` / `--slim`).

## What this verifier does

The Nova prover folds an IVC chain of step-circuit witnesses into a single
relaxed R1CS instance, then compresses it into a **slim sumcheck proof**. On
chain we re-derive the sumcheck challenges via Fiat-Shamir (BLAKE2b-256 +
mod r), so attacker-supplied `r_challenges` cannot be forged. The HashPC
commitment openings are verified off-chain as an audit trail.

## Structure

```
lib/nova/
  types.ak       SlimProof, FinalInstance, CircuitParams, PredicatePolicy
  verifier.ak    verify_slim (precomputed challenges), verify_slim_fs
                 (on-chain Fiat-Shamir), verify_predicate_gate, field_prime
  test_fiat_shamir.ak
validators/
  placeholder.ak       generic Nova sumcheck validator (datum = Option<CircuitParams>)
  predicate_gate.ak    SD Predicate Gate (policy in datum)
```

<details>
<summary><b>SD Predicate Gate (click to expand)</b></summary>

## SD Predicate Gate

`validators/predicate_gate.ak` is a **reusable** spending validator: one script
address serves many gates because the gate's policy lives in the **datum**, not
baked into the script.

- **Datum:** `Option<(CircuitParams, PredicatePolicy)>`
  - `CircuitParams`: expected step-circuit shape (`n_wires`, `n_constraints`,
    `n_pub_out`, `n_pub_in`) — e.g. the composite Predicate depth-2 step:
    `{ n_wires: 10463, n_constraints: 10461, n_pub_out: 5, n_pub_in: 5 }`.
  - `PredicatePolicy`: `{ issuer_pk_u, issuer_pk_v, current_year, country_root }`.
- **Redeemer:** `SlimProof`.
- **Accepts iff** (see `verifier.verify_predicate_gate`):
  1. the slim sumcheck proof is sound (`verify_slim_fs`), and
  2. `proof.circuit_params == expected_params`, and
  3. the proof's public state `x` equals
     `[issuer_pk_u, issuer_pk_v, current_year, country_root, eligible=1]`.

Credential fields (`dob_year`, `country`, signature, Merkle path) never appear
in `x` — they're hidden inside the folded witness — so the gate reveals only
that *some eligible* holder produced a valid proof.

</details>

## Check

```bash
aiken check
# 22 checks, 0 errors, 0 warnings
```
