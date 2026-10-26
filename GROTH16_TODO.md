# Groth16 Remaining Work in `cardano-foundation/bls`

This document is a living snapshot of what still needs to be done on the
Groth16 track in this repository. It was generated from a codebase audit and
is intended to guide prioritisation.

## Status at a glance

| Area | State |
|---|---|
| Core prover/verifier (BLS12-381) | Complete, tested, cross-checked against Sage/zeroj |
| CLI tooling (`prove`, `verify`, `export-vk`) | Complete |
| Dev + Phase-2 MPC trusted setup | Complete on top of public `.ptau` SRS |
| Sparse-matrix proving for large circuits | Complete |
| Batch verification (N+3 Miller loops) | Complete |
| On-chain Aiken verifier (single + batch) | Complete |
| SnarkPack-style proof aggregation | **Not implemented** |
| Embedded Groth16 pairing inside Nova step | **Scaffold / TODO** |
| Formal verification | Very limited (6 small Verus functions) |
| Production ceremonies for value-bearing circuits | Not run |
| CardanoKeyOwnershipStrong monolithic Groth16 | Infeasible on 32 GiB RAM; Nova path slow |

## Prioritised remaining work

### P0 — High impact, ready to start

1. **Groth16 proof aggregation (SnarkPack-style)**
   - *What:* Aggregate many Groth16 proofs into a single short proof.
   - *Where:* `clis/trusted-setup/src/prover.rs`, `clis/groth16/src/cmd/`.
   - *Why:* Batch verification is already done; aggregation is the next cost
     reduction for rollups and batched pools. Explicitly listed as roadmap item
     (q) in `groth16-prover/README.md`.
   - *Effort estimate:* 2–4 weeks.

2. **Complete Step 9 recursive MetaBatch circuit**
   - *What:* Implement Miller loop + final exponentiation in R1CS so a full
     Groth16 batch verifier can run inside a Nova step circuit.
   - *Where:* `circom/MetaBatch/groth16_batch_verifier_nova.circom`,
     `aiken/selective-disclosure/step9/`.
   - *Why:* Enables recursive aggregation of Groth16 proofs inside Nova IVC.
   - *Effort estimate:* 3–6 weeks (Miller loop 2–4 weeks, final exponentiation
     1–2 weeks, per existing docs).

3. **Add `cardano-foundation/nova-slim` as a competitive benchmark system** ✅
   - *What:* Extend the existing benchmark harness so that every Groth16/Nova
     comparison also reports numbers from the upstream `nova-slim`
     implementation (BLS12-381 slim proofs, level-1 verifier, optional SIS/Hash
     commitments).
   - *Delivered:* `circom/benchmarks_nova_slim.py` runs BLS Groth16, BLS Nova
     (Impl 9 / Impl 11), and upstream NovaSlim on the same CardanoKeyOwnership
     workload. Results are integrated into `nova-prover/README.md`,
     `clis/nova/README.md`, and `README.md`.
   - *Why:* The upstream repo has diverged from the in-tree `nova-prover`
     snapshot; side-by-side numbers are needed to decide whether to migrate the
     BLS Nova path upstream and to quantify the trade-off between trusted-setup
     Groth16 and transparent folding.

### P1 — Important, but blocked or larger

4. **Bit-for-bit Rust FFT ↔ zeroj deterministic cross-check**
   - *What:* Close the remaining parity gap between the Rust `FftQapEngine` and
     zeroj's deterministic fixture.
   - *Where:* `zeroj-assessment/ZerojAudit.md` §8, `clis/trusted-setup/src/engine.rs`.
   - *Why:* Removes the last correctness caveat in the zeroj audit.

5. **Expand formal verification coverage**
   - *What:* Verify parser byte-cursor bounds, wire-id validation, MPC delta-chain
     invariants; produce an EasyCrypt model of the Aiken verifier.
   - *Where:* `FormalVerification.md`, `clis/trusted-setup/src/*.rs`,
     `aiken/groth16/README.md`.
   - *Why:* High-assurance claims need more than hand-waving.

6. **Production Phase-2 ceremonies for value-bearing circuits**
   - *What:* Run/audit a Phase-2 MPC for ownership/pool circuits using a public
     `.ptau` SRS; document entropy and verification procedures.
   - *Where:* `clis/trusted-setup/src/phase2.rs`, ceremony runbooks.
   - *Why:* Required before any mainnet deployment.

### P2 — Research / stretch

7. **Resolve CardanoKeyOwnershipStrong economics**
   - *What:* The 15.8M-constraint monolith OOMs on 32 GiB; optimise the Nova step
     chain or split the circuit further.
   - *Where:* `circom/CardanoKeyOwnershipStrong/`,
     `circom/benchmarks_nova_results.json`.

8. **F5 confidential-transfer PoC**
   - *What:* Port the stealth scheme to BLS12-381 Jubjub, build the
     confidential-transfer circuit, integrate with a canonical bridge concept.
   - *Where:* `groth16-prover/docs/F5_RESEARCH_DIRECTION.md`, `aiken/f5/`.

9. **Phase-1 MPC from scratch**
   - *What:* Remove dependency on external PPoT Phase 1.
   - *Where:* `groth16-prover/docs/MPC_Ceremony_Research.md`.
   - *Why:* Only if sovereignty requires it; large undertaking.

10. **CI/platform hardening for the native blst backend**
    - *What:* Full Windows/Linux/macOS blst build matrix, clean platform
      binaries.
    - *Where:* `clis/trusted-setup/native/`.

## Recommended next sprint

If the goal is to get the Groth16 track into a publishable/demo-ready state, the
highest-ROI sequence is:

1. Land the `nova-slim` benchmark integration (P0 #3) — it gives immediate
   comparative data and validates the upstream API against our circuits.
2. Pick either SnarkPack aggregation (P0 #1) or the MetaBatch embedded verifier
   (P0 #2) depending on whether the target use case is off-chain batching or
   recursive on-chain aggregation.
3. Use the benchmark data to decide whether to migrate the in-tree Nova path to
   the upstream `nova-slim` implementation.

## Files consulted

- `groth16-prover/README.md`
- `clis/trusted-setup/README.md`
- `clis/groth16/README.md`
- `aiken/groth16/README.md`
- `circom/README.md`
- `FormalVerification.md`
- `zeroj-assessment/ZerojAudit.md`
- `groth16-prover/docs/MPC_Ceremony_Research.md`
- `groth16-prover/docs/F5_RESEARCH_DIRECTION.md`
- `circom/benchmarks_compare.py`
- `circom/benchmarks_nova_results.json`
- `nova-prover/README.md`
- `clis/nova/README.md`
