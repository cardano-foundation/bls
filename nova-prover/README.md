# nova-prover

Nova IVC folding for BLS12-381 (arkworks) — the **step-chain** implementation
("Implementation 8") and the roadmap toward constant-size folding.

A long computation is decomposed into `N` identical step circuits, each proving
`state_{i+1} = f(step_i, state_i)`. The `fold` operation runs a chain of
Groth16 proofs over the step witnesses — every step proof is individually
verifiable and the state chain is bound by a BLAKE2b512 transcript — while
`verify` re-checks the whole chain.

The proof-system core (R1CS/QAP/engine, ceremony, circom adapter, prover)
lives in `groth16-prover` / `trusted-setup`; this crate adds the IVC layer.
The `nova` CLI (`clis/nova`) wraps this crate's operations.

## How to use

```bash
# Inspect a step circuit (validates the n_pub_in == n_pub_out invariant)
nova params --circuit step_circuit.r1cs

# Single-party ceremony for a step circuit (per-step Groth16 keys)
nova ceremony --circuit step_circuit.r1cs --proving-key step.pk --verifying-key step.vk

# Fold step witnesses into an IVC bundle
nova fold --circuit step_circuit.r1cs --proving-key step.pk --steps ./step_witnesses/ --out bundle.ivc.json

# Verify a folded IVC bundle (pairings + chain + transcript)
nova verify --ivc bundle.ivc.json --verifying-key step.vk
```

The full step-by-step worked example (`cardano_ed25519_ownership_nova` — 255
steps over the Cardano Ed25519 ownership circuit) is in
[`circom/CardanoKeyOwnership/README.md`](../circom/CardanoKeyOwnership/README.md)
(Variant B, "End-to-end flow — Implementation 8 (Nova step-chain)").

## Design

The complete Nova explanation — folding mechanics, comparison with recursive
arguments (Halo2, CIRCOM-recursive), design decisions for our stack — is in
[`docs/nova-folding-design.md`](docs/nova-folding-design.md).

## Implementation 8 (Nova IVC + compression SNARK)

<details>
<summary><b>Implementation 8 — click to expand</b></summary>

> **Status:** ✅ **Done (POC).** An end-to-end Nova CLI (`nova params / ceremony / fold / verify`) is implemented in the `nova-prover` library + `clis/nova` CLI and smoke-tested on four step circuits (Ed25519Verify, EdDSA-JubJub, CardanoKeyOwnership—Ed25519, AnonymousAirdrop). It proves each step as a **standalone Groth16 proof** and binds the state chain with a BLAKE2b512 transcript. The POC validates the step-decomposition + incremental-proving approach end to end. The full Nova **Relaxed-R1CS folding + compression SNARK** (constant-size proof, no per-step Groth16) is no longer part of this implementation — it is tracked as **Implementation 9 (item (u) below)**.
>
> **Goal:** Eliminate the circuit-specific trusted setup entirely for computations that exceed monolithic Groth16 feasibility (~4M+ constraints), and enable incremental proving where each step fits in memory.

### Problem statement (measured after Implementation 7)

After Implementation 7, proving is no longer the e2e bottleneck. The ceremony is:

| Circuit | Ceremony (monolithic Groth16) | % of e2e time |
|---------|------------------------------|---------------|
| Ed25519Verify (~4M) | ~16 min | ~89 % |
| CardanoKeyOwnership (~1.97M) | ~5 min | ~83 % |
| Hypothetical 10M circuit | ~1+ hour / impossible | — |

The ceremony produces `O(n_vars)` group elements. Unlike proving, there is no `h_scalar`-style algebraic shortcut — the cost is fundamentally tied to circuit size.

### What Nova / IVC does

**Incremental Verifiable Computation** splits a computation into **step circuits** of ~40K constraints each:

```
state_{i+1} = f(step_i, state_i)
```

Each step is proven and **folded** into a running accumulator using a **Relaxed R1CS** scheme. The folding operation is transparent (no SRS). At the end, a small **compression SNARK** (Groth16 over ~100K constraints) proves the accumulator is valid.

| Property | Monolithic Groth16 | Nova IVC |
|----------|-------------------|----------|
| **Total constraints** | C | N × (step_size + overhead) ≈ C + N·overhead |
| **Per-step constraints** | C (all at once) | ~40K–60K |
| **Trusted setup** | Per-circuit, SRS ∝ C | **None** for folding; one ~10–20 s ceremony for compression SNARK |
| **Memory peak** | O(C) — ~3 GiB for 4M | O(step_size) — ~50–100 MiB per step |
| **Proving time** | O(C log C) in one batch | O(N · step_size log step_size) incremental |
| **Proof size** | 192 bytes | ~500 bytes (IVC) + 192 bytes (compression) |
| **Verifier** | One pairing check | Pairing check + IVC accumulator check |

**Important:** The total number of constraints does **not** shrink — it grows slightly (~10K–30K overhead per step). The gain is not "circuit slimming"; it is **ceremony elimination** and **per-step memory scaling**.

### What Nova actually invented: recursion you can afford (the friendly version)

Nova IVC splits a large computation into small step circuits (~40K constraints each) and proves each step incrementally. The key innovation is **folding** — a transparent, linear-time algebraic operation that combines two instances of the same step circuit into a single "relaxed" accumulator instance, valid exactly when both inputs were, without ever re-verifying previous steps. The current POC proves each step as a standalone Groth16 proof and binds the chain with a BLAKE2b512 transcript (N proofs, N pairing checks, bundle O(N)). The production-grade path (Implementation 9) replaces the chain with a single compression SNARK — folding N step instances into one Relaxed-R1CS running instance, then proving it with one Groth16 proof verified with a single pairing check (O(1) bundle, O(1) verify). The compression SNARK is a standard Groth16 circuit (~100K constraints), so our existing `FftQapEngine`, `PippengerProver`, `FullProvingKey` ceremony, and `aiken/groth16` verifier all apply unchanged. Per-step memory drops from O(total constraints) to O(step size), unlocking circuits that currently OOM on commodity hardware. See [docs/nova-folding-design.md](docs/nova-folding-design.md) for the full Nova explanation, folding mechanics, comparison with alternatives, and design decisions for our stack.

### Why this is Implementation 8 (not just research)

1. **Ceremony-agnostic deployment.** Run the compression SNARK setup once (~10–20 s), then reuse it for any IVC computation. New circuits do not need new ceremonies.
2. **Memory scaling.** Per-step memory drops from ~3 GiB (4M constraints) to ~50–100 MiB. This unlocks 10M+ constraint circuits that currently OOM even with sparse matrices.
3. **Composable with existing stack.** The compression SNARK is a standard Groth16 circuit (~100K constraints). Our existing `FftQapEngine`, `PippengerProver`, `aiken/groth16` verifier, and `FullProvingKey` ceremony all apply unchanged. The new work is the IVC prover layer above them.
4. **Enables recursive proof aggregation.** Batch N independent proofs into one IVC chain, then compress to a single Groth16 proof. On-chain verifier cost drops from O(N) pairing checks to O(1).

### Projected gains for our circuits

| Circuit | Monolithic Groth16 | Nova fit | Projected change |
|---------|-------------------|----------|-----------------|
| **SimpleExample (3)** | 3 | ❌ No | Nova overhead (~10K) exceeds circuit by 3000× |
| **Privacy / Spend (1,107)** | 1,107 | ❌ No | Sparse prover already handles it in <1 s |
| **Blake2b-224 Preimage (~79K)** | ~79K | ⚠️ Marginal | Ceremony already ~18 s. Nova would add overhead, not worth it. |
| **EdDSAJubJub (12,601)** | 12,601 | ⚠️ Marginal | Ceremony already ~1 s. Nova overhead ~80% of step size. |
| **CardanoKeyOwnership — JubJub (~4K)** | ~4K | ❌ No | Trivial. |
| **CardanoKeyOwnership — Ed25519 (~1.97M)** | ~1.97M | ✅ Done (POC) | Decomposed into 255 × 7.7K `BitElementMulAny` steps (`cardano_ed25519_ownership_nova.circom`); e2e fold+verify passes. |
| **Ed25519Verify (~4M)** | ~4M | ✅ Yes | Main target. SHA-512 is sequentially foldable. Ceremony drops from ~16 min → ~10–20 s. Memory drops from ~3 GiB → ~50 MiB/step. |
| **F5a Privacy Pool (~65K)** | ~65K | ❌ No | Nova overhead (10–30K) would be 15–45% of each step. Sparse prover already handles this. |
| **F5 full depth-32 (~600K)** | ~600K | ⚠️ Maybe | Worth it only if scaling to depth 64+ or 10M+ constraints. |
| **Hypothetical rollup / 10M+** | Impossible | ✅ Mandatory | Only viable path. |

### Verdict

- ✅ **Implementation 8 POC delivered.** Step decomposition + incremental proving validated end to end on four step circuits; ceremony elimination and per-step memory scaling are demonstrated.
- **Next:** the production-grade fold (Relaxed-R1CS accumulator + compression SNARK) is Implementation 9 — pending, tracked as item **(u)**. Undertake it when the O(N) chain or the per-step ceremony becomes operationally painful.
- **When mandatory:** For 10M+ constraint circuits (rollups, full transaction validation) where monolithic Groth16 is infeasible.

### What exists today (implementation plan, step by step)

The POC does **not** implement Relaxed-R1CS folding — that is the scope of Implementation 9 (item **(u)**). Instead it runs a **chain of ordinary Groth16 proofs**, one per step, and binds the state chain with a BLAKE2b512 transcript. Each step proof is fully independent and verifiable; `nova verify` re-derives the chain and the transcript. The only circuit invariant is **`n_pub_in == n_pub_out`** (the public input block of step `i+1` is the public output block of step `i` — public inputs *are* the IVC state), checked by `nova params`.

```
state_0 ──▶ [step0: f(step_0, state_0)] ──▶ state_1 ──▶ [step1] ──▶ … ──▶ state_N
              │ Groth16 proof0                       │ Groth16 proof1
              └──────────────── transcript ─────────┘
              acc = BLAKE2b512(acc || state_out || proof_bytes)
```

### How to run the e2e flow (worked example: `cardano_ed25519_ownership_nova`)

`cardano_ed25519_ownership_nova.circom` (in `circom/CardanoKeyOwnership/`) decomposes the base-point scalar multiplication into **255 identical steps** of 7,724 constraints each (state `(dblIn[4][3], addIn[4][3])` — 24 public inputs / 24 public outputs, 1 private `sel` bit).

The full step-by-step worked example — building the CLI, compiling the step circuit, the **iterative step-witness generation** that makes the chain invariant hold by construction, and the `nova params` / `ceremony` / `fold` / `verify` run with expected output — is in [`circom/CardanoKeyOwnership/README.md`](../circom/CardanoKeyOwnership/README.md) (Variant B, "End-to-end flow — Implementation 8 (Nova step-chain)"). Quick form:

```bash
../../clis/nova/target/release/nova params   --circuit cardano_ed25519_ownership_nova.r1cs
../../clis/nova/target/release/nova ceremony --circuit cardano_ed25519_ownership_nova.r1cs \
  --proving-key cko255.pk --verifying-key cko255.vk
../../clis/nova/target/release/nova fold     --circuit cardano_ed25519_ownership_nova.r1cs \
  --proving-key cko255.pk --steps <witness-dir> --out cko255_ivc.json
../../clis/nova/target/release/nova verify   --ivc cko255_ivc.json --verifying-key cko255.vk
# → Verified 255 steps: 255 pairings OK, state chain OK, transcript OK
```

Smoke-tested on four step circuits: `ed25519_verify_nova` (255 steps), `eddsa_jubjub_nova` (254), `cardano_ed25519_ownership_nova` (255), `anonymous_airdrop_nova` (5).

### Essence of the improvement

Decompose a computation into `N` identical, small step circuits and prove it **incrementally**, so that **ceremony cost and per-step memory scale with step size, not with total computation**:

- **Ceremony is circuit-agnostic and reusable.** The trusted setup runs once on the ~7.7K-constraint step circuit (seconds), not on the ~1.97M monolithic circuit (minutes). New computations reusing the same step shape need no new ceremony.
- **Memory scales per step.** Peak memory drops from O(total constraints) to O(step size) — the original motivation for 4M+ circuits that OOM a monolithic pipeline.
- **Each step is independently checkable.** Every step proof verifies on its own, and the transcript gives a tamper-evident, independently re-derivable binding of the whole chain.
- **Standard Groth16 stack is reused unchanged** — `FftQapEngine`, `PippengerProver`, `FullProvingKey` ceremony, existing `.pk`/`.vk` formats, `verify_with_vk`. The new code is a thin IVC layer (`nova-prover` + `clis/nova`), not a new prover.

### Strong points

| Strong point | Detail |
|--------------|--------|
| Circuit-agnostic | The CLI works for any step circuit with `n_pub_in == n_pub_out`; only that invariant is checked. |
| One-time setup | A single ceremony per step shape serves all runs; no per-user or per-computation ceremony. |
| Debuggable | `nova fold` fails with the exact step whose `state_in` breaks the chain; each step proof is individually verifiable, so a bad witness is isolated to one step. |
| Auditability | The BLAKE2b512 transcript is fully deterministic; `nova verify` re-derives it from the stored states/proofs — tampering with any step is detected. |
| Low risk | Reuses the battle-tested Groth16 path; no new cryptographic primitives in the POC. |

### Weak points / limitations (of the POC)

The two functional gaps of the POC — it is a proof *chain* (N proofs, N pairing checks, bundle O(N)) rather than real Nova folding, and it has no compression SNARK yet — are exactly the scope of **Implementation 9 (item (u))**. The remaining design-level limitations are:

| Weak point | Detail |
|------------|--------|
| Manual circuit redesign | Step decomposition is per-circuit, hand-written (`state_{i+1} = f(step_i, state_i)`); no automatic compiler from flat Circom R1CS. |
| Sequential folding | The chain is inherently sequential; no parallelism across steps. |
| App-level final checks | Checks that need the *complete* output (e.g. `PointCompress(PointA) == A`) are done outside the fold, not enforced per-step. |
| Overhead | For small circuits (≤ ~10K constraints) Nova overhead exceeds the benefit; it pays off only for large/sequential computations. |

### Cryptographic remarks

- **Q: Does the BLAKE2b512 transcript need domain separation between the folding hash and the state-chain hash?** The POC uses the same BLAKE2b512 transcript for both the state-chain binding (`acc = BLAKE2b512(acc ‖ state_out ‖ proof_bytes)`) and the Fiat-Shamir challenge in the NIFS fold (`r = H(acc ‖ step)`). If the same hash function is used without domain separation, it could lead to transcript-reuse attacks where a malicious prover reuses a folding challenge in a different context. The production-grade Implementation 9 should use domain-separated hash calls (e.g., `H("fold" ‖ acc ‖ step)` vs. `H("chain" ‖ acc ‖ state_out ‖ proof_bytes)`).

- **Q: Is the POC's proof chain (N proofs, N pairing checks, bundle O(N)) the right intermediate, or should we jump directly to the full Nova folding?** The proof chain is a necessary intermediate — it validates the step-decomposition approach end to end and provides individually verifiable step proofs. However, it does not deliver Nova's key benefit (O(1) bundle, O(1) verification). The full Nova folding (Implementation 9) is the critical next step.

- **Q: Does the `h_scalar` optimization interact with Nova's per-step ceremony?** Yes. Since each Nova step has its own ceremony (on the ~7.7K-constraint step circuit, not the monolithic circuit), `h_scalar` reduces per-step ceremony cost. The `h_scalar` compression eliminates the `h_query` MSM (which is proportional to the step circuit size), directly reducing the one-time ceremony cost per step shape. This synergy should be documented and benchmarked together.

</details>

## Implementation 9 (Relaxed-R1CS folding + single compression SNARK)

<details>
<summary><b>Implementation 9 — click to expand</b></summary>

> **Status:** 🔨 **Under the work.** Real Nova folding that upgrades the Implementation 8 step-chain (one Groth16 proof per step, bundle O(N), verification O(N) pairings) to a **constant-size** proof: fold N step instances into one Relaxed-R1CS running instance with a NIFS, then compress with a single Groth16 proof verified with one pairing check. The full design, work items, and non-goals are tracked as **Pending item (u)** below.
>
> **Goal:** O(1) bundle + O(1) on-chain verification for sequential computations, reusing the Implementation 8 step circuits and the existing `nova` CLI unchanged.

### What changes vs Implementation 8

| | Implementation 8 (POC, ✅ done) | Implementation 9 (🔨 under the work) |
|---|---|---|
| Per-step prover work | One full Groth16 proof | Two O(step)-sized MSMs (the NIFS fold) |
| Proof bundle | N Groth16 proofs → O(N) | One relaxed instance + one compression proof → O(1) |
| On-chain verification | N pairing checks | One pairing check |
| Trusted setup | One ceremony per step shape | One small, step-agnostic compression ceremony |

### Scope (full detail in [Pending item (u)](#pending))

1. **NIFS folding module** (in-repo, arkworks BLS12-381): Relaxed-R1CS instance `U=(x,u,W̄,Ē)` with Pedersen G1 commitments; Fiat-Shamir challenge `r=H(acc‖step)` via the existing BLAKE2b512 transcript. Folding runs **off-circuit**, so no curve cycle is needed.
2. **Compression circuit** (own Circom, `circom/RelaxedR1CS/`): proves the final relaxed instance is satisfiable; size ≈ one step; proved with the existing Groth16 prover.
3. **CLI:** `nova fold --nifs` → `nova verify` = transcript check + one pairing check; `params / ceremony` and the step circuits unchanged.
4. **Benchmarks:** extend `benchmark_nova.rs` — bundle O(N)→O(1), verification O(N)→O(1) pairings.

**Non-goals** (details in item (u)): in-circuit IVC recursion (not buildable on BLS12-381 — no 2-cycle) and SuperNova non-uniform steps.

### Cryptographic remarks

- **Q: What are the soundness and completeness properties of the NIFS folding scheme, and what is the soundness error per fold and after N folds?** The NIFS fold is computationally sound under the DLOG assumption on BLS12-381. The soundness error per fold is negligible (dominated by the Fiat-Shamir challenge entropy). After N folds, the accumulated soundness error remains negligible as long as the transcript is collision-resistant. This should be explicitly stated in the design doc and the implementation.

- **Q: What is the constraint cost of embedding Pedersen commitments in the compression circuit, and how does this affect the compression SNARK size?** A Pedersen commitment over G1 with a 381-bit scalar requires ~200–400 R1CS constraints in Circom (for the exponentiation). The compression circuit must verify the folded instance's Pedersen commitments as R1CS constraints. The total constraint count of the compression circuit should be estimated and reported, as it directly impacts the compression ceremony cost and the on-chain verification gas.

- **Q: Is the Fiat-Shamir challenge `r=H(acc‖step)` using the same BLAKE2b512 transcript as the state chain, and if so, is domain separation needed?** Yes — the same BLAKE2b512 hash is used for both the state-chain binding and the folding challenge. Without domain separation, a malicious prover could potentially reuse a folding challenge in a different context. Implementation 9 should use domain-separated hash calls (e.g., `H("fold" ‖ acc ‖ step)` vs. `H("chain" ‖ acc ‖ state_out ‖ proof_bytes)`) to prevent transcript-reuse attacks.

</details>

## Implementation 10 (Post-quantum lattice folding)

<details>
<summary><b>Implementation 10 — click to expand</b></summary>

> **Status:** 🔨 **Under the work.** Post-quantum counterpart of Implementation 9, tracked as **Pending item (v)** below. Implementation 9's folding is *commitment-agnostic* — swapping its Pedersen commitments (DLOG-based, broken by Shor) for an **SIS/Ajtai lattice commitment** yields a post-quantum folding scheme with the same IVC structure (the LatticeFold / Lova / ProtogaLattice line of the folding survey).
>
> **Goal:** a lattice-based IVC chain — lattice folding + PQ compression SNARK + hash-based on-chain verifier — as the long-term quantum-resistance path.

### What gets adapted (full detail in [Pending item (v)](#pending))

1. **Folding layer:** replace the Pedersen commitment with an SIS/Ajtai commitment (Lova's power-of-two modulus q=2⁶⁴ is the easiest fit; the folding math is otherwise unchanged).
2. **Compression:** Groth16 is equally non-PQ, so the compression SNARK must also go lattice/hash-based (sumcheck/GKR with hash- or lattice-polynomial commitments).
3. **On-chain verifier:** replace the Aiken Groth16 verifier with a hash-based (STARK-like) verifier — heavier, trading gas for PQ security.
4. **Steps:** re-arithmetize the step circuits for a small field (circom already supports `--prime goldilocks`).

### Candidate lattice schemes (from [Pending item (v)](#pending))

| Scheme | Assumption | Notes |
|---|---|---|
| LatticeFold (Boneh–Chen 2024) | Module-SIS | Sumcheck-heavy → large verifier circuits, bad per-step overhead |
| **Lova** (ASIACRYPT 2024) | Unstructured SIS, q=2⁶⁴ | Easiest to add; no finite-field modular arithmetic |
| ProtogaLattice (2026) | SIS, constant-round | Algebraic folding, no sumcheck; supports CCS/Plonkish steps |

**Reality check:** a chain is only as PQ as its weakest link, so partial PQ buys nothing — the compression SNARK must go PQ too. A hybrid dual proof (Groth16 OR lattice IVC) hedges the transition at double cost. Full status and trade-offs are in **item (v)**.

### Industry context — CIP-1242 (ZKPoSP) and Zcash's quantum-readiness roadmap

This PQ track is not hypothetical — two production-grade references have committed to exactly the staged posture item (v) recommends (document the risk, keep the classical stack as the default, hedge, migrate when standards mature).

- **CIP-1242 — ZKPoSP, post-quantum ZK signatures for Cardano HD wallets** (Botta, Pospieszalski, Ragnoli, Ranvier, IACR ePrint [2026/1508](https://eprint.iacr.org/2026/1508); CIP draft in [cardano-foundation/CIPs PR 1242](https://github.com/cardano-foundation/CIPs/pull/1242)). Replaces/augments the classical Ed25519 ownership witness with a ZK proof that a public key was derived from a seed along the Cardano BIP-32-Ed25519 path, using a **STARK** (RISC Zero zkVM). Two-phase deployment: Phase 1 verifies proofs **off-chain** (wallets, exchanges, indexers) with no ledger change; Phase 2 adds a **native STARK verifier** on-chain, gated on proof size dropping from ~219 KB toward a few KB. The CIP lists this repo as its classical comparison point — efficient, but pairing-based and not quantum-safe — "useful as a performance bound and for a possible **hybrid**" with the STARK path.
- **Zcash — committed three-step quantum-readiness path** (CoinDesk Research, June 2026). (1) Quantum recoverability (ZIP 2005, Ironwood pool) → (2) ML-KEM (FIPS 203) + Tachyon to close the harvest-and-decrypt window → (3) a fully post-quantum pool with **hybrid classical+PQ signatures** and "hash-based or STARK-style proof hardening" of Halo2. Zcash explicitly defers the SNARK swap: PQ proofs are "much larger" and the primitives are "improving almost weekly" — the same Phase-1-then-Phase-2 discipline as ZKPoSP.

**What this means for item (v):** both references validate the "keep the classical stack, hedge, migrate later" posture, and they broaden the PQ target **beyond lattice folding**. Hash-based / STARK-style proof systems (FRI-STARK, zkVMs like RISC Zero, Halo2-with-FRI) are the other live PQ track — transparent (no trusted setup) and natively post-quantum, at the cost of large proofs. Lattice folding and a STARK/zkVM backend are complementary candidates for a future PQ chain; in both cases the on-chain verifier ends up hash-based.

### Cryptographic remarks

- **Q: Is replacing Groth16's pairing-based compression SNARK with a sumcheck/GKR-based PQ SNARK a drop-in replacement, or does it require a fundamentally different verification stack?** It is not a drop-in replacement. Groth16 verification is a single pairing check (~2 ms on Aiken/Plutus). A hash-based or sumcheck-based verifier is significantly heavier (hundreds of field operations per round, multiple rounds). The on-chain verification cost will increase, trading gas for PQ security. The Aiken verifier would need a complete rewrite, and the Plutus V3 budget may not accommodate a complex hash-based verification circuit.

- **Q: Does the hybrid dual proof (Groth16 OR lattice IVC) actually provide meaningful PQ security, or is it just a hedge that doubles cost?** The hybrid provides meaningful PQ security only if the lattice IVC path is fully implemented and verified. A dual proof where only one path is PQ-secure and the other is classically secure does not raise the overall security level — an attacker who breaks the classical path still forges proofs via the Groth16 path. The hybrid is only useful as a transition mechanism during a migration period, not as a permanent solution.

- **Q: If partial PQ (folding only) buys nothing, should we commit to the full PQ stack or not start down this path at all?** The current recommendation in the README is correct: document the risk and keep the classical stack as the default. The PQ path should only be pursued if quantum timelines shorten significantly. However, the design work for the PQ compression SNARK (sumcheck/GKR with lattice commitments) should be started early enough to inform the classical stack's design decisions — for example, choosing a compression circuit structure that can be adapted to a hash-based verifier later.

</details>

## Pending

### (u) Implementation 9 — Relaxed-R1CS folding (NIFS) + single Groth16 compression proof

- **Current:** Implementation 8 POC proves every step as its own Groth16 proof, chained by a BLAKE2b512 transcript → bundle size and on-chain verification grow O(N); no real folding, no compression SNARK.
- **Target:** Fold N step instances into one Relaxed-R1CS running instance, then compress with a single Groth16 proof verified with one pairing check (O(1) bundle, O(1) verify).
- **Work items:**
  1. **NIFS folding module (in-repo, arkworks BLS12-381):** Relaxed-R1CS instance `U=(x,u,W̄,Ē)`, witness `W=(W,E)`, relaxed equation `(AZ)∘(BZ)=u(CZ)+E`; Pedersen commitment over G1; Fiat-Shamir challenge `r=H(acc‖step)` via the existing BLAKE2b512 transcript (off-circuit, no Poseidon gadget); fold instances and witnesses in linear time. Native over BLS12-381 — **no curve cycle needed because folding runs outside any verifier circuit**. No FFTs, no per-step SNARK: recursion overhead is constant, dominated by two group scalar multiplications in the step circuit (the smallest verifier circuit in the literature), and the prover's per-step work is two MSMs of size O(step).
  2. **Compression circuit (own Circom, `circom/RelaxedR1CS/`):** proves the final relaxed instance is satisfiable (`(AZ)∘(BZ)=u(CZ)+E` for folded `Z=(W,x,u)`), reusing the step's A/B/C matrices; size ≈ one step; proved with the existing Groth16 prover.
  3. **CLI:** extend the `nova` CLI (`nova fold --nifs`): fold N step instances → one relaxed instance → one compression proof; `nova verify` = transcript check + single pairings check. `params / ceremony` and existing step circuits unchanged.
  4. **Benchmarks:** extend `benchmark_nova.rs` — bundle O(N)→O(1); verify one pairing (constant vs N); prover time = fast folding + one step-sized compression proof.
  5. **Non-goals (explicitly documented):** true in-circuit IVC (SuperNova-style recursion) is not buildable on BLS12-381 — requires a 2-cycle (Pasta / BN254–Grumpkin) or non-native `Fq1`-in-`Fr1` emulation (~1M+ gates/scalar mult). SuperNova non-uniform steps (different circuit per step) deferred — Implementation 9 assumes one repeated step circuit.
- **Design (target architecture, moved from Implementation 8):** the POC ships the step-chain CLI; the trait and accumulator path below are the Implementation 9 build target:

  ```rust
  /// A single step in an IVC computation.
  pub trait StepCircuit<F: PrimeField> {
      /// Number of constraints in this step.
      fn num_constraints(&self) -> usize;

      /// Compute the next state from current state + step input.
      fn synthesize(
          &self,
          cs: &mut ConstraintSystem<F>,
          z: &[F],        // current state
          w: &[F],        // step witness
      ) -> Vec<F>;       // next state
  }

  /// Nova-style folding prover.
  pub struct NovaProver<C: StepCircuit<Fr>> {
      step_circuit: C,
      compression_pk: FullProvingKey,   // Groth16 pk for ~100K compression circuit
  }
  ```

  **IVC prover path:**
  ```rust
  // 1. Fold each step into a running accumulator.
  let mut accumulator = Accumulator::new(public_params);
  for (step_input, step_witness) in steps {
      let step_proof = step_circuit.prove(step_input, step_witness);
      accumulator = nova::fold(&accumulator, &step_proof, &public_params);
  }

  // 2. Compress to a standard Groth16 proof.
  let (proof, public_inputs) = groth16_prover::prove(
      &compression_pk,
      &accumulator.to_witness(),
  );
  ```

  **On-chain verifier (Aiken):** the existing `aiken/groth16` verifier checks the compression SNARK; an additional accumulator check (2–3 group additions) is added to the validator — small enough to fit in Plutus V3.
- **Why it is hard (moved from Implementation 8):**
  1. **Circuit rewrite.** Current Circom circuits are flat R1CS; Nova requires explicit step circuits with state passing (`state_{i+1} = f(step_i, state_i)`). No automatic compiler exists; each circuit must be redesigned.
  2. **Nova overhead.** Each step includes the Nova verifier logic (~10K–30K constraints). For 40K steps this is ~25 % overhead.
  3. **Ecosystem maturity.** Rust Nova crates (`nova-snark`) exist but integration with Circom-generated R1CS is experimental; most Nova work uses hand-written circuits in custom DSLs.
  4. **On-chain verifier extension.** Aiken needs a small accumulator check in addition to the Groth16 pairing check.
- **Design-space position (per the folding survey — Sakwa et al. 2026):** Implementation 9 sits in the **R1CS + elliptic-curve-MSM** quadrant of the folding landscape (the Nova family): the simplest and most mature axis. The survey's other axes are explicitly out of (u) scope and logged as follow-ups:
  - **CCS/Plonkish folding (HyperNova):** generalizes folding beyond fixed-R1CS (custom gates, lookups) — relevant only if a step must mix constraint shapes.
  - **AIR folding (Cairo-style):** CPU/trace-based steps; not our model.
  - **Post-quantum lattice folding (LatticeFold, Lova, Neo, ProtogaLattice):** our Pedersen commitments are DLOG-based and break under Shor; the PQ track replaces EC-MSM with SIS/Ajtai commitments (Lova even runs on power-of-two moduli, no field arithmetic). Long-term only — it would also mean replacing our Groth16 compression (equally non-PQ), and it tracks the existing "FHE/quantum resistance" long-term research item.
  - **CycleFold** (also surveyed) relaxes the full 2-cycle requirement: only the secondary curve's base field must equal the primary scalar field, and only a single scalar multiplication per fold runs on it. It is the closest published route toward in-circuit recursion *near* BLS12-381 — whether a curve over `Fr1` (e.g. Bandersnatch) instantiates it is an open research question, not (u) scope.
  - **Memory-bounded proving** is an open engineering problem in the survey; our per-step O(step) memory design is exactly that target.
  - **ZK layer:** folding itself is not ZK, but our Groth16 compression proof *is* — zero-knowledge for the final proof comes for free, where Nova+Spartan needs a separate ZK add-on.
- **Reference:** Nova (CRYPTO'22, eprint 2021/370), Nova-Scotia (Circom→Nova frontend), Sonobe (arkworks folding), SuperNova (DeepWiki/lurk-beta), arXiv 2408.00243 (ZKP survey, evaluation criteria), **Sakwa, Omala, Li, "A survey of folding-based zero-knowledge proofs", *Information Sciences* 724 (2026) 122698, [DOI 10.1016/j.ins.2025.122698](https://doi.org/10.1016/j.ins.2025.122698)** ([SSRN preprint](https://doi.org/10.2139/ssrn.5293078)).

### (v) Post-quantum path — lattice folding as the PQ counterpart of Implementation 9

- **Why:** every component of the current stack is broken by Shor's algorithm once large-scale quantum computing arrives — Groth16 is pairing-based (BLS12-381), and the Nova folding commitments are Pedersen over G1 (DLOG-based). Both Implementation 8 and Implementation 9 are classically secure only.
- **The structural fact that makes a PQ adaptation feasible:** Nova's folding scheme is *commitment-agnostic* — it works with **any additively-homomorphic commitment** with O(1)-sized commitments; Pedersen (EC-MSM) is just the standard instantiation. Swapping in an **SIS/Ajtai lattice commitment** yields a post-quantum folding scheme with the same IVC structure — this is exactly the LatticeFold / Lova line covered in the folding survey (§4).
- **Candidate instantiations:**

  | Scheme | Assumption | Notes |
  |---|---|---|
  | LatticeFold (Boneh–Chen 2024) | Module-SIS (MSIS) | First lattice folding; sumcheck-heavy → large verifier circuits, bad for per-step recursion overhead |
  | **Lova** (ASIACRYPT 2024) | Unstructured SIS | Power-of-two modulus q=2⁶⁴, no finite-field modular arithmetic at all, simple linear algebra — easiest to add to our Rust repo; decompose-and-fold + exact Euclidean norm proof |
  | ProtogaLattice (2026) | SIS, constant-round | Protogalaxy-style algebraic folding, no sumcheck, ~1 RO call + range proofs; supports general high-degree relations (→ CCS/Plonkish steps) |
  | Neo / SuperNeo / Cyclo | ring-SIS / MSIS | Newer variants; simpler arithmetic, larger proofs |

- **What we would adapt (proposed shape):**
  1. **Folding layer:** replace the Pedersen commitment in the (u) NIFS module with an SIS/Ajtai commitment (Lova-style power-of-two modulus q=2⁶⁴ is the most hardware-friendly; folding math is otherwise unchanged).
  2. **Compression:** our Groth16 compression proof is equally non-PQ, so a PQ chain needs a PQ compression SNARK (sumcheck/GKR-based, hash- or lattice-polynomial-commitment based). The one-pairing verifier becomes a hash/sumcheck verifier.
  3. **On-chain verifier:** the Aiken Groth16 verifier is replaced by a hash-based (STARK-like) verifier — on-chain verification gets heavier, trading gas/cost for PQ security.
  4. **Steps:** lattice folding runs over small moduli/rings, not a 381-bit prime. Our Circom steps must be re-arithmetized for a small field — circom already supports `--prime goldilocks` (a 64-bit prime), and small fields are *faster* (Lova's design exploits this).
- **Near-term reality check:** a chain is only as PQ as its weakest link, so partial PQ (e.g., folding only) buys nothing — the compression SNARK must also go PQ. Realistic posture:
  1. **Document the risk** (this item) and keep the classical stack — quantum-safe migration is a research/roadmap question, not today's blocker (consistent with the existing long-term item "Evaluate FHE-based selective disclosure for quantum resistance").
  2. **Optional hybrid** for high-value use cases: dual proof (Groth16 + lattice IVC) verified as an OR — the survey's "hybrid elliptic-curve–lattice" open problem; doubles cost but hedges the transition.
  3. **If quantum timelines shorten:** switch the IVC layer to a lattice folding (Lova first) + PQ compression + hash-based on-chain verifier, re-arithmetizing the step circuits for a small field.
  4. **STARK/zkVM is the parallel PQ track** — see the industry context in [Implementation 10](#implementation-10-post-quantum-lattice-folding) (§Industry context — CIP-1242 (ZKPoSP) and Zcash's quantum-readiness roadmap): hash-based proofs are the other live PQ family, and a future PQ chain may pick lattice folding *or* a STARK/zkVM backend — both converge on a hash-based on-chain verifier.
- **Status:** ⏳ **Research direction.** Natural PQ counterpart of Implementation 9 (u); neither is committed.
- **Reference:** LatticeFold (Boneh, Chen, eprint 2024/257), Lova (Fenzi et al., ASIACRYPT 2024, eprint 2024/1964), ProtogaLattice (eprint 2026/1317), Sakwa et al. survey §4 (quantum-secure folding), [SSRN 5293078](https://doi.org/10.2139/ssrn.5293078).

## Benchmarks — Nova IVC step-chain (Implementation 8)

Measured with `cargo run --release --bin benchmark_nova -- --circuit <step.r1cs> --steps <witness-dir>` (single core, keys kept in memory, transcript hashing excluded — it is microseconds per step). Each run performs a fresh single-party ceremony, folds every step witness into a proof (with the state-chain check), and verifies every step proof. All numbers are from the smoke-tested step circuits in the [Implementation 8](#implementation-8-nova-ivc--compression-snark) flow.

| Step circuit | Wires | Constraints | Steps | Ceremony | Fold (total) | Fold (per step) | Verify (total) |
|--------------|-------|-------------|-------|----------|--------------|-----------------|----------------|
| `ed25519_verify_nova` | 7,658 | 7,724 | 255 | **1.97 s** | **116.0 s** | **455 ms** | **2.18 s** |
| `cardano_ed25519_ownership_nova` | 7,658 | 7,724 | 255 | **1.51 s** | **107.8 s** | **423 ms** | **2.09 s** |
| `eddsa_jubjub_nova` | 15 | 9 | 254 | **17 ms** | **2.19 s** | **8.6 ms** | **2.48 s** |
| `anonymous_airdrop_nova` | 1,210 | 1,207 | 5 | **0.51 s** | **1.48 s** | **296 ms** | **0.05 s** |

> **What the numbers mean.** The core claim of Implementation 8 holds: a **one-time ceremony of ~2 s** replaces the monolithic Ed25519Verify (~16 min) / CardanoKeyOwnership (~5 min) ceremonies. The cost is moved to the fold: 255 steps × ~0.42–0.46 s ≈ 2 min, with per-step memory (and therefore peak memory) proportional to the 7.7K-constraint step rather than the ~2–4M-constraint whole circuit. Verification is the current weak point, as documented in Implementation 9 (item **(u)**): each step proof costs a constant ~8–10 ms pairing check, so verifying the full chain is O(N) — ~2.1–2.5 s for 255 steps, and the bundle stores all N proofs (no constant-size compression yet).
>
> **Fixed overhead vs. circuit size.** The 9-constraint `eddsa_jubjub_nova` step still costs 8.6 ms to prove and 9.75 ms to verify per step — the entire per-step cost is fixed prover/verifier overhead (FFT-domain setup, witness-polynomial IFFT, MSM, pairing). The 1,207-constraint airdrop step is 296 ms/step for the same reason. Only when step size grows past ~10K constraints does circuit work dominate the fixed cost — which is exactly the regime Nova targets.
>
> **Reproducibility.** The step `.r1cs` and `step_XXXX.wtns` files are produced by the `circom --prime bls12381` + witness-generation steps in the [Implementation 8](#implementation-8-nova-ivc--compression-snark) section; the benchmark measures the same cryptographic phases as `nova ceremony` / `nova fold` / `nova verify` but keeps the keys in memory (no `.pk`/`.vk` disk I/O) and skips the transcript hashing.

Run the benchmark yourself:

```bash
cd nova-prover

# Nova IVC step-chain (Implementation 8) — ceremony/fold/verify for one step circuit
# (requires a compiled step .r1cs + a directory of step_XXXX.wtns witnesses, see the
# Implementation 8 section; --limit N restricts to the first N steps)
cargo run --release --bin benchmark_nova -- --circuit <step.r1cs> --steps <witness-dir>
```

## References

### Folding schemes, recursive arguments, and SNARKs

1. Jens Groth. *On the Size of Pairing-Based Non-interactive Arguments.* EUROCRYPT 2016. IACR ePrint [2016/260](https://eprint.iacr.org/2016/260).
2. Abhiram Kothapalli, Srinath Setty, Ioanna Tzialla. *Nova: Recursive Zero-Knowledge Arguments from Folding Schemes.* CRYPTO 2022. IACR ePrint [2021/370](https://eprint.iacr.org/2021/370).
3. Abhiram Kothapalli, Srinath Setty. *SuperNova: Proving Universal Machine Executions without Universal Circuits.* IACR ePrint [2022/1758](https://eprint.iacr.org/2022/1758).
4. Abhiram Kothapalli, Srinath Setty. *CycleFold: Folding-Scheme-Based Recursive Arguments over a Cycle of Elliptic Curves.* IACR ePrint [2023/1192](https://eprint.iacr.org/2023/1192).
5. Abhiram Kothapalli, Srinath Setty. *HyperNova: Recursive Arguments for Customizable Constraint Systems.* CRYPTO 2024. IACR ePrint [2023/573](https://eprint.iacr.org/2023/573).
6. Dan Boneh, Binyi Chen. *LatticeFold: A Lattice-based Folding Scheme and its Applications to Succinct Proof Systems.* IACR ePrint [2024/257](https://eprint.iacr.org/2024/257).
7. Giacomo Fenzi, Christian Knabenhans, Ngoc Khanh Nguyen, Duc Tu Pham. *Lova: Lattice-Based Folding Scheme from Unstructured Lattices.* ASIACRYPT 2024. IACR ePrint [2024/1964](https://eprint.iacr.org/2024/1964).
8. Wilson Nguyen, Srinath Setty. *Neo: Lattice-based Folding Scheme for CCS over Small Fields and Pay-per-Bit Commitments.* IACR ePrint [2025/294](https://eprint.iacr.org/2025/294).
9. David Balbás, Anca Nitulescu, Maxime Plançon. *ProtogaLattice: Constant-Round Lattice-based Folding for General Polynomial Relations.* IACR ePrint [2026/1317](https://eprint.iacr.org/2026/1317).
10. Cyprian Omukhwaya Sakwa, Anyembe Andrew Omala, Fagen Li. *A Survey of Folding-Based Zero-Knowledge Proofs.* Information Sciences 724 (2026) 122698. DOI [10.1016/j.ins.2025.122698](https://doi.org/10.1016/j.ins.2025.122698); [SSRN 5293078](https://doi.org/10.2139/ssrn.5293078).
11. Ryan Lavin, Xuekai Liu, Hardhik Mohanty, Logan Norman, Giovanni Zaarour, Bhaskar Krishnamachari. *A Survey on the Applications of Zero-Knowledge Proofs.* arXiv [2408.00243](https://arxiv.org/abs/2408.00243) (2024).
12. Sean Bowe, Jack Grigg, Daira Hopwood. *Recursive Proof Composition without a Trusted Setup* (Halo / Halo2). IACR ePrint [2019/1021](https://eprint.iacr.org/2019/1021).
13. Liam Eagen. *Bulletproofs++: Next Generation Confidential Transactions Based on Proofs of Statement and Knowledge.* IACR ePrint [2022/510](https://eprint.iacr.org/2022/510).
14. Vincenzo Botta, Michał Pospieszalski, Emanuele Ragnoli, John Ranvier. *ZKPoSP: Post-Quantum Zero-Knowledge Proofs for Hierarchical Deterministic Wallets.* IACR ePrint [2026/1508](https://eprint.iacr.org/2026/1508); CIP draft in [cardano-foundation/CIPs PR 1242](https://github.com/cardano-foundation/CIPs/pull/1242).

### Software, specifications, and ceremonies

- [Nova (Microsoft Research)](https://github.com/microsoft/Nova) — Rust implementation of the Nova folding scheme.
- [Nova-Scotia](https://github.com/nalinbhardwaj/Nova-Scotia) — middleware compiling Circom circuits to the Nova prover.
- [Sonobe](https://github.com/privacy-scaling-explorations/sonobe) — experimental arkworks-based folding-schemes library (Nova, CycleFold, HyperNova, ProtoGalaxy).
- [Halo2 (Zcash)](https://github.com/zcash/halo2) — PLONKish recursive proof system.
- [arkworks](https://arkworks.rs/) — Rust ecosystem for pairing-based cryptography (R1CS, Groth16, FFT, MSM).
- [RISC Zero zkVM](https://dev.risczero.com/) — STARK proof system over a Rust zkVM; the proving backend used by CIP-1242 (ZKPoSP).
- [Tachyon (Kroma)](https://github.com/kroma-network/tachyon) — modular ZK backend with a Halo2 + FRI polynomial-commitment scheme and GPU acceleration; the Zcash quantum-readiness track.
- [CoinDesk Research, "Building the Zcash Machine: Tachyon and Quantum Readiness"](https://www.coindesk.com/research/building-the-zcash-machine-tachyon-and-quantum-readiness) — Zcash's three-step path to post-quantum security (June 2026).

---

## License

Apache-2.0
