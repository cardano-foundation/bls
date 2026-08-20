# nova-cli

Command-line interface for the Nova IVC step-chain flow on BLS12-381.

A long computation is decomposed into `N` identical step circuits, each proving `state_{i+1} = f(step_i, state_i)`. The CLI supports three proof paths:

- **Implementation 8 (step-chain):** prove every step as a **standalone Groth16 proof** and bind the state chain with a BLAKE2b512 transcript. Each step proof is individually verifiable, and `verify` re-checks the whole chain (pairings + chain invariant + transcript). Bundle and verify cost are O(N).
- **Implementation 9 (NIFS):** `nova fold --nifs` folds all step instances into one **Relaxed-R1CS instance** (transparent folding, no per-step proving key), `nova compress --groth16` turns it into a **single Groth16 proof**, and `nova verify --ivc --compression-proof` checks it with **one pairing**. Bundle and verify cost are O(1). Requires a one-time compression ceremony.
- **Implementation 10 (sumcheck):** `nova fold --nifs` + `nova compress` (defaults to sumcheck, no `--groth16` needed) produces a **transparent sumcheck + HashPC proof** — no ceremony, no proving key, **ZK for free**. `nova verify --ivc --sumcheck-proof` checks it pairing-free. Bundle and verify cost are O(1).
- **Slim on-chain proofs:** `nova compress --slim` strips the HashPC opening proofs (~98% smaller). `nova verify --ivc --slim-proof` checks a slim proof using the Aiken verifier on-chain.

The core IVC logic lives in the `nova-prover` crate; this crate only adds the command-line interface on top of it. The Groth16 proof-system core lives in `groth16-prover` / `trusted-setup`.

The design, roadmap (Relaxed-R1CS folding + compression SNARK), and benchmarks are documented in [`nova-prover/README.md`](../../nova-prover/README.md) (Implementation 8 and Implementation 9).

---

## Quick reference

Run any command with `--help` for full flag details:

```bash
nova --help
nova params --help
nova ceremony --help
nova fold --help
nova compress --help
nova verify --help
```

Top-level help output:

```
Nova IVC folding CLI for BLS12-381

Usage: nova <COMMAND>

Commands:
  params    Inspect a step circuit and emit a JSON descriptor
  ceremony  Run a single-party ceremony for a step circuit
  fold      Fold step witnesses into an IVC bundle
  compress  Compress a NIFS bundle into a single proof (sumcheck by default, --groth16 for Groth16)
  verify    Verify a folded IVC bundle
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

---

## Command reference

### `params` — inspect a step circuit

Loads a step circuit (`.r1cs`) and validates the IVC invariant **`n_pub_in == n_pub_out`**: the public-input block of step `i+1` must be the public-output block of step `i` — public inputs *are* the IVC state.

```bash
# Print the descriptor as JSON to stdout
nova params --circuit step_circuit.r1cs

# Write the descriptor to a file
nova params --circuit step_circuit.r1cs --out step_circuit.desc.json
```

Non-step circuits are rejected:

```
$ nova params --circuit cardano_ed25519_ownership.r1cs
Error: not a valid step circuit: n_pub_in (256) != n_pub_out (1) — the public inputs
must be exactly the IVC state and must have the same width as the public outputs so
that state_in[i+1] == state_out[i]
```

### `ceremony` — per-step trusted setup

Single-party (dev-only) ceremony for a step circuit. Produces a per-step proving key (`.pk`) and verifying key (`.vk`) in binary format. The `.pk` contains only curve points (no scalars), so the prover uses pure MSM.

```bash
nova ceremony \
  --circuit step_circuit.r1cs \
  --proving-key step.pk \
  --verifying-key step.vk

# h-query scalar compression (Implementation 7) shrinks the PK
nova ceremony \
  --circuit step_circuit.r1cs \
  --proving-key step_hs.pk \
  --verifying-key step_hs.vk \
  --h-scalar
```

> **Warning:** dev-only. For production multi-party ceremonies use `phase2` in the `trusted-setup` CLI.

### `fold` — fold step witnesses into an IVC bundle

Loads the step circuit, the proving key, and a directory of witness files (`step_0000.wtns`, `step_0001.wtns`, …), then produces a Groth16 proof per step, checking the chain invariant and updating a BLAKE2b512 transcript at every step.

```bash
nova fold \
  --circuit step_circuit.r1cs \
  --proving-key step.pk \
  --steps ./step_witnesses/ \
  --out bundle.ivc.json
```

The output bundle (`.ivc.json`) contains all step proofs, the initial state, and the final transcript hash. If any witness breaks the state chain, `fold` fails naming the exact step.

#### NIFS folding (Implementation 9)

With `--nifs` no proving key is needed — folding is transparent and linear-time. The step instances are folded into a single **Relaxed-R1CS instance** (`U = (x, u, W̄, Ē)`), so the bundle is O(1) regardless of `N`. Optionally emit the compression circuit `.r1cs` with `--compression-r1cs`; feed it to `trusted-setup ceremony-dev --sparse` to derive the compression proving / verifying keys.

```bash
nova fold --nifs \
  --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ \
  --out bundle.ivc.json \
  --compression-r1cs compression.r1cs
# → NIFS bundle written to bundle.ivc.json (N steps → one instance, u = <scalar>)
# → Compression circuit (from n step constraints): 2n constraints, ...
```

The NIFS bundle holds only the O(1) final relaxed instance (no per-step proofs); the step witnesses are still needed by `compress` / `verify` to recover the private final witness and re-check the commitments.

### `compress` — compress a NIFS bundle into one proof

Re-folds the step witnesses deterministically, builds the compression circuit (relaxed-equation check `(AZ)∘(BZ) = u(CZ) + E`) and proves it — producing **one O(1) proof** instead of one proof per step. Defaults to **Implementation 10 (sumcheck)**; use `--groth16` for Implementation 9.

#### Sumcheck compression (Implementation 10, default)

No ceremony needed. The sumcheck protocol + HashPC commitments are transparent (deterministic from the step circuit and NIFS params seed). ZK comes for free.

```bash
# Sumcheck is the default — no flags needed
nova compress \
  --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ \
  --out sumcheck.proof.json
# → Sumcheck compression proof written to sumcheck.proof.json
```

#### Groth16 compression (Implementation 9)

Requires a one-time ceremony for the compression circuit.

```bash
# One-time ceremony for the compression circuit (reusable for any step shape)
trusted-setup ceremony-dev --sparse \
  --circuit compression.r1cs \
  --proving-key compression.pk --verifying-key compression.vk

nova compress --groth16 \
  --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ \
  --proving-key compression.pk \
  --out compression.proof.json
# → Groth16 compression proof written to compression.proof.json
```

#### Slim on-chain proofs (--slim)

Strips the HashPC opening proofs from a sumcheck compression proof, reducing proof size by ~98%. The stripped proof is verified against the NIFS bundle commitments using the Aiken verifier on-chain.

```bash
nova compress --slim \
  --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ \
  --out slim.proof.json
# → Slim sumcheck proof written to slim.proof.json (~5 KiB for 7,724-constraint circuits)
```

The result is consumed by `nova verify` on the NIFS bundle.

### `verify` — check a folded IVC bundle

Re-checks the whole chain from the bundle + verifying key:

```bash
nova verify \
  --ivc bundle.ivc.json \
  --verifying-key step.vk

# → Verified 255 steps: 255 pairings OK, state chain OK, transcript OK
# → Final transcript: <blake2b512 hex>
```

Verification checks (1) every step's Groth16 pairing, (2) the `state_out[i] == state_in[i+1]` chain, and (3) the deterministic transcript. Tampering with any proof, state, or transcript is detected.

#### NIFS bundles (Implementation 9 — Groth16 compression)

For a NIFS bundle compressed with `--groth16`, pass the compression proof and verifying key. Verification is **one Groth16 pairing** plus native `com(W)` / `com(E)` MSM re-commitments and the transcript check:

```bash
nova verify \
  --ivc bundle.ivc.json \
  --compression-proof compression.proof.json \
  --compression-vk compression.vk

# → Verified 254 steps: compression proof OK, commitments OK, state chain OK
# → Final transcript: <blake2b512 hex>
```

#### NIFS bundles (Implementation 10 — sumcheck compression)

For a NIFS bundle compressed with sumcheck (the default), pass the sumcheck proof. Verification is **pairing-free** — sumcheck protocol check + HashPC opening verification + Pedersen commitment cross-check:

```bash
nova verify \
  --ivc bundle.ivc.json \
  --sumcheck-proof sumcheck.proof.json

# → Verified 254 steps: sumcheck compression proof OK, commitments OK, state chain OK
# → Final transcript: <blake2b512 hex>
```

#### Slim on-chain proofs

For a slim proof (from `compress --slim`), pass the NIFS bundle and the slim proof. The slim proof contains the sumcheck transcript and final instance but no HashPC opening proofs — verification uses the Aiken verifier on-chain:

```bash
nova verify \
  --ivc bundle.ivc.json \
  --slim-proof slim.proof.json

# → Verified 255 steps: slim sumcheck proof OK
```

---

## Complete workflow

### CardanoKeyOwnership — Ed25519 step-chain (Implementation 8)

Full walkthrough (including the iterative step-witness generation that makes the chain invariant hold by construction): [`circom/CardanoKeyOwnership/README.md`](../../circom/CardanoKeyOwnership/README.md), Variant B.

```bash
# 1. Compile the step circuit (one-time)
cd circom/CardanoKeyOwnership
circom --prime bls12381 --r1cs --wasm --sym cardano_ed25519_ownership_nova.circom

# 2. Inspect the step circuit
nova params --circuit cardano_ed25519_ownership_nova.r1cs

# 3. Per-step trusted setup (seconds, not minutes)
nova ceremony \
  --circuit cardano_ed25519_ownership_nova.r1cs \
  --proving-key cko255.pk --verifying-key cko255.vk

# 4. Fold the step witnesses into an IVC bundle
nova fold \
  --circuit cardano_ed25519_ownership_nova.r1cs \
  --proving-key cko255.pk \
  --steps <witness-dir> \
  --out cko255_ivc.json

# 5. Verify the whole chain
nova verify --ivc cko255_ivc.json --verifying-key cko255.vk
```

### NIFS — constant-size bundle and verify (Implementation 9)

Same step circuits and step witnesses as the Implementation 8 flow, but folding is transparent (no per-step proving key) and the bundle + verify are O(1). Worked end to end on the `cardano_ed25519_ownership_nova` step circuit (255 steps, 7,724 constraints); the same commands run on any step circuit with `n_pub_in == n_pub_out`.

```bash
# 1. Fold the step witnesses into one Relaxed-R1CS instance (no proving key)
nova fold --nifs \
  --circuit cardano_ed25519_ownership_nova.r1cs \
  --steps <witness-dir> \
  --out cko255_ivc.json \
  --compression-r1cs compression.r1cs

# 2. One-time ceremony for the compression circuit (reusable for any step shape)
trusted-setup ceremony-dev --sparse \
  --circuit compression.r1cs \
  --proving-key compression.pk --verifying-key compression.vk

# 3. Compress the final instance into one O(1) Groth16 proof
nova compress \
  --circuit cardano_ed25519_ownership_nova.r1cs \
  --steps <witness-dir> \
  --proving-key compression.pk \
  --out compression.proof.json

# 4. Verify — one Groth16 pairing + native com(W)/com(E) MSMs + transcript
nova verify \
  --ivc cko255_ivc.json \
  --compression-proof compression.proof.json \
  --compression-vk compression.vk
```

Design, caveats (compression proof reveals the folded `Z`/`E`; the compression circuit is `2·n_constraints`), and benchmarks vs the Implementation 8 step-chain are in [`nova-prover/README.md`](../../nova-prover/README.md).

### Sumcheck — transparent compression, no ceremony (Implementation 10)

Same step circuits and step witnesses as the NIFS flow, but compression is ceremony-free and ZK. Worked end to end on the `cardano_ed25519_ownership_nova` step circuit (255 steps, 7,724 constraints).

```bash
# 1. Fold the step witnesses into one Relaxed-R1CS instance (no proving key)
nova fold --nifs \
  --circuit cardano_ed25519_ownership_nova.r1cs \
  --steps <witness-dir> \
  --out cko255_ivc.json

# 2. Compress with sumcheck (no ceremony — this is the default)
nova compress \
  --circuit cardano_ed25519_ownership_nova.r1cs \
  --steps <witness-dir> \
  --out sumcheck.proof.json

# 3. Verify — pairing-free, no verifying key
nova verify \
  --ivc cko255_ivc.json \
  --sumcheck-proof sumcheck.proof.json
```

### Slim on-chain proofs

Strips HashPC opening proofs from a sumcheck compression proof (~98% smaller) for on-chain Aiken verification:

```bash
# 1. Same NIFS fold
nova fold --nifs \
  --circuit cardano_ed25519_ownership_nova.r1cs \
  --steps <witness-dir> \
  --out cko255_ivc.json

# 2. Compress with --slim
nova compress --slim \
  --circuit cardano_ed25519_ownership_nova.r1cs \
  --steps <witness-dir> \
  --out slim.proof.json

# 3. Verify the slim proof
nova verify \
  --ivc cko255_ivc.json \
  --slim-proof slim.proof.json
```

---

## License

Apache-2.0
