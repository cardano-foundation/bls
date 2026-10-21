# nova-cli

Command-line interface for Nova IVC folding on BLS12-381.

A long computation is split into `N` identical step circuits, each proving
`state_{i+1} = f(step_i, state_i)`. The CLI supports **two paths**:

| | <u>**Paper-faithful Nova (default)**</u> | Transparent alternative |
|---|---|---|
| **Path** | `fold --nifs` → `compress` → `verify --compression-proof` | `fold --nifs` → `compress --slim` → `verify --slim-proof` |
| **Implementation** | **9** — NIFS + Groth16 compression | 11 — NIFS + sumcheck + slim proof |
| **Proof size** | O(step) — ~580 KiB | **O(1) — ~1.5 KiB on-chain** |
| **Trusted setup** | **Compression circuit only** (one-time, reusable) | **None** for compression |
| **On-chain verify** | **1 pairing** | **Pairing-free** — native field sumcheck |
| **ZK** | No | **Yes** — witness-hiding |

The **default path** (Implementation 9) is the construction from the Nova paper:
fold the steps with NIFS, compress the folded instance with a Groth16 proof over
the compression circuit, and check it on-chain with a single pairing.  It needs
one trusted setup for the compression circuit.

The **transparent alternative** (Implementation 11) swaps the Groth16 compression
for a transparent sumcheck argument with slim on-chain proofs.  No ceremony, no
proving key, no verifying key — only the step circuit and witnesses are needed.

The core IVC logic lives in `nova-prover`; this crate is the thin CLI wrapper.
Design, benchmarks, and implementation history are in [`nova-prover/README.md`](../../nova-prover/README.md).

> **The cutting-edge Nova work lives upstream** — in
> [`paweljakubas/nova-slim`](https://github.com/paweljakubas/nova-slim).  This
> CLI is the snapshot that the in-tree Aiken verifiers are built against.

---

## Executive Summary

The `nova` CLI implements **Nova IVC folding** — a recursive proof technique that compresses N step-circuit executions into a single constant-sized proof.

**What you get:**
- `fold --nifs` — Fold N step witnesses into one accumulated instance (NIFS)
- `compress` — Compress to one Groth16 proof (default) or a slim sumcheck proof (`--slim`)
- `verify` — Verify off-chain or via Aiken verifier

**Quick start (default path):**
```bash
cd clis/nova
cargo build --release

# 1. Fold (transparent — no proving key) and emit the compression circuit
./target/release/nova fold --nifs \
  --circuit ../../circom/CardanoKeyOwnership/cardano_ed25519_ownership_nova.r1cs \
  --steps ./step_witnesses/ \
  --out bundle.ivc.json \
  --compression-r1cs compression.r1cs

# 2. One-time trusted setup for the compression circuit
trusted-setup ceremony-dev --sparse --circuit compression.r1cs \
  --proving-key compression.pk --verifying-key compression.vk

# 3. Compress to one Groth16 proof
./target/release/nova compress \
  --circuit ../../circom/CardanoKeyOwnership/cardano_ed25519_ownership_nova.r1cs \
  --steps ./step_witnesses/ \
  --proving-key compression.pk \
  --out compression.proof.json

# 4. Verify — one pairing check
./target/release/nova verify \
  --ivc bundle.ivc.json \
  --compression-proof compression.proof.json \
  --compression-vk compression.vk
# → Verified N steps: compression proof OK, commitments OK, state chain OK
```

**Quick start (transparent, no ceremony):**
```bash
# 1. Fold
./target/release/nova fold --nifs \
  --circuit ../../circom/CardanoKeyOwnership/cardano_ed25519_ownership_nova.r1cs \
  --steps ./step_witnesses/ \
  --out bundle.ivc.json

# 2. Compress to slim proof
./target/release/nova compress --slim \
  --circuit ../../circom/CardanoKeyOwnership/cardano_ed25519_ownership_nova.r1cs \
  --steps ./step_witnesses/ \
  --out slim.proof.cbor

# 3. Verify
./target/release/nova verify \
  --ivc bundle.ivc.cbor \
  --slim-proof slim.proof.cbor
# → Verified N steps: slim sumcheck proof OK
```

**Benchmarks (Intel i7-7500U, 255 Ed25519 steps × 7,724 constraints):**

| Phase | Time | Output size |
|-------|------|-------------|
| Fold 255 steps | ~185 ms/step | 47 KiB × N (growing) |
| Compress (Groth16, default) | one Groth16 proof | ~580 KiB |
| Compress (full sumcheck) | ~7.9 s | ~472 KiB |
| Compress (--slim) | ~8 s | **~1.5 KiB** |
| Verify (slim) | ~0.3 ms | — |

**Comparison with Groth16:**

| Property | Groth16 | Nova IVC (slim) |
|----------|---------|-----------------|
| Proof size | 192 B | ~0.4–2.5 KiB |
| Trusted setup | Per-circuit | **None** |
| On-chain verify | Pairing check | Sumcheck (field ops) |
| Predicate composition | Fixed circuit | Fold step circuits freely |

---

## Quick start — default path (paper-faithful Nova)

```bash
# 1. Inspect the step circuit (must satisfy n_pub_in == n_pub_out)
nova params --circuit step_circuit.r1cs

# 2. Fold step witnesses into a single Relaxed-R1CS instance and emit
#    the compression circuit (2× the step constraints)
nova fold --nifs --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ --out bundle.ivc.json \
  --compression-r1cs compression.r1cs

# 3. One-time trusted setup for the compression circuit (reusable per step shape)
trusted-setup ceremony-dev --sparse --circuit compression.r1cs \
  --proving-key compression.pk --verifying-key compression.vk

# 4. Compress into one Groth16 proof
nova compress --circuit step_circuit.r1cs --steps ./step_witnesses/ \
  --proving-key compression.pk --out compression.proof.json

# 5. Verify — one pairing check + native commitment recomputation
nova verify --ivc bundle.ivc.json \
  --compression-proof compression.proof.json --compression-vk compression.vk
# → Verified N steps: compression proof OK, commitments OK, state chain OK
```

The compression circuit is the Nova paper's "SNARK compresses the folded
instance" step: it checks the relaxed equation `(AZ)∘(BZ) = u(CZ) + E` for the
final instance, so verification on-chain is a single pairing instead of N.

## Quick start — transparent path (no ceremony)

```bash
# 1. Inspect the step circuit (must satisfy n_pub_in == n_pub_out)
nova params --circuit step_circuit.r1cs

# 2. Fold step witnesses into a single Relaxed-R1CS instance
nova fold --nifs --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ --out bundle.ivc.json

# 3. Compress into a slim on-chain proof (~1.5 KiB, no ceremony)
nova compress --slim --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ --out slim.proof.json

# 4. Verify (no verifying key needed)
nova verify --ivc bundle.ivc.json --slim-proof slim.proof.json
# → Verified N steps: slim sumcheck proof OK
```

The `--slim` flag strips HashPC opening proofs from the sumcheck bundle. The
sumcheck protocol itself proves knowledge of a witness consistent with the
committed instance, so soundness is preserved. Opening proofs are only needed
for an off-chain audit trail.

### With parallel optimization

```bash
nova fold --nifs --opt-parallel --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.json
nova compress --slim --opt-parallel --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.json
```

### Full sumcheck proof (with openings, for audit)

Add `--sumcheck` to keep the HashPC opening proofs:

```bash
nova compress --sumcheck --circuit step_circuit.r1cs --steps ./step_witnesses/ --out sumcheck.proof.json
nova verify --ivc bundle.ivc.json --sumcheck-proof sumcheck.proof.json
```

---

## Command reference

Run any command with `--help` for full flag details:

```bash
nova --help
nova params --help
nova ceremony --help
nova fold --help
nova compress --help
nova verify --help
```

Top-level help:

```
Nova IVC folding CLI for BLS12-381

Usage: nova <COMMAND>

Commands:
  params    Inspect a step circuit and emit a JSON descriptor
  ceremony  Run a single-party ceremony for a step circuit
  fold      Fold step witnesses into an IVC bundle
  compress  Compress a NIFS bundle into a single proof (Groth16 by default, --sumcheck / --slim for the transparent paths)
  verify    Verify a folded IVC bundle
  help      Print this message or the help of the given subcommand(s)
```

### `params` — inspect a step circuit

Validates the IVC invariant `n_pub_in == n_pub_out`.

```bash
nova params --circuit step_circuit.r1cs
nova params --circuit step_circuit.r1cs --out step_circuit.desc.json
```

### `ceremony` — per-step trusted setup (legacy Impl 8 path only)

Single-party dev-only ceremony for the **step** circuit.  Produces per-step
`.pk` / `.vk`.

```bash
nova ceremony --circuit step_circuit.r1cs --proving-key step.pk --verifying-key step.vk
```

> **Warning:** dev-only.  The default `compress` path does **not** need it —
> only the compression circuit needs a setup, and that one comes from
> `trusted-setup ceremony-dev --sparse` on the `.r1cs` emitted by
> `fold --nifs --compression-r1cs`.

### `fold` — fold step witnesses

**Without `--nifs`** (legacy Impl 8): requires `--proving-key`, produces O(N) bundle.

```bash
nova fold --circuit step_circuit.r1cs --proving-key step.pk \
  --steps ./step_witnesses/ --out bundle.ivc.json
```

**With `--nifs`**: transparent folding, no proving key, O(1) bundle.

```bash
nova fold --nifs --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ --out bundle.ivc.json
```

Add `--compression-r1cs compression.r1cs` to emit the compression circuit needed
by the default Groth16 compression path.

Add `--opt-parallel` for rayon-parallelized cross-term computation.

### `compress` — compress into one proof

**Default:** Groth16 compression (Implementation 9) — the paper-faithful Nova
path.  Requires the compression proving key.

```bash
nova compress --circuit step_circuit.r1cs --steps ./step_witnesses/ \
  --proving-key compression.pk --out compression.proof.json
```

**Transparent sumcheck proof (Implementation 10):** no ceremony, no proving key.

```bash
nova compress --sumcheck --circuit step_circuit.r1cs --steps ./step_witnesses/ --out sumcheck.proof.json
```

**Slim on-chain proof (Implementation 11):** strips HashPC openings (~98% smaller).

```bash
nova compress --slim --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.json
```

### `verify` — verify a folded bundle

**Groth16 compression proof (default path):**

```bash
nova verify --ivc bundle.ivc.json --compression-proof compression.proof.json --compression-vk compression.vk
```

**Slim proof:**

```bash
nova verify --ivc bundle.ivc.json --slim-proof slim.proof.json
```

**Full sumcheck proof:**

```bash
nova verify --ivc bundle.ivc.json --sumcheck-proof sumcheck.proof.json
```

**Step-chain (legacy Impl 8):**

```bash
nova verify --ivc bundle.ivc.json --verifying-key step.vk
```

---

## Complete workflows

### <u>Default — paper-faithful Nova (Groth16 compression)</u>

```bash
# 1. Fold (transparent, no proving key) and emit the compression circuit
nova fold --nifs --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.json \
  --compression-r1cs compression.r1cs

# 2. Ceremony for compression circuit (one-time, reusable)
trusted-setup ceremony-dev --sparse --circuit compression.r1cs \
  --proving-key compression.pk --verifying-key compression.vk

# 3. Compress (Groth16)
nova compress --circuit step_circuit.r1cs --steps ./step_witnesses/ \
  --proving-key compression.pk --out compression.proof.json

# 4. Verify (one pairing)
nova verify --ivc bundle.ivc.json --compression-proof compression.proof.json --compression-vk compression.vk
```

### Transparent — slim proof, no ceremony

```bash
# 1. Fold (transparent, no proving key)
nova fold --nifs --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.json

# 2. Compress to slim proof (~1.5 KiB)
nova compress --slim --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.json

# 3. Verify (pairing-free, no VK)
nova verify --ivc bundle.ivc.json --slim-proof slim.proof.json
```

### Step-chain — per-step Groth16 (legacy)

```bash
# 1. Ceremony (per step shape)
nova ceremony --circuit step_circuit.r1cs --proving-key step.pk --verifying-key step.vk

# 2. Fold (N Groth16 proofs)
nova fold --circuit step_circuit.r1cs --proving-key step.pk \
  --steps ./step_witnesses/ --out bundle.ivc.json

# 3. Verify (N pairings)
nova verify --ivc bundle.ivc.json --verifying-key step.vk
```

---

## Example: CardanoKeyOwnership circuit

> **Note:** `cardano_ed25519_ownership_nova` is an **example step circuit** — one
> of several circuits the CLI has been tested on. The same commands work for any
> step circuit satisfying `n_pub_in == n_pub_out`.

This circuit decomposes Ed25519 base-point scalar multiplication into 255 steps
of 7,724 constraints each (24 public inputs / 24 public outputs). The full
witness-generation walkthrough is in
[`circom/CardanoKeyOwnership/README.md`](../../circom/CardanoKeyOwnership/README.md).

**Default path (paper-faithful Nova):**

```bash
nova params --circuit cardano_ed25519_ownership_nova.r1cs
nova fold --nifs --circuit cardano_ed25519_ownership_nova.r1cs --steps <witness-dir> --out bundle.ivc.json --compression-r1cs compression.r1cs
trusted-setup ceremony-dev --sparse --circuit compression.r1cs --proving-key compression.pk --verifying-key compression.vk
nova compress --circuit cardano_ed25519_ownership_nova.r1cs --steps <witness-dir> --proving-key compression.pk --out compression.proof.json
nova verify --ivc bundle.ivc.json --compression-proof compression.proof.json --compression-vk compression.vk
```

**Transparent path (no ceremony, for comparison):**

```bash
nova fold --nifs --circuit cardano_ed25519_ownership_nova.r1cs --steps <witness-dir> --out bundle.ivc.json
nova compress --slim --circuit cardano_ed25519_ownership_nova.r1cs --steps <witness-dir> --out slim.proof.json
nova verify --ivc bundle.ivc.json --slim-proof slim.proof.json
```

---

## License

Apache-2.0
