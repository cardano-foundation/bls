# nova-cli

Command-line interface for Nova IVC folding on BLS12-381.

A long computation is split into `N` identical step circuits, each proving
`state_{i+1} = f(step_i, state_i)`. The CLI supports **two paths**:

| | <u>**Recommended — no ceremony, slim proof**</u> | With ceremony (legacy) |
|---|---|---|
| **Path** | `fold --nifs` → `compress --slim` → `verify --slim-proof` | `ceremony` → `fold` → `verify` (or `fold --nifs` → `compress --groth16` → `verify --compression-proof`) |
| **Proof size** | **O(1) — ~1.5 KiB on-chain** | O(N) or O(step) — 47 KiB × N or ~580 KiB |
| **Trusted setup** | **None** for compression | Per-step ceremony (Impl 8) or compression ceremony (Impl 9) |
| **On-chain verify** | **Pairing-free** — native field sumcheck | N pairings (Impl 8) or 1 pairing (Impl 9) |
| **ZK** | **Yes** — witness-hiding | No |

The **recommended path** (Implementation 11) uses transparent NIFS folding + sumcheck
compression + slim proofs. No ceremony, no proving key, no verifying key — only the
step circuit and witnesses are needed.

The core IVC logic lives in `nova-prover`; this crate is the thin CLI wrapper.
Design, benchmarks, and implementation history are in [`nova-prover/README.md`](../../nova-prover/README.md).

---

## Quick start — recommended path (no ceremony)

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

Omit `--slim` to keep the HashPC opening proofs:

```bash
nova compress --circuit step_circuit.r1cs --steps ./step_witnesses/ --out sumcheck.proof.json
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
  compress  Compress a NIFS bundle into a single proof (sumcheck by default, --groth16 for Groth16)
  verify    Verify a folded IVC bundle
  help      Print this message or the help of the given subcommand(s)
```

### `params` — inspect a step circuit

Validates the IVC invariant `n_pub_in == n_pub_out`.

```bash
nova params --circuit step_circuit.r1cs
nova params --circuit step_circuit.r1cs --out step_circuit.desc.json
```

### `ceremony` — trusted setup (legacy path only)

Single-party dev-only ceremony. Produces per-step `.pk` / `.vk`.

```bash
nova ceremony --circuit step_circuit.r1cs --proving-key step.pk --verifying-key step.vk
```

> **Warning:** dev-only. Not needed for the recommended slim path.

### `fold` — fold step witnesses

**Without `--nifs`** (legacy Impl 8): requires `--proving-key`, produces O(N) bundle.

```bash
nova fold --circuit step_circuit.r1cs --proving-key step.pk \
  --steps ./step_witnesses/ --out bundle.ivc.json
```

**With `--nifs`** (recommended): transparent folding, no proving key, O(1) bundle.

```bash
nova fold --nifs --circuit step_circuit.r1cs \
  --steps ./step_witnesses/ --out bundle.ivc.json
```

Add `--opt-parallel` for rayon-parallelized cross-term computation.

### `compress` — compress into one proof

**Default (recommended):** sumcheck compression, no ceremony.

```bash
nova compress --circuit step_circuit.r1cs --steps ./step_witnesses/ --out sumcheck.proof.json
```

**Slim on-chain proof (recommended):** strips HashPC openings (~98% smaller).

```bash
nova compress --slim --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.json
```

**Groth16 compression (legacy Impl 9):** requires `--proving-key` from a compression ceremony.

```bash
nova compress --groth16 --circuit step_circuit.r1cs --steps ./step_witnesses/ \
  --proving-key compression.pk --out compression.proof.json
```

### `verify` — verify a folded bundle

**Slim proof (recommended):**

```bash
nova verify --ivc bundle.ivc.json --slim-proof slim.proof.json
```

**Full sumcheck proof:**

```bash
nova verify --ivc bundle.ivc.json --sumcheck-proof sumcheck.proof.json
```

**Groth16 compression (legacy Impl 9):**

```bash
nova verify --ivc bundle.ivc.json --compression-proof compression.proof.json --compression-vk compression.vk
```

**Step-chain (legacy Impl 8):**

```bash
nova verify --ivc bundle.ivc.json --verifying-key step.vk
```

---

## Complete workflows

### <u>Recommended — slim proof, no ceremony</u>

```bash
# 1. Fold (transparent, no proving key)
nova fold --nifs --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.json

# 2. Compress to slim proof (~1.5 KiB)
nova compress --slim --circuit step_circuit.r1cs --steps ./step_witnesses/ --out slim.proof.json

# 3. Verify (pairing-free, no VK)
nova verify --ivc bundle.ivc.json --slim-proof slim.proof.json
```

### With ceremony — Groth16 compression (legacy)

```bash
# 1. Fold (transparent)
nova fold --nifs --circuit step_circuit.r1cs --steps ./step_witnesses/ --out bundle.ivc.json \
  --compression-r1cs compression.r1cs

# 2. Ceremony for compression circuit (one-time, reusable)
trusted-setup ceremony-dev --sparse --circuit compression.r1cs \
  --proving-key compression.pk --verifying-key compression.vk

# 3. Compress (Groth16)
nova compress --groth16 --circuit step_circuit.r1cs --steps ./step_witnesses/ \
  --proving-key compression.pk --out compression.proof.json

# 4. Verify (one pairing)
nova verify --ivc bundle.ivc.json --compression-proof compression.proof.json --compression-vk compression.vk
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

**Recommended slim path:**

```bash
nova params --circuit cardano_ed25519_ownership_nova.r1cs
nova fold --nifs --circuit cardano_ed25519_ownership_nova.r1cs --steps <witness-dir> --out bundle.ivc.json
nova compress --slim --circuit cardano_ed25519_ownership_nova.r1cs --steps <witness-dir> --out slim.proof.json
nova verify --ivc bundle.ivc.json --slim-proof slim.proof.json
```

**Legacy Groth16 path (for comparison):**

```bash
nova fold --nifs --circuit cardano_ed25519_ownership_nova.r1cs --steps <witness-dir> --out bundle.ivc.json --compression-r1cs compression.r1cs
trusted-setup ceremony-dev --sparse --circuit compression.r1cs --proving-key compression.pk --verifying-key compression.vk
nova compress --groth16 --circuit cardano_ed25519_ownership_nova.r1cs --steps <witness-dir> --proving-key compression.pk --out compression.proof.json
nova verify --ivc bundle.ivc.json --compression-proof compression.proof.json --compression-vk compression.vk
```

---

## License

Apache-2.0
