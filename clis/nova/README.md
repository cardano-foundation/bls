# nova-cli

Command-line interface for the Nova IVC step-chain flow on BLS12-381.

A long computation is decomposed into `N` identical step circuits, each proving `state_{i+1} = f(step_i, state_i)`. This CLI proves every step as a **standalone Groth16 proof** and binds the state chain with a BLAKE2b512 transcript. Each step proof is individually verifiable, and `verify` re-checks the whole chain (pairings + chain invariant + transcript).

The core IVC logic lives in the `nova-prover` crate; this crate only adds the command-line interface on top of it. The Groth16 proof-system core lives in `groth16-prover` / `trusted-setup`.

The design, roadmap (Relaxed-R1CS folding + compression SNARK), and benchmarks are documented in [`nova-prover/README.md`](../../nova-prover/README.md).

---

## Quick reference

Run any command with `--help` for full flag details:

```bash
nova --help
nova params --help
nova ceremony --help
nova fold --help
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

---

## License

Apache-2.0
