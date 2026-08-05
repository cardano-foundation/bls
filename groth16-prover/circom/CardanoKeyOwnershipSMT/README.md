# CardanoKeyOwnershipSMT — Ed25519 Key Ownership + SMT Membership Proofs

## Idea

The `CardanoKeyOwnership` circuit proves knowledge of a private Ed25519 scalar `sk`
such that the public key `A = [sk]·G` matches a given compressed key. This is a
**single-key** ownership proof — it trusts that the specific public key `A` is
authorized.

In real-world Cardano deployments, authorization is often **set-based**: a wallet
may accept signatures from any key in a set of authorized keys (multi-sig,
recovery keys, key-rotation committees). The SMT (Sparse Merkle Tree) provides a
compact, verifiable commitment to such a set.

**This project combines the two:**

1. **SMT as a key registry** — authorized public key commitments are inserted into
   an SMT. The Merkle root serves as the trust anchor.
2. **Combined proof** — a single Groth16 proof simultaneously demonstrates:
   - The prover knows `sk` such that `A = [sk]·G` (Ed25519 ownership)
   - The public key `A` is a member of the SMT (Merkle path verification)

This enables privacy-preserving key authorization: the proof verifies that the
signer owns *some* key in the authorized set, without revealing *which* key.

### Workflow

```text
1. Derive a real Cardano payment key (cardano-address CLI)

   $ cardano-address recovery-phrase generate --size 15 > phrase.prv
   $ cardano-address key from-recovery-phrase Shelley < phrase.prv > root.xsk
   $ cardano-address key child 1852H/1815H/0H/0/0 < root.xsk > pay.xsk
   $ cardano-address key public --without-chain-code < pay.xsk > pay.vk

2. Generate witness inputs from the key pair

   $ python3 gen_smt_input.py --xsk pay.xsk --vk pay.vk -o input.json --depth 4

   (or, self-contained with no cardano-address dependency:)

   $ python3 test_e2e.py --depth 4 --index 0 --output input.json

3. Generate the witness

   $ snarkjs wc cardano_key_ownership_smt_js/cardano_key_ownership_smt.wasm \
       input.json witness.wtns

4. Single-party dev ceremony (one-time per circuit, ~6 min)

   $ groth16-prover ceremony-dev --sparse --h-scalar \
       --circuit cardano_key_ownership_smt.r1cs \
       --proving-key smt.pk --verifying-key smt.vk

5. Generate the combined proof (Ed25519 + SMT membership)

   $ groth16-prover prove --sparse \
       --circuit cardano_key_ownership_smt.r1cs \
       --witness witness.wtns --proving-key smt.pk --out proof.bin

6. Verify the combined proof

   $ groth16-prover verify --proof proof.bin --public proof.pub \
       --verifying-key smt.vk
   # → Verification result: VALID

   (or, for the Nova step-chain alternative — see Implementation 8 below:)

   $ groth16-prover nova ceremony --circuit cardano_key_ownership_smt_nova.r1cs \
       --proving-key smt_nova.pk --verifying-key smt_nova.vk
   $ python3 gen_smt_nova_steps.py --input input.json \
       --wasm cardano_key_ownership_smt_nova_js/cardano_key_ownership_smt_nova.wasm \
       --dir steps
   $ groth16-prover nova fold --circuit cardano_key_ownership_smt_nova.r1cs \
       --proving-key smt_nova.pk --steps steps --out smt_nova_ivc.json
   $ groth16-prover nova verify --ivc smt_nova_ivc.json --verifying-key smt_nova.vk
   # → Verified 255 steps: 255 pairings OK, state chain OK, transcript OK
```

### End-to-end flow — Implementation 7 (monolithic + h-scalar)

> This is the **single-proof reference path**: one ~1.97M-constraint Groth16
> proof over the full key-ownership + SMT-membership statement, using the
> Implementation 7 sparse prover (`--sparse`) and h-query scalar compression
> (`--h-scalar`). The ceremony is circuit-specific and one-time (~6 min);
> after that, proofs for any key in the SMT take ~40 s each.

#### Step 1: Derive a real Cardano payment key

```bash
cd groth16-prover/circom/CardanoKeyOwnershipSMT

cardano-address recovery-phrase generate --size 15 > phrase.prv
cardano-address key from-recovery-phrase Shelley < phrase.prv > root.xsk
cardano-address key child 1852H/1815H/0H/0/0 < root.xsk > pay.xsk
cardano-address key public --without-chain-code < pay.xsk > pay.vk
```

**Key insight:** In Cardano's BIP32-Ed25519, the payment signing key `pay.xsk`
encodes the Ed25519 scalar in its first 32 bytes (`kL`), already clamped —
exactly the private witness `sk[255]` the circuit needs. `pay.vk` holds the
standard 32-byte compressed public key.

#### Step 2: Generate circuit input from bech32 keys

```bash
python3 gen_smt_input.py --xsk pay.xsk --vk pay.vk -o input.json --depth 4
```

This produces `input.json` with:
- `A[256]` — compressed public key bits (from `pay.vk`)
- `sk[255]` — clamped scalar bits (from `pay.xsk`)
- `PointA[4][3]` — decompressed public key in extended coordinates
- `smt_siblings[4]`, `smt_directions[4]`, `smt_root` — Merkle path and root

#### Step 3: Generate the witness

```bash
snarkjs wc cardano_key_ownership_smt_js/cardano_key_ownership_smt.wasm \
  input.json witness.wtns

# Optional: confirm the witness satisfies the R1CS (~1.5 min)
snarkjs wchk cardano_key_ownership_smt.r1cs witness.wtns
# → WITNESS IS CORRECT (1,970,791 constraints)
```

#### Step 4: Single-party dev ceremony (one-time per circuit, ~6 min)

```bash
groth16-prover ceremony-dev --sparse --h-scalar \
  --circuit cardano_key_ownership_smt.r1cs \
  --proving-key smt.pk --verifying-key smt.vk
```

> ⚠️ `--sparse` is mandatory at this scale (1.97M constraints) to avoid dense
> matrix allocation; `--h-scalar` (Implementation 7) stores a single
> `delta_inv·T(tau)` scalar instead of the full h-query G1 vector. Outputs:
> `smt.pk` ≈ 1.3 GiB (uncompressed), `smt.vk` ≈ 187 MiB. The ceremony is
> circuit-specific — run it once, reuse the keys for every proof.

#### Step 5: Prove

```bash
groth16-prover prove --sparse \
  --circuit cardano_key_ownership_smt.r1cs \
  --witness witness.wtns --proving-key smt.pk --out proof.bin
# → Proof generation (sparse) took ~32 s
```

#### Step 6: Verify

```bash
groth16-prover verify --proof proof.bin --public proof.pub \
  --verifying-key smt.vk
# → Verification result: VALID
```

#### Step 7 (optional): Export the verification key for on-chain use

```bash
groth16-prover export-vk --verifying-key smt.vk --out smt_vk.ak
```

> The monolithic path is the reference single-proof flow. The
> `cardano_key_ownership_smt_nova.circom` step-chain (Implementation 8) folds
> the scalar multiplication into 255 small steps so the ceremony drops to
> ~2.8 s; the step-chain flow is documented below, and the two flows are
> benchmarked in the [Benchmarks](#benchmarks--pre-nova-vs-nova) section.

### End-to-end flow — Implementation 8 (Nova step-chain)

[`cardano_key_ownership_smt_nova.circom`](cardano_key_ownership_smt_nova.circom)
decomposes the scalar-multiplication part of the ownership statement into
**255 identical steps**, each one `BitElementMulAny` on extended Edwards
coordinates `[4][3]` (each coordinate as 3 limbs of base 2^85):

- state `(dblIn[4][3], addIn[4][3])` — 24 public inputs / 24 public outputs,
  1 private input `sel`.
- per step: `dblOut = 2·dblIn`, `addOut = addIn + sel·dblOut`
  (`sel` = scalar bit, LSB-first).
- after 255 steps: `addOut = 2·[sk]·G`; the final check `addOut == 2·PointA`
  is done by the application *after* the fold (the accumulator is only
  complete after all 255 bits). The SMT membership part stays in the
  monolithic circuit — the fold proves key ownership only.
- sizes: 7658 wires, 7724 constraints per step (vs ~1.97M monolithic). The
  ceremony is reusable for **any** run of this step shape.

**1. Build the CLI**

```bash
cargo build --release --manifest-path ../../cli/Cargo.toml
# binary: ../../cli/target/release/groth16-prover (used as `groth16-prover` below)
```

**2. Compile the step circuit** (once; BLS12-381 field, `circomlib` include path)

```bash
circom --prime bls12381 -l ../Ed25519Verify/node_modules/circomlib/circuits \
  cardano_key_ownership_smt_nova.circom --r1cs --wasm --sym
```

**3. Inspect the step circuit** (must report `n_pub_in == n_pub_out == 24`)

```bash
groth16-prover nova params --circuit cardano_key_ownership_smt_nova.r1cs
```

**4. One ceremony for the step circuit** (reusable for *any* run of the same step shape)

```bash
groth16-prover nova ceremony --circuit cardano_key_ownership_smt_nova.r1cs \
  --proving-key smt_nova.pk --verifying-key smt_nova.vk
```

**5. Generate the 255 step witnesses** `step_0000.wtns … step_0254.wtns` in
one directory. The chain invariant is enforced by construction:

```
dblIn := extended(G)          # circuit base point (same constants as the monolithic circuit)
addIn := extended(O)          # identity
for i in 0..254:
    inputs = (dblIn, addIn, sel := (sk >> i) & 1)   # LSB-first
    run step wasm → full witness step_%04d.wtns
    read outputs (dblOut, addOut) → next (dblIn, addIn)
```

The `sel` bits come from the same clamped scalar as the Implementation 7
flow (`sk[255]` in the monolithic `input.json`). A helper exists:

```bash
python3 gen_smt_nova_steps.py \
  --input input.json \
  --wasm cardano_key_ownership_smt_nova_js/cardano_key_ownership_smt_nova.wasm \
  --dir steps
```

It runs each step through the step circuit's wasm, feeds the outputs
forward, sanity-checks every step against a pure-Python model, and asserts
`addOut == 2·PointA` at the end. (~2.5 min for 255 steps.)

**6. Fold** — proves each step, checks the state chain, accumulates the
transcript (~3 min for 255 × 7.7K-constraint steps)

```bash
groth16-prover nova fold --circuit cardano_key_ownership_smt_nova.r1cs \
  --proving-key smt_nova.pk --steps steps --out smt_nova_ivc.json
```

**7. Verify** — re-checks every Groth16 pairing, the state chain, and the
transcript

```bash
groth16-prover nova verify --ivc smt_nova_ivc.json \
  --verifying-key smt_nova.vk
# → Verified 255 steps: 255 pairings OK, state chain OK, transcript OK
```

**8. Application-level final check** (outside the fold)

```bash
# final addOut (from step_0254.wtns) must equal 2·PointA projectively
python3 - <<'EOF'
from gen_smt_nova_steps import read_wtns, limbs_to_int, ext_add, projective_eq
n8, w = read_wtns("steps/step_0254.wtns")
add_out = tuple(limbs_to_int([w[13 + c*3 + l] for l in range(3)]) for c in range(4))
import json; d = json.load(open("input.json"))
point_a = tuple(limbs_to_int([int(v) for v in limb]) for limb in d["PointA"])
assert projective_eq(add_out, ext_add(point_a, point_a))
print("addOut == 2*PointA: OK")
EOF
```

> **Note:** `nova` verification is still **O(N)** — it re-checks every step
> proof. The constant-size compression SNARK (one pairing, O(1) verify) is
> [Implementation 9](../../README.md#pending) — not yet built.

### Benchmarks — pre-Nova vs Nova

Measured on the same machine (4 × 31 GB) with the `groth16-prover` release
binary, `snarkjs` for witness generation, one shared key, single runs.

| Phase | Pre-Nova (monolithic) | Nova (step-chain) |
|---|---|---|
| circuit | 1,971,079 constraints | 255 × 7,724 constraints |
| key + circuit input | 0.3 s | (shared) |
| witness generation | 9.4 s | 255 steps: 125.9 s |
| ceremony (one-time, reusable) | 491.3 s | 2.8 s |
| prove / fold | 70.8 s | 164.8 s |
| verify | 1.2 s | 3.3 s |
| **e2e, first run (incl. ceremony)** | **573 s** | **297 s** |
| **e2e, steady (ceremony amortized)** | **82 s** | **294 s** |
| proving key | 1.2 GB | 5.0 MB |
| verifying key | 178 MB | 719 KB |

Reading the table:

- **First run** (fresh key + ceremony): Nova is **~48 % faster** — the
  ~8 min monolithic ceremony dwarfs everything, while the Nova ceremony is
  ~3 s. The proving-key footprint drops from 1.2 GB to 5 MB.
- **Steady state** (ceremony reused, per additional key): pre-Nova is
  **~3.5× faster** (82 s vs 294 s). Nova re-derives 255 step witnesses and
  folds them per key; the monolithic prover only redoes one witness + one
  proof. (The step chain is inherently sequential — each step feeds the next.)
- Both flows prove the **same** key-ownership statement; the SMT-membership
  half of the statement is only proven by the monolithic circuit (the Nova
  fold covers the scalar multiplication only, with the `addOut == 2·PointA`
  equality checked outside the fold).

Reproduce: `python3 ../benchmarks_compare.py --family smt --workdir <dir>`
(see `../benchmarks_compare.py` header for the full CLI).

## Design

### Circuit Structure

The combined circuit `CardanoKeyOwnershipSMT` has two main components:

#### 1. Ed25519 Scalar Multiplication (from `cardano_ed25519_ownership.circom`)

Proves `A = [sk]·G` on Curve25519:
- Private input: `sk[255]` (scalar bits)
- Public input: `A[256]` (compressed public key bits)
- Auxiliary input: `PointA[4][3]` (decompressed extended coordinates)
- Uses `ScalarMul`, `PointCompress`, and `PointEqual` templates from `Ed25519Verify`

#### 2. SMT Merkle Path Verification (from `smt.rs` / MiMC hashing)

Proves `A` is in the SMT:
- Private input: `smt_siblings[]` (Merkle path siblings), `smt_directions[]` (left/right bits)
- Public input: `smt_root` (the SMT root)
- The leaf is derived in-circuit via `MultiMimc7(6, 91)` over the decompressed `PointA`
- Uses MiMC(x^7) hashing for the path computation
- Verifies that `hash(leaf, siblings, directions) == smt_root`

#### 3. Bridge: Key Commitment

The Ed25519 public key `A` (256 bits) is committed into the SMT. The commitment
scheme must be consistent between:
- **Insertion**: `gen_smt_input.py` / `test_e2e.py` compute the leaf commitment
- **Verification**: The circuit must compute the same commitment from `PointA`

The implemented bridge hashes the **full decompressed coordinates** of `A`:

```
leaf = MultiMiMC7([x0, x1, x2, y0, y1, y2], k=0)
```

where `x_i`/`y_i` are the base-2^85 chunks of the X and Y coordinates of the
Ed25519 public key point. The circuit computes the same `MultiMimc7(6, 91)`
over its `PointA[2][3]` input, then walks the Merkle path to `smt_root`.

The SMT uses MiMC(x⁷) over the **BLS12-381 scalar field** (`0x73eda7...0001`,
the field circom targets with `--prime bls12381`). Empty leaves default to `0`
and hash up as `mimc2(default, default)`, matching the padding scheme of
`SparseMerkleTree` in `groth16-prover/src/sparse_merkle_tree.rs`.

> Note: the Rust `groth16-prover smt` CLI (`insert`/`export`) targets the
> separate `Privacy` spend circuit, not this one. Its exports produce
> `digest/nullifier/nonce/siblings/directions`, which differ from the
> `CardanoKeyOwnershipSMT` input format.

### Input/Output Specification

#### Public Inputs
- `A[256]` — compressed Ed25519 public key bits
- `smt_root` — SMT root (field element)

#### Private Inputs
- `sk[255]` — Ed25519 scalar bits
- `PointA[4][3]` — decompressed public key in extended coordinates
- `smt_siblings[]` — Merkle path sibling field elements
- `smt_directions[]` — Merkle path direction bits (0=leaf on left, 1=leaf on right)

### File Layout

```text
CardanoKeyOwnershipSMT/
├── README.md                    # This file
├── cardano_key_ownership_smt.circom   # Combined circuit (monolithic)
├── cardano_key_ownership_smt.r1cs       # Compiled R1CS
├── cardano_key_ownership_smt.wasm       # Witness generator
├── cardano_key_ownership_smt_js/        # JS witness gen directory
├── cardano_key_ownership_smt_nova.circom # Nova step circuit (scalar mul only)
├── cardano_key_ownership_smt_nova.r1cs   # Compiled step R1CS
├── gen_smt_input.py                     # Input generator (cardano-address keys)
├── gen_smt_nova_steps.py                # Nova step-witness generator (255 steps)
├── test_e2e.py                          # Self-contained e2e input generator
├── test_smt_simple.py                   # Fixed-seed simple input generator
├── test_smt.sh                          # Input + witness + R1CS check
├── demo.sh                              # End-to-end demo
└── benchmarks.py                        # Witness/proof/verify timings
```

### Dependencies

- `circom` compiler (≥ 2.0.0) for compiling `cardano_key_ownership_smt.circom`
- `snarkjs` for witness generation
- `groth16-prover` CLI for ceremony, proving, and verification (incl. `nova`)
- `cardano-address` CLI for real-world key derivation (optional)
- `pynacl` for the self-contained `test_e2e.py` key generation

### MiMC Hashing in the Circuit

The SMT uses MiMC(x^7) over the BLS12-381 **scalar field** as its hash
function. The circuit and the Python generators must use the same round
constants (see `groth16-prover/src/mimc.rs`, `circom/Privacy/mimc.circom`,
and `ROUND_CONSTANTS` in `gen_smt_input.py`).
- 91 rounds for 128-bit security
- `MultiMimc7(6, 91)` commits the public key coordinates to the leaf

### Security Considerations

1. **Trust anchor**: The SMT root is the trust anchor. Compromise of the root
   compromises all keys in the set.
2. **Key rotation**: To add/remove keys, rebuild the SMT and update the root.
   Old proofs remain valid for the old root.
3. **Privacy**: The SMT stores only the MiMC commitment of the key (not the raw
   key), so the proof hides which key in the set is used — but the public key
   `A` is still visible on-chain. For full privacy, consider using a Pedersen
   commitment instead of MiMC.
4. **Circuit size**: The combined circuit is larger than either component alone.
   The `nova` IVC folding approach (Implementation 8) splits the scalar
   multiplication into 255 small steps, dropping the ceremony from ~6 min to
   ~2.5 s and the proof from one 1.97M-constraint proof to 255 × 7.7K-constraint
   proofs — at the cost of O(N) verification. The SMT membership part remains
   in the monolithic circuit.

## Comparison with Existing Approaches

| Feature | CardanoKeyOwnership | CardanoKeyOwnershipSMT |
|---------|---------------------|------------------------|
| Proves key ownership | ✓ | ✓ |
| Proves set membership | ✗ | ✓ |
| Privacy (which key) | ✗ (key is public) | ✓ (with Hash approach) |
| Trust model | Single key | SMT root = set of keys |
| Circuit size | Smaller | Larger (SMT path included) |
| SMT CLI integration | ✗ | ✓ |
