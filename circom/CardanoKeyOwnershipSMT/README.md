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

The **root — not the individual keys — is what the verifier must trust and
store.** The proof shows the signer owns a public key `A` and that `A` is
authorized by the root, without the verifier ever seeing the key list. (Note: `A`
is a public input of the circuit, so this hides *how* a key is authorized, not
*which* key — see [Drawbacks](#drawbacks).)

### Why not just use `CardanoKeyOwnership`?

`CardanoKeyOwnership` answers one question: *"do you own this specific key `A`?"*.
It does **not** answer *"is `A` authorized?"* — that is a policy decision left to
the verifier. With the plain circuit the verifier must know the authorized keys
itself: it has to store the list (or check every key against on-chain state), and
the key list is exposed to it. For `N` authorized keys that is `O(N)` state and
`O(N)` work per check.

The SMT version moves authorization from **a list of keys** to **a single root**:

- **Constant-size trust anchor.** The verifier stores one field element (the
  root) no matter how many keys are authorized. On-chain state stays fixed as the
  set grows to thousands or millions of keys.
- **Set-based authorization in one proof.** One circuit, one proof shape — "the
  signer owns a key in the set" — regardless of `N`. The natural fit for
  multi-sig, recovery keys, and key-rotation committees.
- **Keys are committed, not stored.** The tree holds only one-way MiMC
  commitments of the public keys, never the raw keys. The authorized key list can
  live off-chain (a registry); the verifier never sees or stores it.
- **Rotation and revocation are root updates.** Rebuild the tree without the key
  and publish a new root. Old proofs still verify against the old root.

### Drawbacks

- **An extra trust anchor.** The root becomes the single point of authorization:
  whoever can publish a root defines the authorized set. In the plain circuit
  each key authenticates itself and there is no such party. The root must be
  maintained by a trusted registry and its publication secured.
- **Slightly larger circuit.** The SMT membership adds `depth` selective-switch +
  MiMC2 constraints: here 1,971,079 vs 1,967,405 constraints (~0.2 % more at
  depth 4). The cost grows with depth and hash rounds.
- **The prover needs the registry.** To prove membership the prover must know the
  current root and fetch its Merkle path from the registry — off-chain
  infrastructure the plain flow does not need.
- **Membership is snapshot-bound.** A proof is only valid for the specific root it
  was generated against. When the set changes, proofs must be re-issued against
  the new root.
- **Privacy is partial.** `A` is a **public input** (`main { public [A, smt_root] }`);
  only `sk`, `PointA`, and the path (siblings/directions) are private. The
  verifier sees exactly which public key is being proven; the proof hides how the
  key is authorized (leaf index / path), not which key it is. True key-hiding
  would require a design that does not publish `A`.

### What happens with the keys after the SMT is used?

1. **Key derivation is unchanged.** You still hold a normal Cardano key pair
   (`pay.xsk` / `pay.vk`, i.e. `sk` and `A`). The SMT does not replace keys or
   change how they are generated.
2. **The registry inserts a commitment, not the key.** The leaf is
   `leaf = MultiMiMC7(PointA)` — a one-way hash of the decompressed public key.
   The raw public key is never written into the tree. The registry keeps the
   `leaf ↔ public key` mapping and the tree structure off-chain so a prover can
   later be handed the path for its own key.
3. **The verifier stores only the root.** The trust anchor (on-chain, or in the
   checking application) is the single Merkle root. Authorizing a signer means
   checking its proof against this one value — no key list is stored or shipped.
4. **Set changes are root updates.** Add a key: compute its leaf, insert it,
   publish the new root. Revoke a key: rebuild the tree without its leaf, publish
   the new root. Nothing else about the proof machinery changes.
5. **Signing.** The prover fetches its Merkle path from the registry, computes
   the witness, and produces a proof with public inputs `(A, smt_root)`. The
   verifier checks ownership *and* membership against the single root in one
   proof.

**Why not just use the keys directly?** Because that forces the verifier to know,
store, and check against the whole key list — and to receive the keys in the
first place. With the SMT the authorized set is committed: the verifier needs only
the root, and the keys never have to be revealed to it.

### Workflow

```text
1. Derive a real Cardano payment key (cardano-address CLI)

   $ cardano-address recovery-phrase generate --size 15 > phrase.prv
   $ cardano-address key from-recovery-phrase Shelley < phrase.prv > root.xsk
   $ cardano-address key child 1852H/1815H/0H/0/0 < root.xsk > pay.xsk
   $ cardano-address key public --without-chain-code < pay.xsk > pay.vk

2. Generate witness inputs from the key pair

   $ ./gen_input.sh --xsk pay.xsk --vk pay.vk --depth 4 --output input.json

   (or, self-contained with a fixed deterministic key, no cardano-address
   or bech32 dependency:)

   $ ./gen_input.sh --fixed --depth 4 --index 0 --output input.json --smt-cli smt

   All the crypto — Ed25519 key decompression and base-2^85 chunking, the
   MiMC leaf commitment, the SMT insert/path, and the full circuit-input
   assembly — is done by the standalone `smt` CLI (`smt key`, `smt leaf`,
   `smt insert`, `smt cardano-input`). `gen_input.sh` only chooses the key
   source (fixed test key, or `bech32` decoding of real `pay.xsk`/`pay.vk`)
   and drives the CLI. See [CLI vs shell/Python](#cli-vs-shellpython) below.
   Use `--smt-cli <path>` to point at a binary not on `PATH`, e.g.
   `clis/smt/target/release/smt`.

3. Generate the witness

   $ snarkjs wc cardano_key_ownership_smt_js/cardano_key_ownership_smt.wasm \
       input.json witness.wtns

4. Single-party dev ceremony (one-time per circuit, ~6 min)

   $ ../../clis/trusted-setup/target/release/trusted-setup ceremony-dev --sparse --h-scalar \
       --circuit cardano_key_ownership_smt.r1cs \
       --proving-key smt.pk --verifying-key smt.vk

5. Generate the combined proof (Ed25519 + SMT membership)

   $ ../../clis/groth16/target/release/groth16 prove --sparse \
       --circuit cardano_key_ownership_smt.r1cs \
       --witness witness.wtns --proving-key smt.pk --out proof.bin

6. Verify the combined proof

   $ ../../clis/groth16/target/release/groth16 verify --proof proof.bin --public proof.pub \
       --verifying-key smt.vk
   # → Verification result: VALID

   (or, for the Nova step-chain alternative — see Implementation 8 below:)

   $ ../../clis/groth16/target/release/groth16 nova ceremony --circuit cardano_key_ownership_smt_nova.r1cs \
       --proving-key smt_nova.pk --verifying-key smt_nova.vk
   $ python3 gen_smt_nova_steps.py --input input.json \
       --wasm cardano_key_ownership_smt_nova_js/cardano_key_ownership_smt_nova.wasm \
       --dir steps
   $ ../../clis/groth16/target/release/groth16 nova fold --circuit cardano_key_ownership_smt_nova.r1cs \
       --proving-key smt_nova.pk --steps steps --out smt_nova_ivc.json
   $ ../../clis/groth16/target/release/groth16 nova verify --ivc smt_nova_ivc.json --verifying-key smt_nova.vk
   # → Verified 255 steps: 255 pairings OK, state chain OK, transcript OK

   (or, for the transparent sumcheck alternative — see Implementation 10 below:)

   $ ../../clis/nova/target/release/nova fold --nifs \
       --circuit cardano_key_ownership_smt_nova.r1cs \
       --steps steps --out smt_ivc.json
   $ ../../clis/nova/target/release/nova compress --sumcheck \
       --circuit cardano_key_ownership_smt_nova.r1cs \
       --steps steps --out smt_sumcheck_proof.json
   $ ../../clis/nova/target/release/nova verify \
       --ivc smt_ivc.json --sumcheck-proof smt_sumcheck_proof.json
   # → Verified 255 steps: sumcheck compression proof OK, commitments OK, state chain OK
```

### End-to-end flow — Implementation 7 (monolithic + h-scalar)

> This is the **single-proof reference path**: one ~1.97M-constraint Groth16
> proof over the full key-ownership + SMT-membership statement, using the
> Implementation 7 sparse prover (`--sparse`) and h-query scalar compression
> (`--h-scalar`). The ceremony is circuit-specific and one-time (~6 min);
> after that, proofs for any key in the SMT take ~40 s each.

#### Step 1: Derive a real Cardano payment key

```bash
cd circom/CardanoKeyOwnershipSMT

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
./gen_input.sh --xsk pay.xsk --vk pay.vk --depth 4 --output input.json
```

The SMT part of the tree is built with the **standalone `smt` CLI**
(`clis/smt`) — this is the primary, supported path, and now the *only* path.
The **MiMC leaf commitment** is computed by `smt key` (which decompresses the
Ed25519 public key, splits it into the six base-2^85 limbs, and hashes them
exactly as the circuit does). `gen_input.sh` runs these commands under the hood:

```bash
smt key --vk <pk-hex> --xsk <scalar-hex> --json        # PointA, A, sk, leaf
smt insert --depth 4 --items <leaf> --index 0 --state smt.json
smt cardano-input --state smt.json --key key.json --out input.json
```

> **There is no in-Python crypto fallback.** The old `multi_mimc7` /
> `build_merkle_tree` / `decompress` implementations were removed. If the
> `smt` binary is missing, `gen_input.sh` fails with a hard error
> and instructions to build it — it never silently falls back to Python math.
> (`gen_smt_input.py` remains as a Python-based orchestrator for the
> benchmark harness `benchmarks_compare.py`.)

Use `--smt-cli <path>` to point at a binary that is not on `PATH`, e.g.
`--smt-cli clis/smt/target/release/smt`.

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
../../clis/trusted-setup/target/release/trusted-setup ceremony-dev --sparse --h-scalar \
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
../../clis/groth16/target/release/groth16 prove --sparse \
  --circuit cardano_key_ownership_smt.r1cs \
  --witness witness.wtns --proving-key smt.pk --out proof.bin
# → Proof generation (sparse) took ~32 s
```

#### Step 6: Verify

```bash
../../clis/groth16/target/release/groth16 verify --proof proof.bin --public proof.pub \
  --verifying-key smt.vk
# → Verification result: VALID
```

#### Step 7 (optional): Export the verification key for on-chain use

```bash
../../clis/groth16/target/release/groth16 export-vk --verifying-key smt.vk --out smt_vk.ak
```

> The monolithic path is the reference single-proof flow. The
> `cardano_key_ownership_smt_nova.circom` step-chain (Implementation 8) folds
> the scalar multiplication into 255 small steps so the ceremony drops to
> ~2.9 s; the step-chain flow is documented below, and the two flows are
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
cargo build --release --manifest-path ../../clis/groth16/Cargo.toml
# binary: ../../clis/groth16/target/release/groth16 (used as `groth16` below)
cargo build --release --manifest-path ../../clis/trusted-setup/Cargo.toml
# binary: ../../clis/trusted-setup/target/release/trusted-setup (used for the ceremony)
```

**2. Compile the step circuit** (once; BLS12-381 field, `circomlib` include path)

```bash
circom --prime bls12381 -l ../Ed25519Verify/node_modules/circomlib/circuits \
  cardano_key_ownership_smt_nova.circom --r1cs --wasm --sym
```

**3. Inspect the step circuit** (must report `n_pub_in == n_pub_out == 24`)

```bash
../../clis/groth16/target/release/groth16 nova params --circuit cardano_key_ownership_smt_nova.r1cs
```

**4. One ceremony for the step circuit** (reusable for *any* run of the same step shape)

```bash
../../clis/groth16/target/release/groth16 nova ceremony --circuit cardano_key_ownership_smt_nova.r1cs \
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
../../clis/groth16/target/release/groth16 nova fold --circuit cardano_key_ownership_smt_nova.r1cs \
  --proving-key smt_nova.pk --steps steps --out smt_nova_ivc.json
```

**7. Verify** — re-checks every Groth16 pairing, the state chain, and the
transcript

```bash
../../clis/groth16/target/release/groth16 nova verify --ivc smt_nova_ivc.json \
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

> **Note:** `nova` verification here is still **O(N)** — it re-checks every step
> proof. The O(1)-verify path is shipped as [Implementation 9](../../nova-prover/README.md#implementation-9-relaxed-r1cs-folding--single-compression-snark): `nova fold --nifs` → `trusted-setup ceremony-dev` on the emitted compression circuit → `nova compress` → `nova verify --compression-proof` — see the [Implementation 9 e2e flow](../../nova-prover/README.md#e2e-flow--implementation-9-nifs). For a **transparent** O(1)-verify path with no ceremony, see [Implementation 10](../../nova-prover/README.md#implementation-10-constant-size-nova-proofs): `nova fold --nifs` → `nova compress --sumcheck` → `nova verify --sumcheck-proof` — no proving or verifying key needed for compression. The step circuit here is byte-identical to `cardano_ed25519_ownership_nova` (7,724 constraints), so the Impl 9/10 numbers measured for it apply; the worked SMT e2e and full tradeoffs are in the [Impl 8 vs Impl 9 comparison](#end-to-end-comparison--implementation-8-step-chain-vs-implementation-9-nifs) below.

## CLI vs shell/Python

All cryptographic and Merkle-tree work for the circuit input lives in the
standalone `smt` CLI (`clis/smt`); the shell/Python scripts are pure orchestration.
This guarantees the input generation uses exactly the same field arithmetic,
round constants, and padding scheme as the circuit itself.

| Step | Where | Commands / functions |
|------|-------|----------------------|
| Key generation (random seeds) | Python | PyNaCl `SigningKey` (test-only, `test_e2e.py`) |
| bech32 key-file decoding (`pay.xsk`/`pay.vk`) | external `bech32` CLI | `bech32` decode (invoked by `gen_input.sh --xsk/--vk` and `gen_smt_input.py`) |
| Ed25519 point decompression (X, Y, Z, T) | Rust CLI | `smt key` → `clis/smt/src/ed25519.rs` `decompress_point` |
| base-2^85 limb chunking of `PointA` | Rust CLI | `smt key` → `to_chunks` |
| MiMC leaf commitment `MultiMiMC7(6,91)` | Rust CLI | `smt key` / `smt leaf` → `clis/smt/src/mimc.rs` |
| `A[256]` / `sk[255]` bit decomposition | Rust CLI | `smt key` → `bits_le`, `clamp_scalar` |
| SMT insert / root / Merkle path | Rust CLI | `smt insert`, `smt digest`, `smt path`, `smt verify` |
| Full circuit-input assembly | Rust CLI | `smt cardano-input` → `{A, sk, PointA, smt_root, smt_siblings, smt_directions}` |
| Witness generation + proof + verify | Rust CLI / snarkjs | `snarkjs wc`/`wchk`, `../../clis/groth16/target/release/groth16 prove`/`verify` |
| Orchestration of `test_smt.sh` / `demo.sh` | shell | `gen_input.sh` (no Python) |
| Orchestration for the benchmark harness | Python | `gen_smt_input.py` (called by `benchmarks_compare.py`) |

The CLI is built with:

```bash
cargo build --release --manifest-path ../../clis/smt/Cargo.toml
# binary: ../../clis/smt/target/release/smt
```

If the CLI (or `bech32`, for the real-key mode) is missing, the scripts stop
with a clear error — there is no Python crypto fallback.

### Benchmarks — pre-Nova vs Nova

Measured on the same machine (4 × 31 GB) with the `groth16` release
binary, `snarkjs` for witness generation, one shared key, single runs.

| Phase | Pre-Nova (monolithic) | Nova (step-chain) |
|---|---|---|
| circuit | 1,971,079 constraints | 255 × 7,724 constraints |
| key + circuit input | 0.3 s | (shared) |
| witness generation | 9.4 s | 255 steps: 125.9 s |
| ceremony (one-time, reusable) | 491.3 s | 2.9 s |
| prove / fold | 70.8 s | 170.9 s |
| verify | 1.2 s | 3.2 s |
| **e2e, first run (incl. ceremony)** | **573 s** | **300 s** |
| **e2e, steady (ceremony amortized)** | **82 s** | **297 s** |
| proving key | 1.2 GB | 5.0 MB |
| verifying key | 178 MB | 719 KB |

Reading the table:

- **First run** (fresh key + ceremony): Nova is **~48 % faster** — the
  ~8 min monolithic ceremony dwarfs everything, while the Nova ceremony is
  ~3 s. The proving-key footprint drops from 1.2 GB to 5 MB.
- **Steady state** (ceremony reused, per additional key): pre-Nova is
  **~3.6× faster** (82 s vs 297 s). Nova re-derives 255 step witnesses and
  folds them per key; the monolithic prover only redoes one witness + one
  proof. (The step chain is inherently sequential — each step feeds the next.)
- Both flows prove the **same** key-ownership statement; the SMT-membership
  half of the statement is only proven by the monolithic circuit (the Nova
  fold covers the scalar multiplication only, with the `addOut == 2·PointA`
  equality checked outside the fold).

Reproduce: `python3 ../benchmarks_compare.py --family smt --workdir <dir>`
(see `../benchmarks_compare.py` header for the full CLI).

### End-to-end comparison — Implementation 8 (step-chain) vs Implementation 9 (NIFS)

Measured on the **same machine / same 255 step witnesses** (full-size state
values): Impl 8 from `benchmark_nova`, Impl 9 via the real CLI e2e (`nova
fold --nifs` → `trusted-setup ceremony-dev` → `nova compress` → `nova
verify`). The SMT step circuit is **byte-identical** to the CKO one
(`cardano_ed25519_ownership_nova.r1cs` — same md5), so these numbers also
hold for `CardanoKeyOwnership`; the fold covers the scalar multiplication
only, the SMT-membership half stays monolithic in both implementations.
Step-witness generation is identical for both implementations, so it is
excluded.

| Phase (per key, `cardano_key_ownership_smt_nova`, 255 × 7,724 constraints) | Impl 8 (step-chain) | Impl 9 (NIFS) |
|---|---|---|
| Ceremony (one-time, reusable) | **2.9 s** (step circuit) | **6.6 s** (compression circuit, 15,448 constraints) |
| Prover per-step | 670 ms (one Groth16 proof) | 224 ms (NIFS fold, two O(step) MSMs) |
| Prover total (fold) | **170.9 s** | **62.1 s** |
| Compress (Impl 9 only) | — | **61.1 s** (incl. ~58 s deterministic re-fold) |
| **Prover e2e, steady (ceremony amortized)** | **170.9 s** | **123.2 s** (1.4×) — **64.8 s** (2.6×) without the re-fold |
| Verify | **3.2 s** (255 pairings, O(N)) | **8.7 s** (one pairing + two MSM re-commitments, O(1)) |
| Bundle | 255 proofs + 255 states = **334.7 KiB (O(N))** | O(1) instance 5.2 KB + compression proof 661 KB = **~666 KiB (O(1))** |
| Proving key | 5.0 MB (step pk) | none for folding; 16 MB compression pk (one-time) |

Reading the table:

- **Fold is 3× faster** per step (224 ms vs 670 ms): the NIFS fold replaces
  one full Groth16 proof per step with two O(step) MSMs, and needs **no
  per-step proving key**.
- **`nova compress` currently re-folds.** The 61.1 s includes ~58 s re-running
  the fold to recover the private final witness, then only ~3 s for the actual
  compression proof. A deployed prover keeps the final witness and skips the
  re-fold → 64.8 s steady-state prover e2e (2.6× vs Impl 8). This is tracked
  as a cleanup.
- **Verify is O(1) but not yet cheaper at N = 255.** Impl 9's single-pairing
  verify (8.7 s) is dominated by the native `com(Z)`/`com(E)` re-commitment
  MSMs (variable-base, ~0.16 ms/point) and is *slower* than Impl 8's 255
  pairings (3.2 s) at this N. Crossover is at **N ≈ 690 steps**; beyond that
  the O(1) verify wins (Impl 8 grows ~12.6 ms/step). Switching these to
  precomputed fixed-base MSMs would make Impl 9's verify sub-second and win
  at all N.
- **Bundle is O(1) but the constant is larger than Impl 8 at N = 255.** The
  compression proof reveals the folded `Z`/`E` (661 KB for the 23K-wire
  compression circuit), so the ~666 KB constant bundle beats Impl 8's O(N)
  bundle (334.7 KiB + ~1.3 KB/step) only past **N ≈ 500**. The O(1)-in-N
  property — not the byte count at small N — is the win.
- **Ceremony moves, doesn't disappear.** Impl 8 needs a 2.9 s step ceremony;
  Impl 9 needs a 6.6 s compression ceremony (built from the step's A/B/C
  matrices, so per step shape in this build). Both are one-time and reusable
  across runs; Impl 9 additionally eliminates the per-step proving key.

### End-to-end flow — Implementation 10 (sumcheck compression, no ceremony)

Implementation 10 replaces the Groth16 compression proof of Implementation 9
with a **transparent sumcheck argument** — no trusted setup needed. The fold
phase is identical to Implementation 9; only the compress and verify steps
change. The step circuit here is byte-identical to
`cardano_ed25519_ownership_nova.r1cs` (7,724 constraints), so the fold
numbers are the same.

**Steps 1–5 are the same as Implementation 8** (key derivation via
`cardano-address` + `smt` CLI, step circuit compilation, step ceremony,
step witness generation with `gen_smt_nova_steps.py`). Then:

**6. NIFS fold** — same as Implementation 9 (no proving key):

```bash
../../clis/nova/target/release/nova fold --nifs \
  --circuit cardano_key_ownership_smt_nova.r1cs \
  --steps steps --out smt_ivc.json
# → NIFS bundle written to smt_ivc.json (255 steps → one instance)
```

**7. Compress with sumcheck** — no ceremony, no proving key:

```bash
../../clis/nova/target/release/nova compress --sumcheck \
  --circuit cardano_key_ownership_smt_nova.r1cs \
  --steps steps --out smt_sumcheck_proof.json
# → Sumcheck proof written to smt_sumcheck_proof.json
```

**8. Verify** — no verifying key needed:

```bash
../../clis/nova/target/release/nova verify \
  --ivc smt_ivc.json --sumcheck-proof smt_sumcheck_proof.json
# → Verified 255 steps: sumcheck compression proof OK, commitments OK, state chain OK
# → Final transcript: <64-byte hex>
```

**9. Application-level final check** (outside the fold — same as Impl 8):

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

**Key differences from Implementation 9:**

- **No compression ceremony.** Implementation 9 requires `trusted-setup ceremony-dev` on the compression circuit (15,448 constraints); Implementation 10 needs nothing.
- **No proving key.** `compress --sumcheck` needs only the step circuit and witnesses.
- **No verifying key.** `verify --sumcheck-proof` needs only the NIFS bundle and sumcheck proof.
- **True O(1) proof size.** Implementation 9's bundle is O(1) in N but O(step size) in constraints; Implementation 10's bundle is O(1) in both.
- **ZK for free.** The verifier never sees the folded witness or error vector.

The NIFS fold phase is **identical** to Implementation 9 (~224 ms/step on
the 7,724-constraint step circuit). See the
[Impl 10 benchmarks](../../nova-prover/README.md#implementation-10--nifs-fold--sumcheck-compression-no-ceremony)
for measured numbers. The SMT membership half of the combined statement
remains in the monolithic circuit — the fold covers the scalar multiplication
only.

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
- **Insertion**: `smt key` (`gen_input.sh` / `gen_smt_input.py` /
  `test_e2e.py` shell out to it) computes the leaf commitment
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
`SparseMerkleTree` in `clis/smt/src/sparse_merkle_tree.rs`.

> Note: `smt insert --index <N>` is what lets `gen_input.sh` /
> `gen_smt_input.py` place the single leaf at an arbitrary index while keeping
> the rest of the tree zero-padded. The `smt export` subcommand targets the
> separate `Privacy` spend circuit instead: it produces
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
├── gen_input.sh                        # Pure-shell input generator (CLI-only)
├── gen_smt_input.py                    # Python orchestrator (benchmark harness)
├── gen_smt_nova_steps.py               # Nova step-witness generator (255 steps)
├── test_e2e.py                         # Self-contained e2e input generator (PyNaCl)
├── test_smt_simple.py                  # Fixed-seed simple input generator (PyNaCl)
├── test_smt.sh                         # Input + witness + R1CS check (uses gen_input.sh)
├── demo.sh                             # End-to-end demo (uses gen_input.sh)
└── benchmarks.py                       # Witness/proof/verify timings
```

### Dependencies

- `circom` compiler (≥ 2.0.0) for compiling `cardano_key_ownership_smt.circom`
- `snarkjs` for witness generation
- `trusted-setup` CLI (`clis/trusted-setup`) for the single-party ceremony
- `groth16` CLI (`clis/groth16`) for proving and verification
- `smt` CLI (`clis/smt`) for all circuit-input crypto
  (`smt key`, `smt leaf`, `smt insert`, `smt cardano-input`) —
  `gen_input.sh`, `test_e2e.py`, `test_smt_simple.py` shell out to it
- `bech32` CLI to decode `pay.xsk`/`pay.vk` bech32 files (needed by
  `gen_input.sh --xsk/--vk` and `gen_smt_input.py`; not needed for
  `gen_input.sh --fixed`)
- `cardano-address` CLI for real-world key derivation (optional — needed by
  `demo.sh` and the benchmark harness)
- `pynacl` for the self-contained `test_e2e.py` key generation (optional)

### MiMC Hashing in the Circuit

The SMT uses MiMC(x^7) over the BLS12-381 **scalar field** as its hash
function. The circuit and the Rust CLI use the same round constants (see
`clis/smt/src/mimc.rs` and `circom/Privacy/mimc.circom`).
- 91 rounds for 128-bit security
- `MultiMimc7(6, 91)` commits the public key coordinates to the leaf

### Security Considerations

1. **Trust anchor**: The SMT root is the trust anchor. Compromise of the root
   compromises all keys in the set.
2. **Key rotation**: To add/remove keys, rebuild the SMT and update the root.
   Old proofs remain valid for the old root.
3. **Privacy (partial)**: The SMT stores only the MiMC commitment of the key (not
   the raw key), so the tree data leaks nothing about the keys. However `A` is a
   public input of the circuit, so the proof itself reveals the public key and
   only hides how it is authorized (leaf index / Merkle path). True key-hiding
   would require not publishing `A` (e.g. committing to a hidden key).
4. **Circuit size**: The combined circuit is larger than either component alone.
   The `nova` IVC folding approach (Implementation 8) splits the scalar
   multiplication into 255 small steps, dropping the ceremony from ~6 min to
   ~2.9 s and the proof from one 1.97M-constraint proof to 255 × 7.7K-constraint
   proofs — at the cost of O(N) verification. Implementation 9 (NIFS) replaces
   the per-step proofs with a transparent fold + one O(1) compression proof
   (see the [Impl 8 vs Impl 9 comparison](#end-to-end-comparison--implementation-8-step-chain-vs-implementation-9-nifs)).
   The SMT membership part remains in the monolithic circuit.

## Comparison with Existing Approaches

| Feature | CardanoKeyOwnership | CardanoKeyOwnershipSMT |
|---------|---------------------|------------------------|
| Proves key ownership | ✓ | ✓ |
| Proves set membership | ✗ | ✓ |
| Verifier trust / state | Per public key `A` | Single SMT root |
| Authorized set size | 1 | Any `N` (constant verification state) |
| Public inputs | `A[256]` | `A[256]`, `smt_root` |
| Hides which key | ✗ (`A` public) | ✗ (`A` public) — hides path/index only |
| Circuit size | 1,967,405 | 1,971,079 (+0.2 % at depth 4) |
| Set rotation / revocation | n/a (per-key proof) | Root update (rebuild SMT) |
| Needs a key registry | ✗ | ✓ (path + root) |
| SMT CLI integration | ✗ | ✓ |
