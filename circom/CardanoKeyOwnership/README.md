# Cardano Private Key → Public Key Ownership Proof

Prove knowledge of the private scalar that generates a given public key — without revealing the private key.

Two variants are provided:

| Variant | Curve | Constraints | Status | Use case |
|---------|-------|-------------|--------|----------|
| **JubJub ownership** | JubJub (BLS12-381-native) | ~4K | ✅ Working e2e | Fast proof, but **NOT** a real Cardano key |
| **Ed25519 ownership** | Curve25519 (Ed25519) | ~1.97M | ✅ Working e2e | Proves **real** Cardano wallet key ownership |

> **Do I need to recompile for every key?** **No.** The `.r1cs` and `.wasm` are compiled **once** and reused for any keypair. Only `input.json` is per-user.

---

## Prerequisites

| Tool | How to get it | Why we need it |
|------|---------------|----------------|
| `circom` | `cargo install circom` | Compile `.circom` → `.r1cs` + `.wasm` |
| `snarkjs` | `npm install -g snarkjs` | Generate `.wtns` from `.wasm` + `input.json` |
| `cardano-address` | [IntersectMBO/cardano-addresses releases](https://github.com/IntersectMBO/cardano-addresses/releases) | Derive real Cardano keys from BIP-39 mnemonic |
| `bech32` (CLI) | [IntersectMBO/bech32 releases](https://github.com/IntersectMBO/bech32/releases) | Decode bech32 key files |
| `trusted-setup` CLI | `cd clis/trusted-setup && cargo build --release` | Trusted-setup ceremonies (`ceremony-dev`) |
| `groth16` CLI | `cd clis/groth16 && cargo build --release` | Proof generation, verification |

---

<details>
<summary><b>Variant A: JubJub Key Ownership (~4K constraints) — click to expand</b></summary>

### What it proves

The prover knows a scalar `sk` such that `pk = [sk] · G_JubJub`, where `G_JubJub` is the JubJub base point. The verifier sees only `pk` — `sk` stays secret.

> **Caveat:** JubJub is a SNARK-friendly curve embedded in BLS12-381's scalar field. It is **not** a standard Cardano Ed25519 key. A separate off-chain commitment can link the JubJub key to a Cardano address, but the proof itself is for the JubJub key.

### End-to-end flow

```bash
cd circom/CardanoKeyOwnership

# 1. Compile (once)
circom --prime bls12381 cardano_key_ownership.circom --r1cs --wasm --sym

# 2. Create input.json with your JubJub private key and public key
#    (example: sk = 12345, pk_x = ..., pk_y = ...)
cat > input.json << 'EOF'
{
  "sk": ["1","0","0","1","0","1","1","0","0","0","0","0","0","0","0","0"],
  "pk_x": ["123456789012345678901234567890123456789012345678901234567890","0","0"],
  "pk_y": ["987654321098765432109876543210987654321098765432109876543210","0","0"]
}
EOF

# 3. Generate witness
snarkjs wtns calculate \
  cardano_key_ownership_js/cardano_key_ownership.wasm \
  input.json witness.wtns

# 4. Dev ceremony
cd ../../clis/groth16
../../clis/trusted-setup/target/release/trusted-setup ceremony-dev \
  --circuit ../../circom/CardanoKeyOwnership/cardano_key_ownership.r1cs \
  --proving-key /tmp/jubjub.pk --verifying-key /tmp/jubjub.vk

# 5. Prove
cargo run --release -- prove \
  --circuit ../../circom/CardanoKeyOwnership/cardano_key_ownership.r1cs \
  --witness ../../circom/CardanoKeyOwnership/witness.wtns \
  --proving-key /tmp/jubjub.pk --out /tmp/jubjub_proof.bin

# 6. Verify
cargo run --release -- verify \
  --proof /tmp/jubjub_proof.bin \
  --public /tmp/jubjub_proof.pub \
  --verifying-key /tmp/jubjub.vk
# → Verification result: VALID
```

</details>

---

<details>
<summary><b>Variant B: Ed25519 Key Ownership (~1.97M constraints) — click to expand</b></summary>

### What it proves

The prover knows the **clamped Ed25519 scalar** `a` (derived from a Cardano BIP32-Ed25519 extended signing key) such that the public key `A` equals `PointCompress([a]·G)` on Curve25519.

This is a minimal subset of the full `Ed25519Verify` circuit: one scalar multiplication on the base point, plus point compression. No SHA-512, no signature components. It proves ownership of a **real Cardano wallet key**.

> ### ⭐ Recommended for Ed25519: use **Implementation 8** (the Nova step-chain) — ~47 % faster first run, 240× smaller proving key
>
> The monolithic ~1.97M-constraint flow below is bottlenecked by its ceremony:
> **~8 min ceremony + ~74 s prove + ~10 s witness ≈ ~9.7 min e2e on first run**.
> The [Implementation 8](../../nova-prover/README.md#implementation-8-nova-ivc--compression-snark) step-chain decomposes the same ownership proof into **255 × 7.7K-constraint steps** (`cardano_ed25519_ownership_nova.circom`): the ceremony drops to **~3 s** and the fold takes **~179 s**, i.e. **~5.2 min total e2e on first run** — with per-step memory instead of ~4.5 GiB peak, and a 5 MB pk instead of 1.2 GB. The steps, keys, and transcript are all bound by a BLAKE2b512 state chain. (Note: once the ceremony is amortized across many keys, the monolithic path is ~3.6× faster per key — see the [Benchmarks](#benchmarks--pre-nova-vs-nova) section below.)
>
> ```bash
> circom --prime bls12381 -l ../Ed25519Verify/node_modules/circomlib/circuits \
>   cardano_ed25519_ownership_nova.circom --r1cs --wasm --sym
> ../../clis/nova/target/release/nova params --circuit cardano_ed25519_ownership_nova.r1cs
> ../../clis/nova/target/release/nova ceremony --circuit cardano_ed25519_ownership_nova.r1cs \
>   --proving-key cko255.pk --verifying-key cko255.vk
> ../../clis/nova/target/release/nova fold --circuit cardano_ed25519_ownership_nova.r1cs \
>   --proving-key cko255.pk --steps <witness-dir> --out cko255_ivc.json
> ../../clis/nova/target/release/nova verify --ivc cko255_ivc.json --verifying-key cko255.vk
> ```
>
> Full worked example (witness generation, flags, expected output): the **End-to-end flow — Implementation 8 (Nova step-chain)** section below. The monolithic Implementation 7 flow that follows remains available as the reference single-proof path. For a transparent, ceremony-free compression alternative, see **Implementation 10** (sumcheck compression): `nova fold --nifs` → `nova compress` → `nova verify --sumcheck-proof`. For on-chain proof sizes under 16 KiB, see **Implementation 11** (slim proofs): `nova compress --slim` → `nova verify --slim-proof`.

### End-to-end flow — Implementation 7 (monolithic + h-scalar)

> This is the **single-proof reference path**: one ~1.97M-constraint Groth16 proof, using the Implementation 7 sparse prover (`--sparse`) and h-query scalar compression (`--h-scalar`). Use it when you need one standalone proof for the whole key-ownership statement (e.g. a single on-chain verification). For interactive / step-heavy use, prefer the Implementation 8 step-chain below (~46 % faster first-run e2e).

#### Step 1: Derive a real Cardano payment key

```bash
cd circom/CardanoKeyOwnership

# Generate a 15-word recovery phrase
cardano-address recovery-phrase generate --size 15 > phrase.prv

# Derive the extended root signing key
cardano-address key from-recovery-phrase Shelley < phrase.prv > root.xsk

# Derive the payment signing key (path 1852H/1815H/0H/0/0)
cardano-address key child 1852H/1815H/0H/0/0 < root.xsk > pay.xsk

# Extract the public key (without chain code)
cardano-address key public --without-chain-code < pay.xsk > pay.vk
```

**Key insight:** The payment signing key `pay.xsk` encodes the Ed25519 scalar in its first 32 bytes (`kL`). In Cardano's BIP32-Ed25519, `kL` is **already clamped** — exactly what the circuit needs as the private witness `sk[255]`. The `pay.vk` file contains the standard 32-byte Ed25519 compressed public key.

#### Step 2: Generate circuit input from bech32 keys

```bash
# Decode bech32 and convert to bit/chunk arrays
python3 gen_cardano_address_input.py --xsk pay.xsk --vk pay.vk -o input.json
```

This produces `input.json` with:
- `A[256]` — compressed public key bits (from `pay.vk`)
- `sk[255]` — clamped scalar bits (from `pay.xsk`)
- `PointA[4][3]` — decompressed public key in extended coordinates

#### Step 3: Compile, witness, ceremony, prove, verify

```bash
# 3a. Compile the circuit (once)
circom --prime bls12381 -l ../Ed25519Verify/node_modules/circomlib/circuits \
  cardano_ed25519_ownership.circom --r1cs --wasm --sym

# 3b. Generate witness
snarkjs wtns calculate \
  cardano_ed25519_ownership_js/cardano_ed25519_ownership.wasm \
  input.json witness_ownership.wtns

# 3c. Dev ceremony (⚠️ MUST use --sparse)
#     Add --h-scalar to store a single scalar instead of the full h_query vector.
#     This halves the PK size and cuts prove time by ~10–15 %.
cd ../../clis/groth16
../../clis/trusted-setup/target/release/trusted-setup ceremony-dev --sparse --h-scalar \
  --circuit ../../circom/CardanoKeyOwnership/cardano_ed25519_ownership.r1cs \
  --proving-key /tmp/cardano_ed25519.pk \
  --verifying-key /tmp/cardano_ed25519.vk

# 3d. Prove (⚠️ MUST use --sparse)
#     No extra flags needed — the prover auto-detects h_scalar from the PK.
cargo run --release -- prove --sparse \
  --circuit ../../circom/CardanoKeyOwnership/cardano_ed25519_ownership.r1cs \
  --witness ../../circom/CardanoKeyOwnership/witness_ownership.wtns \
  --proving-key /tmp/cardano_ed25519.pk \
  --out /tmp/cardano_ed25519_proof.bin

# 3e. Verify
cargo run --release -- verify \
  --proof /tmp/cardano_ed25519_proof.bin \
  --public /tmp/cardano_ed25519_proof.pub \
  --verifying-key /tmp/cardano_ed25519.vk
# → Verification result: VALID
```

#### Step 4: Export VK for on-chain deployment (optional)

```bash
cargo run --release -- export-vk \
  --verifying-key /tmp/cardano_ed25519.vk \
  --out /tmp/cardano_ed25519_vk.ak
```

### End-to-end flow — Implementation 8 (Nova step-chain)

[`cardano_ed25519_ownership_nova.circom`](cardano_ed25519_ownership_nova.circom) decomposes the same ownership statement into **255 identical steps**, each one `BitElementMulAny` on extended Edwards coordinates `[4][3]` (each coordinate as 3 limbs of base 2^85):

- state `(dblIn[4][3], addIn[4][3])` — 24 public inputs / 24 public outputs, 1 private input `sel`.
- per step: `dblOut = 2·dblIn`, `addOut = addIn + sel·dblOut` (`sel` = scalar bit, LSB-first).
- after 255 steps: `addOut = 2·[sk]·G`; the final checks `addOut == PointA` (projective) and `PointCompress(PointA) == A` are done by the application *after* the fold (they cannot be folded per-step — the accumulator is only complete after all 255 bits).
- sizes: 7658 wires, 7724 constraints per step (vs ~1.97M monolithic). Same ceremony is reusable for **any** run of this step shape.

**1. Build the CLI**

```bash
cargo build --release --manifest-path ../../clis/nova/Cargo.toml
# binary: ../../clis/nova/target/release/nova (used as `nova` below)
```

**2. Compile the step circuit** (once; BLS12-381 field, `circomlib` include path)

```bash
circom --prime bls12381 -l ../Ed25519Verify/node_modules/circomlib/circuits \
  cardano_ed25519_ownership_nova.circom --r1cs --wasm --sym
```

**3. Inspect the step circuit** (must report `n_pub_in == n_pub_out == 24`)

```bash
../../clis/nova/target/release/nova params --circuit cardano_ed25519_ownership_nova.r1cs
```

**4. One ceremony for the step circuit** (reusable for *any* run of the same step shape)

```bash
../../clis/nova/target/release/nova ceremony --circuit cardano_ed25519_ownership_nova.r1cs \
  --proving-key cko255.pk --verifying-key cko255.vk
```

**5. Generate the 255 step witnesses** `step_0000.wtns … step_0254.wtns` in one directory (full witness files, produced by the step circuit's wasm). Generate them **iteratively** so the chain invariant holds by construction:

```
dblIn := extended(G)          # base point, [4][3] x base-2^85 limbs
addIn := extended(O)          # identity
for i in 0..255:
    inputs = (dblIn, addIn, sel := (sk >> i) & 1)
    run wasm → full witness step_%04d.wtns
    read outputs (dblOut, addOut) → next (dblIn, addIn)
```

The `sel` bits come from the same clamped scalar `sk` as in the Implementation 7 flow (`sk[255]` produced by `gen_cardano_address_input.py`). Run each step through the step circuit's wasm (e.g. `snarkjs wtns calculate cardano_ed25519_ownership_nova_js/cardano_ed25519_ownership_nova.wasm`).

**6. Fold** — proves each step, checks the state chain, accumulates the transcript (≈2–4 min for 255 × 7.7K-constraint steps)

```bash
../../clis/nova/target/release/nova fold --circuit cardano_ed25519_ownership_nova.r1cs \
  --proving-key cko255.pk --steps <witness-dir> --out cko255_ivc.json
```

**7. Verify** — re-checks every Groth16 pairing, the state chain, and the transcript

```bash
../../clis/nova/target/release/nova verify --ivc cko255_ivc.json --verifying-key cko255.vk
# → Verified 255 steps: 255 pairings OK, state chain OK, transcript OK
```

> **Note:** `nova` verification here is still **O(N)** — it re-checks every step proof. The O(1)-verify path is shipped as [Implementation 9](../../nova-prover/README.md#implementation-9-relaxed-r1cs-folding--single-compression-snark): `nova fold --nifs` → `trusted-setup ceremony-dev` on the emitted compression circuit → `nova compress --groth16` → `nova verify --compression-proof` — see the [Implementation 9 e2e flow](../../nova-prover/README.md#e2e-flow--implementation-9-nifs). For a **transparent** O(1)-verify path with no ceremony, see [Implementation 10](../../nova-prover/README.md#implementation-10-constant-size-nova-proofs): `nova fold --nifs` → `nova compress` → `nova verify --sumcheck-proof` — no proving or verifying key needed for compression. For on-chain proof sizes under 16 KiB, see **Implementation 11** (slim proofs): `nova compress --slim` → `nova verify --slim-proof`.

### Benchmarks — pre-Nova vs Nova

Measured on the same machine (4 × 31 GB) with the `nova` release binary, `snarkjs` for witness generation, one shared key, single runs.

| Phase | Pre-Nova (monolithic) | Nova (step-chain) |
|---|---|---|
| circuit | 1,967,405 constraints | 255 × 7,724 constraints |
| key + circuit input | 0.3 s | (shared) |
| witness generation | 9.8 s | 255 steps: 133.0 s |
| ceremony (one-time, reusable) | 496.4 s | 2.7 s |
| prove / fold | 73.9 s | 178.5 s |
| verify | 1.5 s | 3.2 s |
| **e2e, first run (incl. ceremony)** | **582 s** | **314 s** |
| **e2e, steady (ceremony amortized)** | **86 s** | **312 s** |
| proving key | 1.2 GB | 5.0 MB |
| verifying key | 178 MB | 719 KB |

Reading the table:

- **First run** (fresh key + ceremony): Nova is **~46 % faster** — the ~8 min monolithic ceremony dominates, while the Nova ceremony is ~3 s. The proving-key footprint drops from 1.2 GB to 5 MB and peak memory from ~4.5 GiB to per-step.
- **Steady state** (ceremony reused, per additional key): pre-Nova is **~3.6× faster** (86 s vs 312 s). Nova re-derives 255 step witnesses and folds them per key; the monolithic prover only redoes one witness + one proof. (The step chain is inherently sequential — each step feeds the next.)
- Both flows prove the **same** Ed25519 ownership statement; the point-compression and `addOut == 2·PointA` checks are done outside the Nova fold.

Reproduce: `python3 ../benchmarks_compare.py --family cko --workdir <dir>`
(see `../benchmarks_compare.py` header for the full CLI; the same harness covers `--family smt`).

### End-to-end comparison — Implementation 8 (step-chain) vs Implementation 9 (NIFS) vs Implementation 10 (sumcheck)

Measured on the **same machine / same 255 step witnesses** (full-size state values): Impl 8 from `benchmark_nova`, Impl 9 via the real CLI e2e (`nova fold --nifs` → `trusted-setup ceremony-dev` → `nova compress` → `nova verify`), Impl 10 via `benchmark_nova --sumcheck`. Step-witness generation is identical for all three, so it is excluded.

| Phase (per key, `cardano_ed25519_ownership_nova`, 255 × 7,724 constraints) | Impl 8 (step-chain) | Impl 9 (NIFS) | Impl 10 (sumcheck) |
|---|---|---|---|
| Ceremony (one-time, reusable) | **2.7 s** (step circuit) | **6.4 s** (compression circuit, 15,448 constraints) | **None** |
| Prover per-step | 700 ms (one Groth16 proof) | 230 ms (NIFS fold, two O(step) MSMs) | 185 ms (NIFS fold, two O(step) MSMs) |
| Prover total (fold) | **178.5 s** | **53.4 s** | **47.3 s** |
| Compress | — | **55.3 s** (incl. ~53 s deterministic re-fold) | **7.75 s** (no ceremony, no PK) |
| **Prover e2e, steady (ceremony amortized)** | **178.5 s** | **108.7 s** (1.6×) | **55.1 s** (3.2×) |
| Verify | **3.2 s** (255 pairings, O(N)) | **7.8 s** (one pairing + two MSM re-commitments, O(1)) | **7.87 s** (sumcheck + HashPC, O(1), ZK) |
| Bundle | 255 proofs + 255 states = **334.7 KiB (O(N))** | O(1) instance 5.6 KB + compression proof 650 KB = **~656 KiB (O(1))** | O(1) instance 3.2 KB + sumcheck proof 469.6 KB = **~472.8 KiB (O(1), ZK)** |
| Proving key | 5.0 MB (step pk) | none for folding; 16 MB compression pk (one-time) | **None** |

Reading the table:

- **Fold is 3× faster** per step (185 ms vs 700 ms): the NIFS fold replaces one full Groth16 proof per step with two O(step) MSMs, and needs **no per-step proving key**. Impl 10 fold is slightly faster than Impl 9 due to lower overhead (no compression circuit context).
- **Impl 10 eliminates ceremony.** Impl 8 needs 2.7 s step ceremony; Impl 9 needs 6.4 s compression ceremony; Impl 10 needs **nothing** — the sumcheck protocol and HashPC commitments are transparent.
- **Impl 10 compress is faster.** 7.75 s vs 55.3 s (7×) — no deterministic re-fold overhead, no Groth16 proof. The HashPC commitments dominate at this step width.
- **Verify is comparable at N = 255.** Impl 10 (7.87 s) ≈ Impl 9 (7.8 s) < Impl 8 (3.2 s, O(N) pairings). Crossover is at **N ≈ 660 steps**; beyond that the O(1) verify wins.
- **Bundle is truly O(1) and smaller.** Impl 10's 472.8 KiB < Impl 9's 656 KiB — the sumcheck proof is smaller than the Groth16 compression proof because it doesn't reveal `Z`/`E`. Both beat Impl 8's O(N) bundle past **N ≈ 500**.
- **ZK comes free.** Impl 10 never reveals `Z` or `E`; Impl 8 and 9 reveal them in the bundle/compression proof.

</details>

---

<details>
<summary><b>End-to-end flow — Implementation 10 (sumcheck compression, no ceremony) — click to expand</b></summary>

Implementation 10 replaces the Groth16 compression proof of Implementation 9 with a **transparent sumcheck argument** — no trusted setup needed. The fold phase is identical to Implementation 9; only the compress and verify steps change.

**Steps 1–5 are the same as Implementation 8** (key derivation, input generation, compile step circuit, ceremony, generate step witnesses). Then:

**6. NIFS fold** — same as Implementation 9 (no proving key):

```bash
../../clis/nova/target/release/nova fold --nifs \
  --circuit cardano_ed25519_ownership_nova.r1cs \
  --steps <witness-dir> --out cko255_ivc.json
# → NIFS bundle written to cko255_ivc.json (255 steps → one instance)
```

**7. Compress with sumcheck** — no ceremony, no proving key:

```bash
../../clis/nova/target/release/nova compress \
  --circuit cardano_ed25519_ownership_nova.r1cs \
  --steps <witness-dir> --out cko255_sumcheck_proof.json
# → Sumcheck proof written to cko255_sumcheck_proof.json
```

**8. Verify** — no verifying key needed:

```bash
../../clis/nova/target/release/nova verify \
  --ivc cko255_ivc.json --sumcheck-proof cko255_sumcheck_proof.json
# → Verified 255 steps: sumcheck compression proof OK, commitments OK, state chain OK
# → Final transcript: <64-byte hex>
```

**Key differences from Implementation 9:**

- **No compression ceremony.** Implementation 9 requires `trusted-setup ceremony-dev` on the compression circuit (15,448 constraints); Implementation 10 needs nothing.
- **No proving key.** `compress` (default: sumcheck) needs only the step circuit and witnesses.
- **No verifying key.** `verify --sumcheck-proof` needs only the NIFS bundle and sumcheck proof.
- **True O(1) proof size.** Implementation 9's bundle is O(1) in N but O(step size) in constraints (the compression proof reveals `Z`/`E`). Implementation 10's bundle is O(1) in both — proof size is O(log(n_constraints)) field elements.
- **ZK for free.** The verifier never sees the folded witness or error vector.

The NIFS fold phase is **identical** to Implementation 9 (~230 ms/step on 7,724-constraint circuits). The sumcheck compress/verify phases are currently slower than Groth16 for small circuits but scale better as step width grows. See the [Impl 10 benchmarks](../../nova-prover/README.md#implementation-10--nifs-fold--sumcheck-compression-no-ceremony) for measured numbers.

</details>

---

<details>
<summary><b>Implementation 11 — Slim on-chain proof (Cardano ≤16 KiB) — click to expand</b></summary>

Implementation 11 strips the HashPC opening proofs (`w_opening`, `e_opening`) from the sumcheck bundle. These opening proofs (the BLAKE2b truth tables for Z and E) are only needed for off-chain auditability — the sumcheck proof itself already proves knowledge of a witness consistent with the committed instance. Removing them reduces the on-chain proof from **~473 KiB** to **~4 KiB** — well under Cardano's **16 KiB** transaction size limit.

**Proof size breakdown (ed25519, 255 steps):**

| Component | Full sumcheck | Slim (on-chain) |
|---|---|---|
| Sumcheck transcript | ~200 B | ~200 B |
| Fiat-Shamir challenges | ~2 KiB | ~2 KiB |
| HashPC opening proofs (Z + E) | ~469 KiB | **stripped** |
| Commitment digests (2 × BLAKE2b-512) | — | 128 B |
| **Total** | **~473 KiB** | **~4.1 KiB** |

**Steps 1–6 are the same as Implementation 10** (fold → compress). Then:

**7. Compress with slim flag** — strips opening proofs:

```bash
../../clis/nova/target/release/nova compress --slim \
  --circuit cardano_ed25519_ownership_nova.r1cs \
  --steps <witness-dir> --out cko255_slim.json
# → Slim proof written to cko255_slim.json (down from ~473 KiB to ~4 KiB)
```

**8. Verify slim proof** — no verifying key, no opening proofs:

```bash
../../clis/nova/target/release/nova verify \
  --ivc cko255_ivc.json --slim-proof cko255_slim.json
# → Verified 255 steps: slim sumcheck proof OK, state chain OK
#    (no opening proofs — off-chain audit trail)
```

**What the slim verifier checks:**

1. Sumcheck protocol — proves ∃ Z, E such that `com(Z) = w_commit` and `com(E) = e_commit` and the relaxed-R1CS holds
2. Fiat-Shamir transcript — deterministic from the fold; verifier recomputes challenges
3. Final IVC state — the public output (e.g., ownership attestation)

The opening proofs (Z and E truth tables) are submitted separately by a relayer for auditability but are *not* required for on-chain soundness. See the [Impl 11 design rationale](../../nova-prover/README.md#implementation-11--cardano-ready-nova-proofs-all-three-optimizations-on-impl-10) for the security analysis.

</details>

---

<details>
<summary><b>Post-quantum alternative — Lova folding (lattice-prover) — click to expand</b></summary>

The post-quantum track replaces Nova's Pedersen commitments with Ajtai/SIS lattice commitments. The `lattice-prover` crate implements the Lova folding scheme (ASIACRYPT 2024), which runs on Z_{2^64} — no field arithmetic, fully transparent.

**R1CS-to-Lova adapter:** Circom witnesses (BLS12-381 field elements) are converted to Lova vectors via 4-limb decomposition (each 32-byte element → 4 × u64 limbs). This enables folding real circuit witnesses through the Lova pipeline.

| Metric | Nova Impl 10 (sumcheck) | Lova (EdDSA, 15 signals) | Lova (Airdrop, 1,210 signals) |
|--------|-------------------------|--------------------------|-------------------------------|
| Fold/step | 185 ms | **0.60 ms** | 1,197 ms |
| Verify/step | 7.87 s | **0.03 ms** | 285 ms |
| Proof size | 472.8 KiB | **31.9 KiB** | 2,571 KiB |
| Post-quantum | ❌ | ✅ | ✅ |

**Key observations:**

- **Small circuits are practical** — EdDSA (15 signals) folds at 0.60 ms/step, faster than Nova's NIFS (185 ms/step), while remaining post-quantum secure.
- **Proof size is constant** regardless of step count — a key Lova advantage over Nova's linear-in-step-count proofs.
- **Large circuits need optimization** — the 4-limb BLS12-381 expansion multiplies the effective dimension by 4×, making Ed25519 (7,658 signals) ~50,000× slower per step.
- **No trusted setup** — Lova is fully transparent (no ceremony, no proving/verifying key).

**Usage:**

```bash
cd clis/lattice

# Display Lova parameters
lattice --lova params --m 60 --n 60

# Fold 32 steps
lattice --lova fold --steps 32 --m 60 --n 60

# Benchmark with real circuit witnesses
cargo run --release --bin benchmark_lova_r1cs -- \
  --steps-dir /tmp/opencode/bench/eddsa_steps --limit 32
```

See [`lattice-prover/README.md`](../../lattice-prover/README.md) for full Lova documentation and [`clis/lattice/README.md`](../../clis/lattice/README.md) for CLI usage.

</details>

---

## How it works (Ed25519 variant)

```circom
template CardanoEd25519Ownership() {
    signal input A[256];      // compressed public key (public)
    signal input sk[255];     // clamped scalar (private)
    signal input PointA[4][3]; // decompressed point (private)

    // 1. [sk] · G
    component pMul = ScalarMul();
    pMul.s <== sk;
    pMul.P <== G;   // Curve25519 base point

    // 2. Assert [sk]·G == PointA
    component equal = PointEqual();
    equal.p <== pMul.sP;
    equal.q <== PointA;

    // 3. Assert PointCompress(PointA) == A
    component compressA = PointCompress();
    compressA.P <== PointA;
    compressA.out === A;
}
```

Uses `ScalarMul`, `PointEqual`, and `PointCompress` from `Ed25519Verify/` (Electron-Labs templates adapted for BLS12-381).

---

## References

- [`Ed25519Verify/README.md`](../Ed25519Verify/README.md) — Full Ed25519 signature verification on BLS12-381
- [`EdDSAJubJub/README.md`](../EdDSAJubJub/README.md) — JubJub curve parameters
- [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032) — EdDSA / Ed25519 specification
- [Electron-Labs/ed25519-circom](https://github.com/Electron-Labs/ed25519-circom) — upstream Ed25519 Circom circuits
- [IntersectMBO/cardano-addresses](https://github.com/IntersectMBO/cardano-addresses) — Cardano key derivation (CIP-1852)
- [IntersectMBO/cardano-crypto](https://github.com/IntersectMBO/cardano-crypto) — Cardano key derivation logic

## License

MIT (same as upstream circomlib and EdDSAJubJub/Ed25519Verify circuits).
