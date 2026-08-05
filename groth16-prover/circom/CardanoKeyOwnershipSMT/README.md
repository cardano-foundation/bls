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
> ~1.5 s; see the `CardanoKeyOwnership` README for the analogous step-chain
> workflow.

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
├── cardano_key_ownership_smt.circom   # Combined circuit
├── cardano_key_ownership_smt.r1cs       # Compiled R1CS
├── cardano_key_ownership_smt.wasm       # Witness generator
├── cardano_key_ownership_smt_js/        # JS witness gen directory
├── gen_smt_input.py                     # Input generator (cardano-address keys)
├── test_e2e.py                          # Self-contained e2e input generator
├── test_smt_simple.py                   # Fixed-seed simple input generator
├── test_smt.sh                          # Input + witness + R1CS check
├── demo.sh                              # End-to-end demo
└── benchmarks.py                        # Witness/proof/verify timings
```

### Dependencies

- `circom` compiler (≥ 2.0.0) for compiling `cardano_key_ownership_smt.circom`
- `snarkjs` for witness generation
- `groth16-prover` CLI for ceremony, proving, and verification
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
   For large SMT depths, consider using the `nova` IVC folding approach to
   batch multiple proofs.

## Comparison with Existing Approaches

| Feature | CardanoKeyOwnership | CardanoKeyOwnershipSMT |
|---------|---------------------|------------------------|
| Proves key ownership | ✓ | ✓ |
| Proves set membership | ✗ | ✓ |
| Privacy (which key) | ✗ (key is public) | ✓ (with Hash approach) |
| Trust model | Single key | SMT root = set of keys |
| Circuit size | Smaller | Larger (SMT path included) |
| SMT CLI integration | ✗ | ✓ |
