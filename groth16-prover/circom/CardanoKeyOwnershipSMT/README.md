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
1. Generate witness inputs from an Ed25519 key pair

   $ python3 test_e2e.py --depth 4 --index 0 --output witness.json

   (or, from a real Cardano key:)

   $ cardano-address key public --without-chain-code < pay.xsk > pay.vk
   $ python3 gen_smt_input.py --xsk pay.xsk --vk pay.vk -o witness.json --depth 4

2. Generate the witness

   $ snarkjs wc cardano_key_ownership_smt_js/cardano_key_ownership_smt.wasm \
       witness.json witness.wtns

3. Check the witness satisfies the R1CS

   $ snarkjs wchk cardano_key_ownership_smt.r1cs witness.wtns

4. Generate the combined proof (Ed25519 + SMT membership)

   $ snarkjs groth16 prove cardano_key_ownership_smt_final.zkey \
       witness.json proof.json public.json

5. Verify the combined proof

   $ snarkjs groth16 verify cardano_key_ownership_smt_verification_key.json \
       public.json proof.json
```

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
- Private input: `siblings[]` (Merkle path siblings), `direction[]` (left/right bits)
- Public input: `digest` (SMT root), `leaf` (the key commitment)
- Uses MiMC(x^7) hashing for the path computation
- Verifies that `hash(leaf, siblings, directions) == digest`

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

- `circom` compiler (≥ 2.0.0)
- `snarkjs` for witness generation and proof verification
- `cardano-addresses` CLI for key generation (optional, for real-world use)
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
