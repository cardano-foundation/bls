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
1. Build the SMT of authorized key commitments

   $ groth16-prover smt insert --depth 4 \
       --items "commit1,commit2,commit3,commit4" \
       --state auth_keys.json

2. Export the SMT witness data for a specific nullifier

   $ groth16-prover smt export --state auth_keys.json \
       --nullifier <nullifier> --out witness.json

3. Generate the combined proof (Ed25519 + SMT membership)

   $ groth16-prover prove --circuit cardano_key_ownership_smt.r1cs \
       --witness witness.wtns --proving-key circuit.pk --out proof.bin

4. Verify the combined proof

   $ groth16-prover verify --proof proof.bin --public proof.pub --verifying-key circuit.vk
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
- **Insertion**: `smt insert` uses MiMC(x^7) to hash items into the tree
- **Verification**: The circuit must compute the same commitment from `A`

Two approaches for the bridge:

| Approach | Description | Trade-off |
|----------|-------------|-----------|
| **Direct** | Use `A` (or a hash of `A`) as the SMT leaf value directly | Simple, but leaks key identity to SMT |
| **Hash** | Commit to `H(A)` where `H` is MiMC(x^7), store `H(A)` in SMT | More privacy, requires matching hash in circuit |

The **Hash** approach is recommended: the SMT stores `MiMC(A)` and the circuit
computes the same MiMC hash as part of the proof, then verifies membership of
`MiMC(A)` in the tree.

### Input/Output Specification

#### Public Inputs
- `A[256]` — compressed Ed25519 public key bits
- `digest` — SMT root (field element)
- `MiMC(A)` — MiMC hash of the public key (field element)

#### Private Inputs
- `sk[255]` — Ed25519 scalar bits
- `PointA[4][3]` — decompressed public key in extended coordinates
- `siblings[]` — Merkle path sibling field elements
- `direction[]` — Merkle path direction bits (0=left, 1=right)

### File Layout

```text
CardanoKeyOwnershipSMT/
├── README.md                    # This file
├── cardano_key_ownership_smt.circom   # Combined circuit
├── cardano_key_ownership_smt.r1cs       # Compiled R1CS
├── cardano_key_ownership_smt.wasm       # Witness generator
├── cardano_key_ownership_smt_js/        # JS witness gen directory
├── setup_cardano_address_smt.sh         # Setup script
├── gen_cardano_address_smt_input.py     # Input generator (extended)
├── test_cardano_address_smt_e2e.sh      # E2E test script
├── test_ownership_smt_input.json        # Test input
└── witness_ownership_smt.wtns           # Test witness
```

### Dependencies

- `circom` compiler (≥ 2.0.0)
- `snarkjs` for witness generation and proof verification
- `cardano-addresses` CLI for key generation (optional, for real-world use)
- `groth16-prover` CLI for proving and verification

### MiMC Hashing in the Circuit

The SMT uses MiMC(x^7) as its hash function. The circuit must implement the
same MiMC round function to compute the Merkle path. The number of rounds
depends on the security level:
- 91 rounds for 128-bit security (BLS12-381 base field)
- The `mimc` module in `groth16-prover` provides the `mimc2` function

### Security Considerations

1. **Trust anchor**: The SMT root is the trust anchor. Compromise of the root
   compromises all keys in the set.
2. **Key rotation**: To add/remove keys, rebuild the SMT and update the root.
   Old proofs remain valid for the old root.
3. **Privacy**: The Hash approach hides which specific key is being used, but
   the public key `A` is still visible on-chain. For full privacy, consider
   using a Pedersen commitment instead of MiMC.
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
