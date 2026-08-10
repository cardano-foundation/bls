# Anonymous Airdrop — Reputation-Gated Token Distribution

Prove you qualify for an airdrop based on a secret reputation score — without revealing your identity or your exact score.

This circuit is a **composite** of three existing building blocks:
1. **SMT membership** (`Spend(depth)` from `circom/Privacy/`) — prove a credential exists in a Sparse Merkle Tree.
2. **Range proof** (`Num2Bits(n)` from `circomlib`) — prove the score fits in `n` bits.
3. **Comparison** (`GreaterEqThan(n)` from `circomlib`) — prove `score >= minScore`.

The leaf commitment binds all three secrets together: `commitment = MiMC(MiMC(nullifier, nonce), score)`.

---

## Circuit design

```circom
template AnonymousAirdrop(depth, n) {
    // Public inputs
    signal input digest;       // SMT root
    signal input minScore;     // Minimum score required
    signal input nullifier;    // Credential ID (revealed to prevent double-claim)

    // Private inputs
    signal input nonce;        // Secret nonce
    signal input score;        // Secret reputation score
    signal input sibling[depth];
    signal input direction[depth];

    // 1. Range proof: score < 2^n
    component n2bScore = Num2Bits(n);
    n2bScore.in <== score;

    // 2. Range proof: minScore < 2^n
    component n2bMin = Num2Bits(n);
    n2bMin.in <== minScore;

    // 3. Threshold proof: score >= minScore
    component gte = GreaterEqThan(n);
    gte.in[0] <== score;
    gte.in[1] <== minScore;
    gte.out === 1;

    // 4. Compute commitment = MiMC(MiMC(nullifier, nonce), score)
    component hasher0 = Mimc2();
    hasher0.in0 <== nullifier;
    hasher0.in1 <== nonce;

    component hasher1 = Mimc2();
    hasher1.in0 <== hasher0.out;
    hasher1.in1 <== score;

    signal commitment;
    commitment <== hasher1.out;

    // 5. SMT membership proof (same structure as Spend(depth))
    ...
}
```

**Public inputs:** `digest`, `minScore`, `nullifier`  
**Private inputs:** `nonce`, `score`, `sibling[depth]`, `direction[depth]`

---

## Full CLI flow

### 1. Compile the circuit

```bash
cd circom/AnonymousAirdrop
circom --prime bls12381 -l ../Ed25519Verify/node_modules/circomlib/circuits \
  anonymous_airdrop_depth2.circom --r1cs --wasm --sym
```

Result: `anonymous_airdrop_depth2.r1cs` (1561 constraints) + `anonymous_airdrop_depth2.wasm`.

### 2. Build the SMT and compute witness inputs

The project maintains an SMT of eligible members. Each member has a `(nullifier, nonce, score)` triple. The leaf is `MiMC(MiMC(nullifier, nonce), score)`.

Use the helper binary (or do it manually):

```bash
cd ../../groth16-prover
cargo run --bin compute_airdrop_inputs --features privacy
cd ../circom/AnonymousAirdrop
```

This prints:
- The SMT digest (root)
- `input.json` for the accepted case (score >= minScore)
- `input_rejected.json` for the rejected case (score < minScore)

Save the accepted JSON to `input.json`:
```json
{
  "digest": "11532464310312174561046533224304711315458591992375104258711270731788815721034",
  "minScore": "100",
  "nullifier": "3",
  "nonce": "300",
  "score": "120",
  "sibling": ["0", "47252287271164011656207288696370005352642778257683443251406641354340159993877"],
  "direction": ["0", "1"]
}
```

### 3. Compute the witness

```bash
snarkjs wtns calculate anonymous_airdrop_depth2_js/anonymous_airdrop_depth2.wasm \
  input.json witness.wtns
```

### 4. Run the dev ceremony

```bash
cd ../../clis/groth16
../../clis/trusted-setup/target/release/trusted-setup ceremony-dev \
  --circuit ../../circom/AnonymousAirdrop/anonymous_airdrop_depth2.r1cs \
  --proving-key ../../circom/AnonymousAirdrop/airdrop.pk \
  --verifying-key ../../circom/AnonymousAirdrop/airdrop.vk
```

Output:
```
Dev ceremony complete. Full proving key generated.
  Proving key:  ../../circom/AnonymousAirdrop/airdrop.pk  (552882 bytes compressed)
  Verifying key: ../../circom/AnonymousAirdrop/airdrop.vk  (76000 bytes)
```

### 5. Generate the proof

```bash
cargo run --release -- prove \
  --circuit ../../circom/AnonymousAirdrop/anonymous_airdrop_depth2.r1cs \
  --witness ../../circom/AnonymousAirdrop/witness.wtns \
  --proving-key ../../circom/AnonymousAirdrop/airdrop.pk \
  --out ../../circom/AnonymousAirdrop/proof.bin
```

Output:
```
Loaded circuit: 1576 wires, 1575 constraints
Using on-the-fly QAP construction (Implementation 5)
Proof generated successfully.
Proof written to ../../circom/AnonymousAirdrop/proof.bin
Public input written to ../../circom/AnonymousAirdrop/proof.pub
```

### 6. Verify the proof

```bash
cargo run --release -- verify \
  --proof ../../circom/AnonymousAirdrop/proof.bin \
  --public ../../circom/AnonymousAirdrop/proof.pub \
  --verifying-key ../../circom/AnonymousAirdrop/airdrop.vk
```

Output:
```
Verification result: VALID
```

### 7. Try the rejected case (should fail)

```bash
snarkjs wtns calculate anonymous_airdrop_depth2_js/anonymous_airdrop_depth2.wasm \
  input_rejected.json witness_rejected.wtns
```

Output:
```
ERROR: Assert Failed. Error in template AnonymousAirdrop_9 line: 50
```

The assertion `gte.out === 1` fails because Bob's score (42) is less than the minimum (100). The witness cannot even be built, let alone a proof generated.

---

## Files

| File | Description |
|---|---|
| `anonymous_airdrop.circom` | Reusable `AnonymousAirdrop(depth, n)` template |
| `anonymous_airdrop_depth2.circom` | Instantiation with depth=2, n=32 |
| `input.json` | Accepted witness input (Carol, score=120, minScore=100) |
| `input_rejected.json` | Rejected witness input (Bob, score=42, minScore=100) |
| `compute_airdrop_inputs.rs` | Rust helper to build SMT and compute inputs |
