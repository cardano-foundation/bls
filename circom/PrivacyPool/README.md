# Privacy Pool — confidential shielded transactions (Step 3 / F5a)

Confidential privacy-pool circuits combining **identity privacy** (Step 1,
predicate proofs) and **amount hiding** (Step 2, Twisted ElGamal) into a single
shielded-payment engine: users deposit a commitment, spend it privately, and
withdraw — without revealing address, identity, or value.

This directly implements the **F5a — Shielded Amounts** circuit of
[`groth16-prover/docs/F5_RESEARCH_DIRECTION.md`](../../groth16-prover/docs/F5_RESEARCH_DIRECTION.md).

## Circuits

| File | What it proves |
|------|----------------|
| [`note.circom`](note.circom) | Note commitment `Poseidon(Poseidon(nullifier, amount), blinding)` and `nullifier_hash = Poseidon(0, nullifier)`. |
| [`merkle.circom`](merkle.circom) | Reusable Poseidon Merkle membership over a caller-supplied leaf (`depth` levels). |
| [`privacy_pool.circom`](privacy_pool.circom) | **1-in / 2-out spend**: Merkle membership + nullifier-uniqueness + per-note amount range checks + value conservation (`in == out1 + out2 + fee`). |
| [`privacy_pool_nova.circom`](privacy_pool_nova.circom) | **Nova IVC step** — one Merkle level per step, `state_out = Poseidon(switch(state_in, sibling, direction))`. |
| [`gen_privacy_input.py`](gen_privacy_input.py) | Off-chain witness builder (commitments, Merkle root, path) for the Groth16 circuit. |
| [`gen_nova_privpool_steps.py`](gen_nova_privpool_steps.py) | Per-step witness builder for the Nova Merkle chain (each step feeds the next sibling/direction). |

### `privacy_pool.circom` — public vs private

| Direction | Signals |
|-----------|---------|
| **Public** | `merkle_root`, `nullifier_hash`, `out_commitment_1`, `out_commitment_2`, `fee` |
| **Private** | `nullifier`, `in_amount`, `in_blinding`, `out_nullifier_{1,2}`, `out_amount_{1,2}`, `out_blinding_{1,2}`, `sibling[depth]`, `direction[depth]` |

Each output note gets a **fresh** nullifier/blinding; the pool records the two
new output commitments and publishes the input's `nullifier_hash` (so it
cannot be double-spent) — the semantics of a shielded pool.

## Constraint counts (BLS12-381)

| Circuit | Non-linear | Linear | Total |
|---------|-----------|--------|-------|
| `privacy_pool` (depth 4, n=32) | 2,785 | 4,302 | 7,087 |
| `privacy_pool_nova` (1 step) | 245 | 390 | 635 |

## Compile

```bash
cd circom/PrivacyPool
circom privacy_pool.circom --r1cs --wasm --sym --prime bls12381 \
  -l ../RangeProof/node_modules/circomlib/circuits \
  -l ./node_modules/circomlib/circuits
# likewise for privacy_pool_nova.circom
```

`--prime bls12381` **must** match the Rust prover / Nova verifier curve.

## Groth16 e2e

```bash
# 1. Off-chain values
python3 gen_privacy_input.py 4          # writes input.json
snarkjs wtns calculate privacy_pool_js/privacy_pool.wasm input.json witness.wtns

# 2. Dev ceremony (use --sparse for this circuit's size)
cargo run --release --manifest-path ../../clis/trusted-setup/Cargo.toml -- \
  ceremony-dev --sparse --circuit privacy_pool.r1cs \
  --proving-key /tmp/pp.pk --verifying-key /tmp/pp.vk

# 3. Prove & verify
cargo run --release --manifest-path ../../clis/groth16/Cargo.toml -- prove --sparse \
  --circuit privacy_pool.r1cs --witness witness.wtns \
  --proving-key /tmp/pp.pk --out /tmp/pp.proof
cargo run --release --manifest-path ../../clis/groth16/Cargo.toml -- verify \
  --proof /tmp/pp.proof --public /tmp/pp.pub --verifying-key /tmp/pp.vk
# → Verification result: VALID
```

## Nova e2e

```bash
# 1. Compile the step circuit, generate 4 chained limb witnesses
circom privacy_pool_nova.circom --r1cs --wasm --sym --prime bls12381 \
  -l ../RangeProof/node_modules/circomlib/circuits -l ./node_modules/circomlib/circuits
python3 gen_nova_privpool_steps.py --wasm privacy_pool_nova_js/privacy_pool_nova.wasm \
  --depth 4 --dir steps/

# 2. Fold / compress / verify via nova-slim (sibling of bls/)
NOVA=../../nova-slim/cli/target/release/nova-slim
$NOVA fold   --curve bls12-381 --circuit privacy_pool_nova.r1cs --steps steps/ --out pp.ivc.cbor
$NOVA compress --slim --curve bls12-381 --circuit privacy_pool_nova.r1cs --steps steps/ --out pp_slim.proof.cbor
$NOVA verify --curve bls12-381 --ivc pp.ivc.cbor --slim-proof pp_slim.proof.cbor
# → Verified ... state chain OK
```

The folded chain transforms the input note's commitment (leaf) into the
public Merkle root; a terminal constraint in production asserts both that
final state and the range/conservation/non-nullifier checks of the spend.
