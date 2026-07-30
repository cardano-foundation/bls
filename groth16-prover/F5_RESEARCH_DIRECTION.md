# F5 — Shielded Cross-Chain Privacy Pool

> **Research direction for the groth16-prover roadmap**  
> **Status:** ⏳ Under investigation — not yet committed to implementation.  
> **PoC:** [f5.primemodulus.com](https://f5.primemodulus.com/)  
> **Repo:** [github.com/merkle-groot/f5](https://github.com/merkle-groot/f5)
>
> **Architecture context:** The **F5a — Shielded Amounts** section below maps directly to **Step 3** of the selective-disclosure architecture described in [`aiken/selective-disclosure/README.md`](../aiken/selective-disclosure/README.md). Step 3 explains how the F5a circuit composes identity privacy (Step 1) and amount hiding (Step 2) into a complete privacy-pool system on Cardano.

---

## One-sentence summary

A **single privacy pool on Ethereum L1** whose only withdrawal path is a **private cross-chain delivery**. You spend an L1 note, the value bridges canonically to a shielded pool on an L2, and a stealth commitment lands there — so no public address touches the value on either side.

---

## Why this is different from existing privacy pools

| Aspect | Tornado Cash / Privacy Pools | F5 |
|--------|------------------------------|-----|
| **Chains** | One pool per chain | One L1 pool serves **all** L2s |
| **Anonymity set** | Fragmented across N chains | **Single concentrated set** |
| **Withdrawal** | Public address on same chain | **Stealth commitment on destination L2** |
| **Bridge trust** | N/A (single chain) or custom relayers | **Canonical bridges only** |
| **Stealth scheme** | None (or ERC-5564 on-chain ECDSA) | **ZK-native stealth in-circuit** |

---

## How it works (high level)

### Deposit
1. Alice deposits 100 ETH into the **F5 pool** on Ethereum L1.
2. The pool records a **commitment** (a note) in a Merkle tree. The note binds value + nullifier + stealth viewing key.
3. No public address is associated with the deposit — only the commitment root is public.

### Withdrawal (cross-chain)
1. Alice wants to withdraw to **Arbitrum** (or any supported L2).
2. She generates a **Groth16 proof** showing: (a) her note exists in the L1 Merkle tree, (b) she knows the nullifier, (c) she derives a **stealth public key** on the destination L2.
3. The proof is sent via the **canonical L1→L2 bridge**. The bridge only forwards the proof and the commitment — no recipient address is visible.
4. On Arbitrum, a **shielded pool contract** verifies the proof. If valid, it mints a **stealth commitment** (not a direct transfer) that Alice's viewing key can later open.
5. At no point does a public Ethereum or Arbitrum address touch the funds.

### Shielded cross-chain transfer (pay someone privately)
1. Bob publishes a **shielded address** (a viewing key, not a blockchain address).
2. Alice wants to pay Bob 50 ETH on **Optimism**.
3. Alice generates a proof: she spends her own L1 note and derives a stealth commitment **for Bob's viewing key** on Optimism.
4. The proof crosses via canonical bridge. Bob, using his viewing key, scans the shielded pool on Optimism and discovers the commitment meant for him.
5. Bob generates his own proof to spend the stealth note — again, no public address ever appears.

---

## Key innovations

### 1. Destination is a property of the withdrawal, not the deposit

In existing privacy pools, you decide the destination chain **when you deposit** (because each chain has its own pool). In F5, you decide **when you withdraw** — the L1 pool is chain-agnostic. This means:

- **One anonymity set for all chains.** A deposit into the L1 pool contributes to the anonymity of withdrawals on Arbitrum, Optimism, Base, and any future L2 simultaneously.
- **No liquidity fragmentation.** All deposits sit in one contract; the bridge only moves proofs, not value.

### 2. Canonical bridges only — no new trust surface

F5 does **not** introduce:
- Custom relayers
- Multi-sig bridge committees
- Liquidity pools on each L2

It uses **official L1→L2 message passing** (the same canonical bridges that already exist for rollups). The bridge forwards a Groth16 proof and a Merkle root — both are self-evidently valid or invalid. The bridge operators learn nothing.

### 3. ZK-native stealth (non-conformant ERC-5564 on Baby Jubjub)

Standard ERC-5564 stealth addresses work like this:
- Recipient publishes a **spending public key** and a **viewing public key**.
- Sender computes an **ephemeral shared secret** (ECDH), derives a **stealth private key**, and sends funds to the corresponding stealth public key.
- Recipient scans the chain, tries to decrypt each transaction with their viewing key, and discovers which ones are meant for them.
- To spend, the recipient signs a transaction with the stealth private key (ECDSA on secp256k1).

**F5 changes the last step:** instead of signing a transaction with the stealth key, the recipient **opens a Poseidon constraint in a Groth16 circuit**. The stealth key derivation uses **Baby Jubjub** (or Jubjub on BLS12-381 for Cardano), so the entire spend happens inside a zero-knowledge proof. No ECDSA signature ever appears on-chain.

This means:
- The stealth spend key is **never used for on-chain signing** — it exists only inside the circuit.
- The proof attests: "I know the stealth private key that corresponds to this stealth public key, and the Merkle path proves this note was legitimately created."
- The viewing key is only used for **scanning** (off-chain), not for spending.

---

## What would need to happen for groth16-prover

Adapting F5 to Cardano / our stack requires:

| Step | What | How our stack helps |
|------|------|---------------------|
| 1 | Port stealth scheme from Baby Jubjub to **Jubjub** (BLS12-381 native) | Our `circom/EdDSAJubJub/` and `circom/CardanoKeyOwnership/` circuits already implement Jubjub scalar multiplication and point derivation. |
| 2 | Build a Circom circuit proving: (a) **Merkle membership** of L1 note, (b) **stealth key derivation**, (c) valid **bridge message hash** | Our `circom/PoseidonMerkle/` gadget provides Merkle membership (~250 constraints/level). The Ed25519 ownership circuit shows how to derive a public key from a private scalar in-circuit. |
| 3 | Integrate with a **canonical Cardano bridge** | Depends on ecosystem maturity (e.g., Milkomeda, IBC, or future canonical L2s). The proof format is standard Groth16 — any bridge that can pass 192 bytes + public inputs can carry it. |
| 4 | Prove efficiently at scale | The **sparse prover** (Implementation 6) is mandatory. A full F5 circuit (Merkle depth 20 + stealth derivation + bridge hash) would likely exceed 500K constraints. Dense matrices would OOM; sparse keeps memory at O(#non_zero_entries). |
| 5 | Verify on-chain | Our `aiken/groth16` Aiken verifier already validates Groth16 proofs in Plutus V3 scripts. The bridge contract would call `verifier.ak` with the proof + public inputs (Merkle root + stealth public key). |

---

## F5a — Shielded Amounts: Range Proofs + Pedersen Commitments

> **The missing circuit.** F5 as described hides *who* withdraws and *where* the funds go, but it still reveals the **amount** of each deposit and withdrawal on-chain (or forces users into a small set of fixed denominations). For meaningful financial privacy, the transaction value itself must be hidden.

### What we would prove

A **confidential transaction circuit** that extends the F5 spend proof with two additional constraints:

1. **Amount commitment.** Each note commits to its value via a Poseidon hash: `commitment = Poseidon(amount, blinding_factor, nullifier, viewing_key)`. The commitment is what actually sits in the Merkle tree, not the plaintext amount.
2. **Range proof.** When spending a note, the prover shows `amount ∈ [0, 2^n)` using a bitwise decomposition + carry-chain range proof. This prevents negative amounts (inflation) without revealing the exact value.
3. **Conservation of value (in-circuit sum check).** For a transfer that consumes `m` input notes and creates `k` output notes, the circuit proves:
   ```
   sum(input_amounts) == sum(output_amounts) + fee
   ```
   The fee is a public input; the individual amounts remain private.

### Why this is interesting for our stack

| Building block | Already exists in repo | How it composes |
|----------------|----------------------|-----------------|
| **Poseidon hash commitment** | `circom/PoseidonPreimage/` (~300 constraints) | Each note's commitment is a Poseidon pre-image. The same gadget is reused for the Merkle leaf hash. |
| **Merkle membership** | `circom/PoseidonMerkle/` (~250 constraints/level) | The commitment from step 1 is the leaf. Proving membership shows the note was legitimately deposited. |
| **Range proof** | `circom/RangeProof/` (~`n + 250` constraints) | A 64-bit range proof adds only ~314 constraints per note. For two inputs + two outputs, that's <1.3K constraints — negligible compared to the Merkle path. |
| **Field arithmetic sum check** | Native Circom `===` | The in-circuit addition `in1 + in2 == out1 + out2 + fee` is a single linear constraint. |

### Constraint budget (realistic scenario)

| Component | Constraints | Notes |
|-----------|-------------|-------|
| Merkle membership (depth 20) | ~5,000 | One per input note |
| Poseidon commitment (per note) | ~300 | Reused for input + output notes |
| Range proof (64-bit, per note) | ~314 | One per input and output note |
| Conservation sum check | 1 | Linear constraint across 4 note amounts + fee |
| Stealth key derivation | ~50,000 | From existing F5 analysis |
| **Total (2-in / 2-out / depth 20)** | **~65K** | Entirely within dense-prover reach; sparse path handles it in seconds |

### Public vs private inputs

| Direction | Signal | Description |
|-----------|--------|-------------|
| **Public** | `merkle_root` | Current state of the L1 commitment tree |
| **Public** | `output_commitments[k]` | New commitments created by this spend |
| **Public** | `fee` | Network / protocol fee (prevents free withdrawals) |
| **Public** | `nullifier_hash` | Unique identifier marking the input note as spent |
| **Private** | `input_amounts[m]` | Values of the notes being consumed |
| **Private** | `blinding_factors[m+k]` | Random nonces for input and output commitments |
| **Private** | `merkle_paths[m]` | Sibling hashes and indices proving each input note exists |
| **Private** | `stealth_scalar` | Private key used to derive the stealth output address |

### Open question: 64-bit vs 128-bit ranges

Cardano uses **lovelace** (1 ADA = 1,000,000 lovelace). A 64-bit range comfortably covers any plausible transaction (`2^64 lovelace ≈ 1.8 × 10^19 ADA`). A 32-bit range is too small (`≈ 4.3 ADA`). The existing `RangeProof` circuit is parameterised by `n`, so switching from 32 to 64 to 128 bits is only a template parameter change.

### Bottom line for F5a

This circuit turns F5 from a "stealth address mixer" into a true **confidential payment system** where neither the sender, recipient, amount, nor destination chain is visible. The entire proof (Merkle + range + conservation + stealth) is still under ~100K constraints for realistic note configurations — well within the capabilities of our sparse prover. It is the natural next step after proving "I own this key" (`CardanoKeyOwnership`) and "this note exists in a tree" (`PoseidonMerkle`).

**Architecture placement:** In the [`aiken/selective-disclosure`](../aiken/selective-disclosure/README.md) roadmap, F5a is **Step 3** — the composition of identity privacy (Step 1, predicate proofs) and amount hiding (Step 2, Twisted ElGamal) into a single privacy-pool system. The circuit described here is the cryptographic engine; the selective-disclosure document explains the Cardano-specific script architecture (Pool Script, deposit/transfer/withdraw flow, and UTxO lifecycle).

---

## Folding schemes (Nova family) — projection & fit

> **Executive summary:** A common misconception is that Nova / folding schemes "slim down" circuits — i.e., reduce the total number of constraints. They do not. The total algebraic work (constraint count) stays essentially the same, and each folding step adds **~10K–30K overhead constraints** for the Nova verifier logic. The real gains are elsewhere: **elimination of the per-circuit trusted setup**, **per-step memory scaling**, and the ability to handle computations that exceed 10M+ constraints where monolithic Groth16 is infeasible. For our current circuits, the sparse prover (Implementation 6) already solved the memory problem; Nova is only compelling if we need circuits larger than ~4M constraints or want a fully transparent setup.

### What Nova actually does

**Incremental Verifiable Computation (IVC)** splits a computation into a sequence of **step circuits**:

```
state_{i+1} = f(step_i, state_i)
```

Each step is proven independently and **folded** into a running accumulator. The folding operation itself is cheap (a few elliptic-curve additions). At the end, a small **compression SNARK** (e.g., Groth16 over ~100K constraints) proves the accumulator is valid.

| Property | Monolithic Groth16 | Nova IVC |
|----------|-------------------|----------|
| **Total constraints** | C (e.g., 4M) | N × (step_size + overhead) ≈ C + N·overhead |
| **Per-step constraints** | C (all at once) | step_size + ~10K–30K overhead |
| **Trusted setup** | Per-circuit ceremony (SRS size ∝ C) | **None** for folding; one tiny ceremony for compression SNARK |
| **Memory peak** | O(C) — 3 GiB for 4M constraints | O(step_size) — ~50–100 MiB per step |
| **Proving time** | O(C log C) in one batch | O(N · step_size · log step_size) incremental |
| **Proof size** | 192 bytes (Groth16) | ~500 bytes (IVC) + 192 bytes (compression) |
| **Verifier** | One pairing check | Pairing check + IVC accumulator check |

### Why "circuit slimming" is the wrong framing

The total number of field multiplications does not shrink. Consider our Ed25519 signature verification circuit (~4M constraints):

| Component | Monolithic Groth16 | Nova decomposition |
|-----------|-------------------|--------------------|
| SHA-512 (12 rounds) | ~600K constraints | ~100 steps × ~6K constraints/round |
| ScalarMul ·G (base point) | ~1.2M constraints | Hard to decompose incrementally |
| ScalarMul h·A (variable point) | ~1.2M constraints | Hard to decompose incrementally |
| PointAdd, PointCompress, equality | ~1M constraints | Could be folded into steps |
| **Nova overhead per step** | — | ~10K–30K constraints |
| **Total** | ~4M | ~4M + (N × overhead) ≈ **4.5M–5.5M** |

**The constraint count grows, not shrinks.** The benefit is that no single step exceeds ~40K–60K constraints, so:
- The trusted setup is for a tiny ~100K compression circuit (~10–20 seconds) instead of a 4M-constraint monster (~16 minutes).
- Memory per step is ~50 MiB instead of ~3 GiB.
- Proving can be streamed — you fold one SHA-512 round at a time without holding the full 4M witness in RAM.

### Projected gains for our circuits

| Circuit | Monolithic Groth16 | Nova fit | Projected change |
|---------|-------------------|----------|-----------------|
| **SimpleExample (3 constraints)** | 3 | ❌ No | Nova overhead (~10K) exceeds circuit by 3000× |
| **Privacy / Spend (1,107 constraints)** | 1,107 | ❌ No | Sparse prover already handles it in <1s |
| **Poseidon Merkle (737 constraints)** | 737 | ❌ No | Trivial for current stack |
| **Blake2b-224 Preimage (~79K)** | ~79K | ⚠️ Marginal | Sparse prover: ceremony ~18s, prove ~5s. Nova would save setup time but add overhead. Not worth it. |
| **EdDSAJubJub (12,601 constraints)** | 12,601 | ⚠️ Marginal | Ceremony is already ~1s with sparse path. Nova overhead would be ~80% of step size. |
| **CardanoKeyOwnership — JubJub (~4K)** | ~4K | ❌ No | Trivial. |
| **CardanoKeyOwnership — Ed25519 (~1.97M)** | ~1.97M | ⚠️ Hard | Main cost is one scalar multiplication (~1.2M). Not naturally decomposable into steps without redesigning the Montgomery ladder as an incremental state machine. |
| **Ed25519Verify (~4M)** | ~4M | ✅ Yes | Main target. SHA-512 is sequentially foldable. Scalar multiplication could be chunked if rewritten. Ceremony drops from ~16 min to ~10–20 s. Memory drops from ~3 GiB to ~50 MiB/step. |
| **F5a Privacy Pool (~65K)** | ~65K | ❌ No | Nova overhead (10–30K) would be 15–45% of each step. Sparse prover already handles this comfortably. |
| **F5 full depth-32 (~600K)** | ~600K | ⚠️ Maybe | If we need to go deeper (depth 64 → ~1.2M) or add more inputs/outputs, Nova becomes relevant. Currently sparse prover handles ~600K in ~2–3 min. |

### The real bottleneck Nova solves

For our stack, the bottleneck after Implementation 6 (sparse prover) is **not** memory or proving time — it is the **trusted setup ceremony** for large circuits:

| Circuit | Ceremony (monolithic) | Ceremony (Nova compression SNARK) |
|---------|----------------------|-----------------------------------|
| Ed25519Verify (~4M) | ~16 min | ~10–20 s |
| CardanoKeyOwnership (~1.97M) | ~5 min | ~10–20 s |
| Hypothetical 10M circuit | ~1+ hour / impossible | ~10–20 s |

Nova makes the ceremony **circuit-agnostic**: you run the tiny compression SNARK setup once, then use it for any IVC computation. This is the operational gain — not constraint reduction.

### Integration difficulty for Cardano

| Challenge | Severity | Notes |
|-----------|----------|-------|
| **Circuit rewrite** | High | Current Circom circuits are flat R1CS. Nova requires explicit step circuits with state passing. No automatic compiler exists. |
| **On-chain verifier** | High | Aiken would need to verify both the IVC accumulator and the compression SNARK. Our current `aiken/groth16` verifier only handles standard Groth16. |
| **Ecosystem** | Medium | `nova-snark` exists in Rust but integration with Circom-generated R1CS is experimental. Most Nova work uses hand-written circuits. |
| **Nova overhead** | Low–Medium | ~10K–30K per step is acceptable for 40K+ steps; painful for small steps. |

### Verdict: when to adopt Nova

- **Now:** Not needed. Implementation 6 (sparse prover) handles all current circuits. Ceremony times (~5 min for 1.97M, ~16 min for 4M) are acceptable for dev/testnet.
- **Soon:** If we need **recursive proof aggregation** (batching N proofs into one) or **incremental computation** (e.g., streaming Merkle tree updates), Nova is the right tool.
- **Later:** If we design circuits exceeding **10M constraints** (full transaction validation, multi-sig with many parties, rollup state transitions), monolithic Groth16 becomes infeasible and Nova becomes mandatory.

---

## Risk / open questions

1. **Circuit size.** Merkle membership (500K constraints at depth 32) + stealth derivation (~50K constraints) + bridge message validation (~20K constraints) ≈ **~600K constraints total**. This is within sparse-prover reach (~2–3 min prove time), but still large for dev iteration.
2. **Canonical bridge latency.** L1→L2 message passing can take 7 days on optimistic rollups. F5 withdrawals would inherit this delay unless ZK-proof-based fast bridges are used.
3. **Scanning overhead.** Bob must scan every stealth commitment on the destination L2 to find those meant for him. With many users, this requires efficient filtering (e.g., tagged commitments or lightweight ZK filters).
4. **Regulatory.** Privacy pools are under heightened scrutiny. F5 does not solve compliance — it only moves the problem cross-chain. Any production deployment would need withdrawal screening / association-set mechanisms (see Privacy Pools paper).

---

## Bottom line

F5 is the most ambitious privacy direction on the research horizon: a **single, chain-agnostic anonymity set** served by canonical bridges, with **ZK-native stealth** that never exposes a public address. It directly leverages three things our stack already has — Poseidon Merkle gadgets, in-curve key derivation, and a sparse prover for large circuits — while pushing the boundary from "prove ownership of one key" to "privately move value across chains without revealing who owns it."
