# Verifiable Random Functions

### High level description

A Verifiable Random Function (VRF) is a cryptographic primitive that provides a deterministic, verifiable hash output from an input. It is the public-key version of a keyed hash - only the holder of the secret key can compute the hash, but anyone with the public key can verify the correctness of the hash.

**Key properties:**
- **Uniqueness**: For any fixed public key and input, only one valid proof exists for a given hash output
- **Collision resistance**: It is infeasible to find two different inputs that produce the same hash output
- **Pseudorandomness**: The hash output appears random to anyone who doesn't know the secret key

**Use cases:**
- **[Privacy-protected data structures](#privacy-protected-data-structures)**: Prevent enumeration attacks on hash-based data structures (e.g., private UTXO sets in blockchains)
- **[Leader selection](#leader-selection)**: Randomly select leaders in consensus protocols without revealing the winner until after selection
- **[Proof of prior possession](#proof-of-prior-possession)**: Demonstrate knowledge of a secret without revealing it
- **[Non-interactive randomness](#non-interactive-randomness)**: Generate verifiable randomness for lotteries or gaming applications

**Basic workflow:**

Import the library:
```
use vrf/core as vrf
```

1. **Key Generation**: Generate a secret key (SK) and public key (PK) pair
   ```
   (sk, pk) = vrf.keys_from_secret(secret_keying_material)
   ```

2. **Prove**: Compute the proof for a given input
   ```
   pi = vrf.prove(sk, alpha, salt)
   // alpha is the input, salt is encode_to_curve_salt (e.g., "ECVRF_")
   ```

3. **Proof to Hash**: Extract the hash output from the proof (optional)
   ```
   Some(beta) = vrf.proof_to_hash(pi)
   // Returns Some(beta) if proof is valid, None otherwise
   ```

4. **Verify**: Anyone can verify the proof using the public key
   ```
   Some(beta) = vrf.verify(pk, alpha, pi, salt, validate_key_flag)
   // Returns Some(beta) if valid, None if invalid
   ```

The relationship: `VRF_hash(SK, alpha) = VRF_proof_to_hash(VRF_prove(SK, alpha))`

## Proof of Prior Possession

**The problem**: Alice wants to prove to Bob that she knows a secret X (e.g., a password or BLS secret key) without revealing X to Bob, and she wants Bob to be cryptographically certain that Alice possessed X *at the time the proof was created*.

This is harder than it sounds. Several naive approaches fail:

- **Digital signatures**: Alice signs a message with her key. But this only proves she has a signing key, not necessarily that she knows the secret X itself. Malicious signers may use extracted or delegated keys.
- **Password hashes**: Alice sends `hash(X)`. But Bob needs a pre-shared or stored hash to compare against, and the hash itself can be brute-forced or replayed.
- **Challenge-response**: Bob sends a random challenge; Alice responds with `sign(challenge, sk)`. This is interactive (requires a round trip) and still only proves signing capability, not direct possession of X.

**The VRF solution**:
1. Alice derives her VRF key pair directly from the secret: `(sk, pk) = vrf.keys_from_secret(X)`
2. Alice uses the secret itself as the VRF input: `pi = vrf.prove(sk, X, ...)`
3. Alice sends `(pk, pi)` to Bob
4. Bob verifies: `vrf.verify(pk, X, pi, ...)` — if it returns `Some(beta)`, Alice knew X; if `None`, she did not

**How it works**:

| Step | Alice (prover, knows X) | Bob (verifier) |
|------|------------------------|----------------|
| 1 | Derive `(sk, pk)` from secret X | — |
| 2 | Compute `pi = prove(sk, X)` using X as both key and input | — |
| 3 | Send `(pk, pi)` to Bob | Receives `(pk, pi)` |
| 4 | — | Run `verify(pk, X, pi)` |
| 5 | — | If `Some(beta)`, Alice possessed X at proof time |

**Why it works**:
- **Self-binding**: Because the secret X is used both to derive the keypair *and* as the VRF input, the resulting proof is cryptographically bound to that exact secret. A proof computed for `X` cannot verify against a different secret `Y`.
- **Non-extractability**: The proof `pi` does not leak information about `sk` or `X`. Eve can observe `pi` and `pk` but cannot recover the secret.
- **Non-interactivity**: Alice produces the proof in a single message. No challenge round-trip is needed.
- **Time-binding**: The proof demonstrates possession *at creation time*, not just any time. It cannot be forged retroactively.

**Comparison with other approaches**:

| Approach | Reveals secret? | Interactive? | Proves possession of X? | Forgeable without X? |
|----------|-----------------|--------------|------------------------|----------------------|
| Password hash | Partial (leak risk) | No | Yes | If hash is stolen |
| Digital signature | No | No | Indirectly | If key is extracted |
| Challenge-response | No | Yes | Indirectly | If key is extracted |
| **VRF PoPP** | **No** | **No** | **Yes (direct)** | **No** |

**Use cases**:
- **BLS rogue-key prevention**: In multi-signatures, an attacker might forge a public key that cancels out honest signers. Proof of Possession (PoP) — a special case of PoPP — proves the prover knows the secret corresponding to their public key, defeating rogue-key attacks.
- **Passwordless authentication**: A server stores `(pk, last_beta)`. The client proves knowledge of their password-derived key without ever sending the password.
- **Validator key registration**: A blockchain validator registers `pk` on-chain and attaches a PoPP so the protocol knows they actually control the secret key.
- **Credential issuance**: An authority issues a credential only after receiving a PoPP tied to a user-chosen secret, ensuring the user truly knows the secret.

**Example: legitimate prover succeeds**

```aiken
// Alice (prover):
let secret = "my_secret_password"
let (sk, pk) = vrf.keys_from_secret(secret)

// Alice uses the secret itself as the VRF input
let pi = vrf.prove(sk, "my_secret_password", "ECVRF_")

// Alice sends (pk, pi) to Bob
```

**Example: verifier checks the proof**

```aiken
// Bob (verifier):
let pk_from_alice = pk
let pi_from_alice = pi

let result = vrf.verify(pk_from_alice, "my_secret_password", pi_from_alice, "ECVRF_", False)

// result == Some(beta)  -> Alice knew the secret
// result == None        -> Alice did NOT know the secret
```

**Example: adversary with wrong secret fails**

```aiken
// Eve tries to impersonate Alice using the wrong secret
let (sk_eve, pk_eve) = vrf.keys_from_secret("wrong_password")
let pi_eve = vrf.prove(sk_eve, "wrong_password", "ECVRF_")

// Bob verifies using Alice's expected secret
let result = vrf.verify(pk_eve, "my_secret_password", pi_eve, "ECVRF_", False)
// result == None  -> Eve is rejected because the proof was computed
//                    for "wrong_password", not "my_secret_password"
```

**Security properties**:
- **Binding**: The proof is bound to the specific secret used as input. A proof for `X` will not verify against `Y`.
- **Non-extractability**: Observing `(pk, pi)` does not reveal the secret key or the input secret.
- **Non-interactivity**: No challenge-response round trip is required.
- **Unforgeability**: Without knowing `sk` (derived from X), it is computationally infeasible to produce a valid proof that verifies against X.
- **Time-binding**: The proof attests to possession at the moment it was created, preventing retroactive forgery.

See [validators/placeholder.ak](./validators/placeholder.ak) for a working test: `test_proof_of_prior_possession`

## Non-interactive Randomness

**The problem**: Many applications — from online lotteries to blockchain gaming to committee selection — need a source of randomness that is simultaneously:
- **Unpredictable**: Nobody can guess the output in advance
- **Publicly verifiable**: Anyone can confirm the output was generated correctly
- **Non-interactive**: No back-and-forth communication between prover and verifier is needed
- **Deterministic**: The same input always yields the same output, preventing manipulation after the fact

Centralized solutions like the [NIST randomness beacon](https://beacon.nist.gov/home) or the [University of Chile beacon](https://random.uchile.cl/en/about/) provide public randomness, but they are not cryptographically verifiable in a decentralized way and require trusting a single operator. Commit-reveal schemes are interactive and complex. Hashing a secret value (`hash(secret || input)`) is not verifiable because nobody can check the prover actually used the claimed secret.

**The VRF solution**:
1. A trusted operator (or oracle) publishes their public VRF key `pk` in advance
2. For each round, the operator uses a *publicly known input* (e.g., a block hash, round number, or timestamp) as the VRF alpha
3. The operator computes: `beta = vrf.proof_to_hash(vrf.prove(sk, input))`
4. The operator publishes `(input, beta, pi)` — anyone can verify the randomness with just `pk`

**How it works**:

| Step | Operator (knows `sk`) | Verifiers / Public |
|------|----------------------|-------------------|
| 1 | Publish `pk` in advance | Everyone sees `pk` |
| 2 | Wait for a public input (e.g., block hash) | Input becomes known |
| 3 | Compute `beta = proof_to_hash(prove(sk, input))` | — |
| 4 | Publish `(input, beta, pi)` | Everyone receives the triple |
| 5 | — | Run `verify(pk, input, pi)` to confirm `beta` is valid |

**Why it works**:
- **Deterministic yet unpredictable**: Before the public input is known, `beta` is indistinguishable from random to anyone without `sk`. Once the input is fixed, the output is uniquely determined and cannot be changed.
- **Verifiable**: The proof `pi` cryptographically binds the operator's public key to the specific input and output. Anyone can verify this binding without trusting the operator.
- **Non-interactive**: The operator publishes a single message. No challenge-response or multi-round protocol is required.
- **Unbiasable**: Because the input is public and the output is deterministic, the operator cannot grind on inputs to produce a favorable `beta`. They get one shot per input.

**Comparison with other approaches**:

| Approach | Predictable? | Verifiable? | Interactive? | Decentralized? |
|----------|--------------|-------------|--------------|----------------|
| Centralized beacon (NIST) | No | No (trust-based) | No | No |
| Hash of secret + input | No | No | No | No |
| Commit-reveal | No | Yes | Yes (2 rounds) | Partial |
| **VRF randomness** | **No** | **Yes** | **No** | **Can be** |

**Real-world VRF-based randomness beacons**:

- **drand (League of Entropy)**: A distributed randomness beacon originally developed at EPFL's DEDIS lab and now stewarded by Randamu. It uses threshold cryptography and bilinear pairings (BLS12-381) to produce collective, publicly verifiable, unbiased random values at fixed intervals. The League of Entropy includes organizations such as Cloudflare, Protocol Labs, and NIST. Clients can verify each beacon output cryptographically without trusting any single node. Since 2024, drand operates three mainnet networks: a default chained network (30s period), a quicknet unchained network (3s period, compatible with timelock encryption), and an EVM-compatible network using BN254.
- **Chainlink VRF**: A decentralized oracle network that uses VRF to provide on-chain verifiable randomness for smart contracts. Smart contracts request randomness; Chainlink nodes compute the VRF output off-chain and deliver the proof on-chain, where the smart contract verifies it before using the random number.
- **Cardano's Ouroboros Praos**: The protocol uses VRF-based randomness to determine slot leadership unpredictably. While this is a form of leader selection, it is fundamentally a randomness beacon whose outputs are consumed by the consensus protocol itself.

**Use cases**:
- **Lottery draws and gaming**: Use a future block hash as the input so the operator cannot manipulate the outcome. Players can verify the winning numbers after the draw.
- **Card shuffling and dice rolling**: Online casinos can prove each shuffle or roll was fair.
- **Smart contract randomness**: DeFi protocols, NFT mints, and on-chain games can request VRF outputs to assign rarities, select winners, or randomize game states.
- **Committee selection and sortition**: Randomly select a jury, audit committee, or validator set with cryptographically provable fairness.
- **Timelock encryption and e-cash**: VRF outputs can serve as decryption-time oracles or as the basis for unlinkable electronic cash schemes.

**Example: single-round randomness generation**

```aiken
// Operator generates randomness for round 42:
let round_input = "block_12345_hash"
let (sk, pk) = vrf.keys_from_secret(operator_secret)
let pi = vrf.prove(sk, round_input, "ECVRF_")
let Some(beta) = vrf.proof_to_hash(pi)
// beta is a deterministic 32-byte pseudorandom value for this round

// Operator publishes (pk, round_input, beta, pi)

// Anyone can verify:
let Some(beta_verified) = vrf.verify(pk, round_input, pi, "ECVRF_", False)
// beta_verified == beta confirms the operator did not cheat
```

**Example: extracting a fair random number in range [0, N)**

```aiken
// Given a verified beta (32 bytes), convert to an integer and reduce modulo N
let N = 100  // e.g., a 100-sided die
let random_number = bytearray_to_integer(True, beta) % N
// random_number is now in [0, 99]
```

**Example: adversarial operator cannot forge or predict**

```aiken
// Even if the operator is malicious, they cannot:
// 1. Predict beta before the input is known (pseudorandomness)
// 2. Forge a proof for a different beta (uniqueness)
// 3. Change beta after the input is fixed (determinism)

// If an operator tries to publish a tampered proof:
let tampered_pi = tamper_with_proof(pi)
let result = vrf.verify(pk, round_input, tampered_pi, "ECVRF_", False)
// result == None  -> tampered proof is rejected
```

**Security properties**:
- **Unpredictability**: Before the public input is known, `beta` is indistinguishable from random to anyone without `sk`.
- **Verifiability**: Anyone can check `verify(pk, input, pi)` to confirm the output was computed correctly.
- **Determinism**: The same `(sk, input)` always yields the same `beta`, preventing post-hoc manipulation.
- **Uniqueness**: Only one valid `beta` exists per `(pk, input)`, preventing the operator from cherry-picking outcomes.
- **Unbiasability**: The operator cannot grind on inputs because the input is publicly fixed before the VRF is evaluated.

See [validators/placeholder.ak](./validators/placeholder.ak) for a working test: `test_non_interactive_randomness`

## Privacy-Protected Data Structures

**The problem**: When you store data in a hash-based structure (e.g., a Merkle tree or a hash map), using regular hashes like `sha2_256(data)` leaks information. An attacker can enumerate common or expected data inputs, compute their hashes, and check if those positions exist in the public structure. This is called an **enumeration attack** and it compromises the confidentiality of the stored dataset.

**The VRF solution**: Replace regular hashes with VRF hash outputs. Since `beta = VRF_hash(sk, data)` is pseudorandom and unpredictable to anyone without the secret key `sk`, an attacker cannot enumerate or link positions to specific data items. Only the prover (who holds `sk`) can compute the address of a given record. Yet anyone can verify, using the public key, that a claimed `(data, beta)` pair is valid.

**How it works**:

| Step | Prover (knows `sk`) | Verifier (knows `pk`) |
|------|---------------------|-----------------------|
| 1 | Derive `beta = proof_to_hash(prove(sk, data))` | — |
| 2 | Store `(beta, encrypted_payload)` in public structure | Sees the structure but cannot link `beta` to `data` |
| 3 | To reveal membership later, send `(data, proof)` | Run `verify(pk, data, proof)` to get `beta`, then check `beta` is in the structure |

**Why it works**: The VRF output appears random to anyone without the secret key. Without `sk`, an attacker cannot determine which `beta` corresponds to which `data`. Even if the attacker knows the plaintext `data`, they cannot compute its `beta` to test for presence in the structure.

**Use cases**:
- **Private UTXO sets** (blockchains like Cardano): Hide which UTXOs exist on-chain while allowing the owner to spend them by proving membership.
- **Stealth addresses**: A recipient can scan the blockchain for their payments by computing the expected VRF-derived positions, without revealing their viewing key.
- **Confidential databases**: Store records in a public Merkle tree where only authorized parties know which branches contain which data.
- **Privacy-preserving membership proofs**: Prove that a user is on an allow-list without revealing the entire list or the user's exact position.

**Example: storing multiple private records**

```aiken
// Prover (owner of the secret key):
let secret = "prover_secret_key"
let (sk, pk) = vrf.keys_from_secret(secret)

// Private records to store
let record_1 = "alice_payment_100"
let record_2 = "bob_escrow_250"
let record_3 = "charlie_refund_50"

// Only the prover can compute the "address" for each record
let pi_1 = vrf.prove(sk, record_1, "ECVRF_")
let Some(beta_1) = vrf.proof_to_hash(pi_1)
// beta_1 is a 32-byte pseudorandom "address"

let pi_2 = vrf.prove(sk, record_2, "ECVRF_")
let Some(beta_2) = vrf.proof_to_hash(pi_2)

let pi_3 = vrf.prove(sk, record_3, "ECVRF_")
let Some(beta_3) = vrf.proof_to_hash(pi_3)

// Store (beta_i, encrypted_payload_i) in a public Merkle tree or map.
// Outsiders cannot enumerate which records exist because they
// cannot compute beta_i from the record names.
```

**Example: membership proof**

```aiken
// Later, the prover wants to prove that "alice_payment_100" exists.
// The prover sends the verifier:
//   - the original data: "alice_payment_100"
//   - the VRF proof: pi_1
//   - the public key: pk
//   - a Merkle path showing beta_1 is in the tree (omitted here for brevity)

// Verifier checks:
let Some(beta_verified) = vrf.verify(pk, "alice_payment_100", pi_1, "ECVRF_", False)
// beta_verified == beta_1
// Verifier then checks that beta_verified is present in the public structure.
// If both checks pass, the record is proven to exist without ever
// revealing the other records (record_2, record_3) or their positions.
```

**Security properties**:
- **Confidentiality**: Without `sk`, `beta` is indistinguishable from random. An attacker cannot enumerate or link entries.
- **Verifiability**: Anyone with `pk` can verify that a `(data, beta, proof)` triple is valid.
- **Uniqueness**: For a given `pk` and `data`, there is exactly one valid `beta`. This prevents collisions and ensures deterministic addressing.
- **Integrity**: Because the proof binds `data` to `beta`, a malicious prover cannot forge a fake membership proof for arbitrary data.

See [validators/placeholder.ak](./validators/placeholder.ak) for a working test: `test_privacy_protected_data`

## Leader Selection

**The problem**: In Proof-of-Stake blockchains and distributed consensus protocols, a random leader (or set of leaders) must be selected for each round or slot. The selection mechanism must satisfy several critical properties:

- **Unpredictability**: Nobody should be able to predict the next leader in advance
- **Individual secrecy**: Only the selected stakeholder should know they won *before* broadcasting, preventing targeted DDoS or bribery attacks
- **Public verifiability**: Anyone must be able to verify the selection was fair and correct
- **Proportional fairness**: Selection probability should be proportional to each participant's stake or weight

Naive approaches fail:
- Public hash of `hash(stakeholder_id || epoch)` reveals the leader immediately, enabling attacks
- Commit-reveal schemes are interactive, complex, and can be aborted by malicious participants

**The VRF solution**:
1. Each stakeholder registers a public VRF key with the protocol
2. For each epoch/slot, all stakeholders use the *same* public epoch identifier as input
3. Each stakeholder *privately* computes: `beta = vrf.proof_to_hash(vrf.prove(sk, epoch))`
4. If `beta < threshold(stake)`, that stakeholder is selected as leader for that slot
5. Only after producing a block does the stakeholder reveal their proof `(epoch, pi)`
6. The network verifies both the VRF proof validity and the threshold check

**How it works**:

| Step | Stakeholder (knows secret `sk`) | Network / Verifiers |
|------|--------------------------------|---------------------|
| 1 | Compute `beta = proof_to_hash(prove(sk, epoch))` | — |
| 2 | Check if `beta < threshold` (proportional to stake) | — |
| 3 | If selected, privately prepare the next block | — |
| 4 | Broadcast the block together with `(epoch, pi, pk)` | — |
| 5 | — | Verify `vrf.verify(pk, epoch, pi)` returns valid `beta` |
| 6 | — | Confirm `beta < threshold` to confirm leadership |

**Why it works**:
- **Unpredictability**: The VRF output is pseudorandom. Before the epoch number is fixed, `beta` is indistinguishable from random for all stakeholders.
- **Individual secrecy**: Each stakeholder privately computes their own `beta`. No one else can learn whether Alice, Bob, or Charlie was selected until they voluntarily broadcast their proof.
- **Public verifiability**: Once revealed, anyone can run `vrf.verify(pk, epoch, pi)` to confirm the leader legitimately won the slot.
- **Unbiasability**: The epoch input binds the randomness to a specific round. Changing the epoch changes all outputs, preventing grinding attacks.
- **Proportional fairness**: By calibrating thresholds to stake share, a stakeholder with 30% of total stake has roughly a 30% chance of being selected in any given slot.

**Comparison with other approaches**:

| Approach | Predictable? | Secret? | Verifiable? | Interactive? |
|----------|--------------|---------|-------------|--------------|
| Public hash | Yes (everyone knows) | No | Yes | No |
| Commit-reveal | No | Yes | Yes | Yes (2 rounds) |
| **VRF** | No | Yes | Yes | **No** |

**Use cases**:
- **Blockchain consensus** (e.g., Ouroboros Praos in Cardano, Algorand): Slot leaders propose blocks without revealing identity ahead of time
- **Distributed systems leader election**: Randomly pick a coordinator for consensus rounds
- **Proof-of-Stake validation**: Weighted random sampling of validators for committee selection

**Example: multi-stakeholder election**

Consider three stakeholders with different stake weights competing for the same slot:

```aiken
// Shared public input for this consensus slot
let epoch = "epoch_12345_slot_42"

// Alice (30% stake, threshold = max_beta * 0.30)
let (sk_alice, pk_alice) = vrf.keys_from_secret("alice_stake_secret")
let pi_alice = vrf.prove(sk_alice, epoch, "ECVRF_")
let Some(beta_alice) = vrf.proof_to_hash(pi_alice)
let threshold_alice = 3000  // 30% of range

// Bob (50% stake, threshold = max_beta * 0.50)
let (sk_bob, pk_bob) = vrf.keys_from_secret("bob_stake_secret")
let pi_bob = vrf.prove(sk_bob, epoch, "ECVRF_")
let Some(beta_bob) = vrf.proof_to_hash(pi_bob)
let threshold_bob = 5000  // 50% of range

// Charlie (20% stake, threshold = max_beta * 0.20)
let (sk_charlie, pk_charlie) = vrf.keys_from_secret("charlie_stake_secret")
let pi_charlie = vrf.prove(sk_charlie, epoch, "ECVRF_")
let Some(beta_charlie) = vrf.proof_to_hash(pi_charlie)
let threshold_charlie = 2000  // 20% of range

// Each stakeholder privately checks their own result
let is_alice_leader = bytearray_to_integer(True, beta_alice) < threshold_alice
let is_bob_leader = bytearray_to_integer(True, beta_bob) < threshold_bob
let is_charlie_leader = bytearray_to_integer(True, beta_charlie) < threshold_charlie
```

**Example: verifying a claimed leader**

```aiken
// The network receives Bob's claim that he is the slot leader.
// Bob broadcasts: (pk_bob, epoch, pi_bob)

// Any validator on the network can verify:
let Some(beta_verified) = vrf.verify(pk_bob, epoch, pi_bob, "ECVRF_", False)

// Confirm the threshold check
let is_valid_leader = bytearray_to_integer(True, beta_verified) < threshold_bob

// If is_valid_leader is True, Bob legitimately won the slot.
// If False, Bob's claim is rejected.
```

**Security properties**:
- **Unpredictability**: Nobody can predict who wins a future slot because the VRF output is pseudorandom until the epoch is known.
- **Individual secrecy**: Only Bob knows he is the leader until he broadcasts. This protects against pre-slot DDoS and bribery.
- **Public verifiability**: Once Bob reveals `pi_bob`, anyone can verify his leadership claim cryptographically.
- **Unbiasability**: The epoch binds all outputs to a specific slot. An attacker cannot grind on inputs to manipulate selection.
- **Proportional fairness**: Thresholds are set in proportion to stake, ensuring no minority stakeholder can dominate.

See [validators/placeholder.ak](./validators/placeholder.ak) for a working test: `test_leader_selection`

## Notes on lib/core.ak implementation

VRF is standarized in [standard](https://www.rfc-editor.org/rfc/rfc9381.html#name-vrf-algorithms).

What is important we have standarized for [RSA](https://www.rfc-editor.org/rfc/rfc9381.html#name-rsa-full-domain-hash-vrf-rs) and [elliptic curves](https://www.rfc-editor.org/rfc/rfc9381.html#name-elliptic-curve-vrf-ecvrf).
In elliptic curves BLS12-381 is not present. Here we show that **we CAN implement VRF using aiken bls12-381 primitives** and how it could be implemented.

## Building and testing

```sh
aiken check
```

## Resources on Aiken

Find more on the [Aiken's user manual](https://aiken-lang.org).

