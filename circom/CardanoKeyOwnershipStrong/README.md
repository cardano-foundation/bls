# CardanoKeyOwnershipStrong — full CIP-1852 CKD chain (HMAC-SHA512) ownership

## Idea

`CardanoKeyOwnership` proves knowledge of a private Ed25519 scalar `sk` such that
the public key `A = [sk]·G` matches a given compressed key: **"you own this
specific payment key `A`"**. The key derivation itself happens *outside* the
circuit — the statement *"`sk` is the payment key of *this* wallet*"* is taken as
given and is never checked.

`CardanoKeyOwnershipStrong` moves the **entire wallet derivation inside the
circuit**. The prover shows knowledge of the **96-byte master signing key
(`XPrv`)** that derives — via the CIP-1852 / BIP32 child-key derivation (CKD)
chain `m/1852H/1815H/0H/0/0`, computed with HMAC-SHA512 — the Cardano payment
key whose compressed public key is the public value `A`. The circuit itself
performs, per step:

1. the **HMAC-SHA512 CKD** of the *hardened* branch (key from `0x00 ‖ kL‖kR‖idx`,
   chain code from `0x01 ‖ kL‖kR‖idx`) and of the *soft* branch (key from
   `0x02 ‖ Apub‖idx`, chain code from `0x03 ‖ Apub‖idx`) on the current
   `kL‖kR‖cc` state,
2. a **mod-2^256 addition** of the child `kL` value,
3. the **Ed25519 public key** of the derived child key in-circuit
   (`Ed25519Pub256`, scalar reduced mod the subgroup order `n` first), and
4. selection of the derived branch / public key for the 1024-bit state and
   256-bit public-key outputs.

The Nova step-circuit is one *uniform* step handling every derivation type
(seed, hardened, soft, final) selected by a private 2-bit `op` input, so the
**same step is folded 6 times** for the full path.

> **Fixture / golden output.** `master = bytes(range(96))` at
> `m/1852H/1815H/0H/0/0` produces the payment public key
> `A = 63658c2ec89f2fc978bd99c4ee00c6057d6a5b0baa29dc9d62beb4c5e511862c`,
> which matches `cardano-address` exactly. The 6-step Nova chain reproduces this
> `A` on the last step (`final apk == A`).

### Why not just use `CardanoKeyOwnership`?

`CardanoKeyOwnership` answers *"do you own this key `A`?"* — it leaves *"is `A`
actually derived from your root?"* to the caller. A prover could submit *any*
key pair (`sk`, `A`) it generated on the spot; nothing binds `A` to a wallet the
verifier cares about, so the ownership decision is only as strong as the
off-circuit key derivation and the list the verifier keeps.

The strong version proves the **seed-to-key link itself**: the private input is
the 96-byte `XPrv` (not a detached `sk`), and the circuit derives the payment
key at the full CIP-1852 path. The verifier still stores only the final
compressed key `A`, but now `A` is *provably* the payment key of the master seed
the prover knows. This is the natural statement for

- **cold-storage / wallet-level ownership**, where the root seed is the real
  asset and payment keys are disposable derivatives,
- **hardware-wallet custody proofs** (the seed never leaves the device; only
  the derivation is proven),
- **recovery / key-rotation flows**, where a root must be proven to control the
  current on-chain key without exposing any intermediate key.

### Drawbacks

- **HMAC-SHA512 is expensive in-circuit.** Each step instantiates *both* CKD
  branches (hardened 552-bit and soft 296-bit HMACs) to keep the step shape
  constant, plus a full Ed25519 scalar multiplication per step. Result: a
  **5.93M-constraint step / 15.8M-constraint monolith** — ~8× the
  `CardanoKeyOwnership` monolith, ~770× the 7.7K-step `cko`/`smt` chains.
- **Monolithic Groth16 is infeasible on the measurement host** (`pure`, Intel Core i7-7500U @ 2.70 GHz, 2C/4T, 32 GiB RAM). The one-time ceremony
  peaks at **29.1 GiB RSS** (dense) and was
  OOM-killed; the sparse run also died. Only the **Nova step-chain** path is
  practical on this host — and it is slow (see [Benchmarks](#benchmarks--pre-nova-vs-nova)).
- **Point compression stays outside.** As in the other families, `PointCompress`
  and `addOut == 2·PointA` style checks are done outside the fold; the circuit
  outputs the 256-bit `apk` field points.
- **Step-wise apk recomputation is deliberate but costly.** Every step re-derives
  the child public key so the chain state is self-contained; an
  apk-last-step-only design would cut the step size but break the uniform
  step-width IVC constraint.

### Workflow — the 6-step chain

| Step | `op` | Derivation | State in → out (`kL‖kR‖cc` + `apk`) |
|------|------|-----------|--------------------------------------|
| 0 | `00` seed | `kL‖kR‖cc = master` (96 B), derive **1852H** | master → child(1852H) |
| 1 | `10` hard | derive **1815H** | → child(1815H) |
| 2 | `10` hard | derive **0H** (account) | → child(0H) |
| 3 | `01` soft | derive **0** (role, external) | → child(0, soft) |
| 4 | `01` soft | derive **0** (address index) | → final payment key |
| 5 | `11` final | zero `kL‖kR‖cc`, pass through | → `apk = A` |

The generator (`gen_strong_nova_steps.py`) walks the BIP32-style python model
for the same path, reduces the Ed25519 scalar mod `n` before the pubkey multiply
(matching real libraries), and checks each step witness against the circuit
outputs before writing it.

---

## End-to-end flow — Nova step-chain (Implementation 10, transparent)

The strong family runs as a **NIFS fold + sumcheck compression** chain
(Implementation 10): no ceremony, no proving/verifying key. The step circuit is
compiled once; the 6 step witnesses are generated per (master, path) input; the
fold merges them into one relaxed instance; the sumcheck argument compresses it.

```bash
# binary: ../../clis/nova/target/release/nova (used as `nova` below)
# 1. Compile the uniform step circuit (once; O1 keeps the 5.93M-constraint size small)
circom CardanoKeyOwnershipStrong/cardano_ed25519_ownership_strong_nova.circom \
  --r1cs --sym --wasm -o <build> \
  -l CardanoKeyOwnershipStrong -l CardanoKeyOwnershipStrong/sha512
# → non-linear 4,606,999 + linear 1,326,765 = 5,933,764 constraints
# → public inputs 1024, private inputs 802

# 2. Generate the 6 step witnesses from the fixed master fixture
python3 CardanoKeyOwnershipStrong/gen_strong_nova_steps.py \
  --wasm <build>/cardano_ed25519_ownership_strong_nova_js/cardano_ed25519_ownership_strong_nova.wasm \
  --dir <steps> --snarkjs snarkjs
# → step 0..5: OK; wrote 6 step witnesses (final apk == A)

# 3. NIFS fold (single relaxed instance; no proving key)
nova fold --nifs --circuit <build>/cardano_ed25519_ownership_strong_nova.r1cs \
  --steps <steps> --out strong_ivc.json
# → NIFS bundle written (6 steps → one instance)

# 4. Compress with a transparent sumcheck (re-folds deterministically)
nova compress --circuit <build>/cardano_ed25519_ownership_strong_nova.r1cs \
  --steps <steps> --out strong_sumcheck.proof

# 5. Verify (no verifying key)
nova verify --ivc strong_ivc.json --sumcheck-proof strong_sumcheck.proof
# → Verified 6 steps: sumcheck compression proof OK, commitments OK, state chain OK
```

## End-to-end flow — real wallet via `cardano-address` (Impl 10)

The **practical** route for this family is the Nova step-chain (Implementation
10) — the monolithic Groth16 ceremony is infeasible on the measurement host.
The full loop below was run against a **real `cardano-address` wallet** (v4.0.0)
generated on the same host:

```bash
# 1a. Wallet key material (cardano-address handles the BIP39 phrase)
cardano-address recovery-phrase generate --size 15 \
  | cardano-address from-recovery-phrase Shelley > root.xsk
cardano-address key child 1852H/1815H/0H/0/0 < root.xsk > pay.xsk
cardano-address key public --without-chain-code < pay.xsk > pay.vk
cat pay.vk      # addr_vk1… (32-byte compressed Ed25519 payload)

# 1b. Master XPrv for the circuit = extended_key ‖ chain_code (96 bytes)
MASTER_HEX=$(cardano-address key inspect < root.xsk \
  | jq -r '"\(.extended_key)\(.chain_code)"')

# 2. 6 step witnesses (model is cross-checked against the circuit before writing)
python3 CardanoKeyOwnershipStrong/gen_strong_nova_steps.py \
  --wasm <build>/cardano_ed25519_ownership_strong_nova_js/cardano_ed25519_ownership_strong_nova.wasm \
  --master-hex "$MASTER_HEX" --path 1852H/1815H/0H/0/0 --dir <steps> --snarkjs snarkjs
# → step 0..5: OK; wrote 6 step witnesses (final apk == A)

# 3. Transparent Nova chain (no trusted setup, no keys)
nova fold --nifs --circuit <build>/cardano_ed25519_ownership_strong_nova.r1cs \
  --steps <steps> --out strong_ivc.json
nova compress --circuit <build>/cardano_ed25519_ownership_strong_nova.r1cs \
  --steps <steps> --out strong_sumcheck.proof
nova verify --ivc strong_ivc.json --sumcheck-proof strong_sumcheck.proof
# → Verified 6 steps: sumcheck compression proof OK, commitments OK, state chain OK

# 4. Cross-check: the last step's apk must equal the wallet's own public key
python3 - <<'EOF'
import struct
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
rest = open("pay.vk").read().strip().partition("1")[2]
acc = bits = 0; out = []
for c in rest:
    acc = (acc << 5) | CHARSET.index(c); bits += 5
    if bits >= 8: bits -= 8; out.append((acc >> bits) & 0xff)
payload = bytes(out)[:32]                      # drop the 4-byte bech32 checksum
d = open("<steps>/step_0005.wtns", "rb").read()
n8, = struct.unpack_from("<I", d, 24); nw, = struct.unpack_from("<I", d, 28 + n8)
off = 28 + n8 + 16
w = [int.from_bytes(d[off + 32*i: off + 32*(i+1)], "little") for i in range(nw)]
apk = bytes(sum(int(w[769 + 8*i + j]) << j for j in range(8)) for i in range(32))
assert apk == payload, "wallet public key mismatch!"
print("final apk == addr_vk payload:", apk.hex())
EOF
```

Measured on host **`pure` (Intel Core i7-7500U @ 2.70 GHz, 2C/4T, 32 GiB RAM)** the
loop produced — for the example wallet with

```text
MASTER_HEX  = 90aa88529362e0f8…c9ace cf33cd8348cbe989…51562d   (extended_key ‖ chain_code)
addr_vk     = 20dcb296a836dc05573cf5f5726be7f581b463b2564b2a0275f72f9c4edb1857
```

— all 6 step witnesses valid and **`final apk == A ==` the `addr_vk` payload,
byte-for-byte**. Note the circuit's `apk` and the wallet's compressed public key
share the same byte order, so the 32-byte comparison is direct (`==`, no
endianness flip). This is the exact soundness target of the case: the seed-only
proof reproduces the wallet's own payment key in-circuit.

## End-to-end flow — monolithic Groth16 (Implementation 7; infeasible here)

The monolith `cardano_ed25519_ownership_strong.circom` folds the whole path into
one circuit with public inputs `[A, purpose, coinType, accountIx, roleIdx,
addrIdx]`. Its witness IS computable on the measurement host `pure` (2 min 15 s,
1.9 GiB, see benchmarks); the Groth16 **ceremony is not** (30.5 GiB peak RSS vs
32 GiB installed), so it is documented but not run end-to-end here.

```bash
# witness (Feasible): ~2 min 15 s, 1.9 GiB peak, 503 MB wtns, 15.8M constraints
# ceremony (Infeasible on the 32 GiB host):
../../clis/trusted-setup/target/release/trusted-setup ceremony-dev --sparse --h-scalar \
  --circuit cardano_ed25519_ownership_strong.r1cs \
  --proving-key strong.pk --verifying-key strong.vk
# → dense run peaked 29.1 GiB RSS and was OOM-killed; the sparse run died too.
```

---

## Benchmarks — pre-Nova vs Nova

Measured 2026-09-10 on host **`pure` — Intel Core i7-7500U @ 2.70 GHz (2C/4T), 32 GiB RAM, Debian 12**, single runs, `snarkjs`
for witness generation, `nova` release binary (single-core, no `--opt parallel`).

| Phase | Prior Nova (step-chain, Impl 10) | Monolithic Groth16 (Impl 7) |
|---|---|---|
| circuit | 6 × 5,933,764 constraints (5,910,830 wires, 980,739,856 B (≈936 MiB) r1cs) | 15,806,867 constraints (15,734,799 wires, 2.58 GiB r1cs) |
| inputs | 1024 public in/out, 802 private (768 master + 2 op + 32 idx) | 1 out + 416 in public, 768 private |
| witness generation | 6 steps ≈ ~2 min each | 2 min 15 s / 1.9 GiB |
| ceremony (one-time, reusable) | **none** (transparent) | **infeasible** — dense 29.1 GiB RSS → OOM; sparse died |
| prove / fold | **≈ 18,700 s** (≈ 5.2 h, 6 steps) | — |
| compress | ≈ still running (not yet measured) | — |
| verify | ≈ still running (not yet measured) | — |
| proving key | none | — |
| verifying key | none | — |

Readings:

- **The chain is only practical as a Nova step-chain.** The 6 × 5.93M-constraint
  fold is transparent (no ceremony, no keys — strong is the case where the
  ceremony savings matter most) but heavy: **≈ 18,700 s, dominated by a ~4 h
  single-core cold-start MSM set-up** for the first fold; the marginal later
  steps folded in ~5–7 min each.
- **Monolithic Groth16 is out of reach on 32 GiB** — the ceremony alone needs
  ≳29 GiB. This is the circuit where *decomposition isn't optional*.

### How the strong family compares with the other `CardanoKeyOwnership*` families

Same machine, measured numbers. `cko`/`smt` run 255 × 7,724-constraint steps;
`strong` runs 6 × 5,933,764-constraint steps.

| Metric | CardanoKeyOwnership (`cko`) | CardanoKeyOwnershipSMT (`smt`) | CardanoKeyOwnershipStrong (`strong`) |
|---|---|---|---|
| Statement | own one payment key `A = [sk]·G` | own `A` **and** `A ∈` SMT root registry | master seed derives `A` at `m/1852H/1815H/0H/0/0` |
| Monolith size | 1,967,405 cstr (~1.97M) | 1,971,079 cstr | **15,806,867 cstr (~8.0×)** |
| Step circuit | 7,724 cstr | 7,724 cstr (same r1cs hash) | **5,933,764 cstr (~768×)** |
| Steps | 255 | 255 | 6 |
| Step witness | ~0.5 s each | ~0.5 s each | ~2 min each |
| Nova Impl 10 fold | **152.8 s** (~0.6 s/step) | **150.3 s** | **≈ 18,700 s** (≈ 3,100 s/step nominal) |
| Nova Impl 10 verify | 27.2 s | 25.4 s | pending (compress still running) |
| NovaSlim | fold 152.5 s, verify **0.025 s**, proof **721 B** | same shape | not yet run |
| Sumcheck bundle (Impl 10) | 686,929 B | 686,929 B | ivc bundle 179,775 B (proof pending) |
| Monolithic ceremony | ≈ 19.5 min (pk 1.32 GB, vk 178 MB) | ≈ 19.5 min | **infeasible** (29.1 GiB RSS OOM) |
| Monolithic prove / verify | ≈ 2.5 min / ≈ 3.5 s | same | — |

Readings:

- **Statement strength ↑, cost ↑ sharply.** Adding the derivation chain costs
  ~8× the monolith and ~770× the per-step width; per-step fold cost scales
  accordingly (~3,100 s vs ~0.6 s nominal).
- **`strong` is 6 steps vs 255** — so even at ~5,000× per-step fold cost, the
  *total* fold is "only" ~120× (`~5.2 h` vs `~2.5 min`), and both beat their own
  monolithic ceremony (which `strong` cannot even run).
- **The fold's cold-start dominates.** A ~4 h one-time MSM set-up makes the
  first fold expensive for *any* strong input; amortized per-wallet and with
  `nova fold --opt parallel` (rayon over 4 cores) the steady-state estimate is
  far better — but the honest single-core Impl 10 number is recorded above.
- **`strong` is where Nova's transparency matters most**: `cko`/`smt` pay only
  ~3–6 s of ceremony; `strong` would have *no viable ceremony at all* in
  Groth16, so the NIFS/sumcheck path is the only option on host `pure`.

---

## Design

### Circuit Structure

```
cardano_ed25519_ownership_strong_nova.circom   main = CardanoKeyOwnershipStrongStep
├─ modn.circom        ModN256          reduce 256-bit LE scalar mod n (2^252+27742317777372353535851937790883648493)
├─ ed25519_pub.circom Ed25519Pub256    [kL mod n]·G → apk (ChunkedMul fixed-base)
├─ ckd_cardano.circom 
│  ├─ CkdHardened     HMAC-SHA512 CKD, hardened (0x00 · kL‖kR‖cc) → nkL‖nkR‖ncc
│  ├─ CkdSoft         soft branch (0x01 · kL‖kR‖cc) + child apk recomputation
│  └─ BinSumAlt / LEAdd256   binary carry-adders (mod 2^256)
│  └─ Endianness        byte/bit reversal + 3-bit shift (Mul8L224/Mul8L48), ZVec LE256z
├─ sha512 / sha512core.circom / sha512F.circom   fused register-rolling SHA-512 core
└─ Ed25519Verify/scalarmul.circom + pointcompress.circom   fixed-base mult, apk = [kL]G
```

Uniform step template (constant across all 6 folds):

1. `op[2]` selects `seedSel / hardSel / softSel / finalSel` (`op[i]·(1-op[i]) === 0`).
2. Seed step sources `kL‖kR‖cc` from the private `master[768]`; otherwise the
   public state `kLIn‖kRIn‖ccIn` is used.
3. Both `CkdHardened` and `CkdSoft` run on the chosen key material (constant
   shape), each padding its HMAC to a fixed width (552-bit hardened / 296-bit
   soft).
4. `selK/selR/selC = h.branch + softSel·(s.branch − h.branch)` selects the
   derived child key (soft mode subtracts to stay single-product per r1cs row).
5. `modn` reduces `selK` mod the ed25519 subgroup order; `Ed25519Pub256` computes
   the child public key `apk`.
6. Final step (`op = 11`) zeroes `kL‖kR‖cc` and passes through `apkIn`; all other
   steps output the child state and child `apk`.

### Input/Output Specification

**Step circuit public (1024 in / 1024 out):** `kLIn[256] ‖ kRIn[256] ‖ ccIn[256]
‖ apkIn[256]` on the input side and the same 1024-bit state plus `apk` on the
output side (`n_pub_out == n_pub_in`, required by the IVC invariant).

**Step circuit private (802):** `master[768]` (the 96-byte `XPrv`), `op[2]`
(derivation selector), `idx[32]` (the 31-bit child index).

**Fixture `strong_in.json`:** the fixed master bytes are `range(96)`, i.e.
`000102…5f` little-endian, path `1852H/1815H/0H/0/0` -> pub
`63658c2ec89f2fc978bd99c4ee00c6057d6a5b0baa29dc9d62beb4c5e511862c`.

### File Layout

```
CardanoKeyOwnershipStrong/
├─ cardano_ed25519_ownership_strong.circom     monolithic all-in-one circuit (Impl 7)
├─ cardano_ed25519_ownership_strong_nova.circom uniform 6-step Nova circuit (Impl 10)
├─ gen_strong_nova_steps.py                    generates the 6 step witnesses + model check
├─ modn.circom                                 ModN256 — scalar reduction mod n
├─ ckd_cardano.circom                          CkdHardened / CkdSoft / LEAdd256 / endianness
├─ ed25519_pub.circom                          Ed25519Pub256 = [kL mod n]·G → apk
├─ binsum_alt.circom                           binary full-adder / N2B3 (signal-based)
├─ sha512core.circom sha512F.circom sha512/    fused SHA-512 core used by both HMAC branches
```

### Dependencies

| Include | Used by |
|---|---|
| `ckd_cardano.circom` | CKD branches, adders, endianness |
| `binsum_alt.circom` | `FullAdder` / `N2B3` (hint binary decomposition) |
| `sha512F.circom`, `sha512core.circom`, `sha512/` | HMAC-SHA512 pads + fused 512-bit core |
| `Ed25519Verify/scalarmul.circom` (+ `pointcompress.circom`) | fixed-base `ChunkedMul`, `Ed25519Pub256` |
| `modn.circom` | scalar mod `n` before the point multiply |

### Derivation semantics (why the numbers line up)

- Child keys are **summed mod 2^256** (`LEAdd256`), exactly like the reference
  Icarus/Cardano HD wallet wrappers.
- The child **chain code is the right half** of a dedicated HMAC-SHA512
  (`ncc = HMAC(cc, 0x01‖kL‖kR‖idx)[32:]` hardened, `0x03‖Apub‖idx` soft),
  matching what `gen_strong_nova_steps.py` re-derives from
  `cardano-address`'s `extended_key ‖ chain_code`.
- Every real Ed25519 library reduces the scalar **mod the subgroup order
  `n = 2^252 + 27742317777372353535851937790883648493`** before `[k]·G`; the
  in-circuit `ModN256` reproduces that (constant `m = 2^256 − n` added to
  `s[0]`), so `Ed25519Pub256` receives a reduced scalar and never sees the
  "non-binary" limb values the fixed-base mul asserts against.
- The fixture master key, its derived intermediates, and the regenerated model
  use this reduced-pubkey semantics end to end; the golden `A` is preserved.

### Security Considerations

- **Soundness of the chain:** the Nova IVC binds initial state + final instance
  (+ transcript) in one relaxed R1CS; the verifier sees only the final `apk` and
  the public key `kLIn‖kRIn‖ccIn‖apkIn` per step. The private `master`, `op`, and
  `idx` never leave the fold.
- **Uniformity is the honesty condition:** both CKD branches are always computed
  and `op`/`idx` are validated (`op[i]·(1-op[i]) === 0`, 31-bit index), so a soft
  step cannot masquerade as hardened and vice versa.
- **The seed is the whole wallet**: compromise of `master` recovers every
  descendant key in one step; keep the seed in a hardware/HSM boundary and prove
  only the derived `A` on-chain.
- **The final `apk` equality is checked outside the fold** (as with the other
  families); the circuit proves derivation-integrity and key-ownership, not
  address encodings (bech32/base58, point compression).

---

## Comparison with Existing Approaches

- **In-repo families:** `cko` = single detached key, `smt` = key *set*
  membership via Merkle root. `strong` replaces the "trust me, this is the
  wallet's key" step by proving the root-seed → payment-key link in-circuit. It
  is 8× the monolith and ~770× the step width of the other two — the steepest
  statement-vs-cost trade-off in the `CardanoKeyOwnership*` family.
- **Monolithic Groth16 vs Nova:** Groth16 is unviable for `strong` on this
  machine (ceremony ≥29 GiB / OOM). Nova is the only feasible route, and even
  there the 6-step fold takes ~5.2 h single-core — the honest data point that
  circuit decomposition (multi-step / `--opt parallel` / another folding layer)
  is the *required* next step for real deployments, not publishable
  convenience.
- **Standalone tools:** `cardano-address` (reference derivation) is used only to
  confirm the golden fixture; derivation, CKD, and pubkey are reproduced
  inside the circuit and re-checked by the python BIP32-style model
  (`gen_strong_nova_steps.py`) before any witness is written.

## References

- CIP-1852 — Cardano hierarchical deterministic wallet keys (1852H/1815H/0H…).
- BIP-32 / BIP-44 child-key derivation (HMAC-SHA512 CKD).
- RFC 8032 Ed25519; the ed25519 subgroup order `n = 2^252 + 27742317777372353535851937790883648493`.
- Nova (Kothapalli, Setty, Tzialla) — NIFS folding + sumcheck compression (Implementation 10 in this repo).

## License

Same as the rest of the repository.