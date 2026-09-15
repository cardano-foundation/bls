# Groth16 from first principles — Installment 2: Optimizations and the trusted-setup ceremony

> **Installment 2 of 5.** In [Installment 1](zkp-from-first-principles.md) we built the entire Groth16 pipeline from first principles: R1CS → QAP → trusted setup → proof → pairing check, walking a tiny 5-constraint `SumOfProducts` circuit through 16 printable binaries. Along the way we deliberately leaned on the *dev* ceremony — fixed, deterministic scalars — so that every intermediate value is reproducible.
>
> The dev pipeline is correct, but it is also **slow, memory-hungry, single-party, and capped at 14 constraints**. This installment replaces each bottleneck with a production technique, and it does so the way the codebase actually grew: **one implementation at a time**, from the monomial baseline (Implementation 1) through the FFT engine (2), Pippenger MSM (3), the Circom adapter (4), on-the-fly QAP (5), sparse matrices (6), and h-query compression (7). Each section explains the bottleneck in plain words, shows the fix, and then hands you the exact CLI commands to see the difference for yourself — with real before/after numbers.
>
> After the sprint we turn to the production **trusted-setup ceremony** — why the scalars must be secret, how a known `τ` becomes a forgery factory, and how a multi-party MPC ceremony keeps `τ` unknown forever (this part is already written below). We close by surveying the landscape beyond Groth16 and where this stack goes next.
>
> We're writing this document the same way we built the code: **section by section.** Right now you're reading through Implementations 2 and 3 in full; Implementations 4–7 appear in a later pass. Each section is self-contained, so you can jump in anywhere.

---

## Table of Contents

**Part One — the optimization sprint**

- [How to follow along](#how-to-follow-along)
- [The baseline: Implementation 1 — dense monomial](#the-baseline-implementation-1--dense-monomial)
- [The optimization sprint](#the-optimization-sprint)
- [Implementation 2 — FFT: polynomial arithmetic, O(n²) → O(n log n)](#implementation-2--fft)
  - [A first real circuit: Poseidon](#a-first-real-circuit-poseidon)
  - [Try it on a slightly bigger circuit](#try-it-on-a-slightly-bigger-circuit)
- [Implementation 3 — Pippenger MSM](#implementation-3--pippenger-msm)
- [Implementations 4–7 (to be written)](#implementations-47-to-be-written)

**Part Two — the trusted-setup ceremony**

- [The trusted-setup ceremony](#the-trusted-setup-ceremony)
  - [Why the scalars must be secret and random](#why-the-scalars-must-be-secret-and-random)
  - [The scalars and who must not know them](#the-scalars-and-who-must-not-know-them)
  - [The ceremony in our repository](#the-ceremony-in-our-repository)

- [What's next in this installment](#whats-next-in-this-installment)

---

## How to follow along

Everything runs from the existing repository. You need:

- **Rust** (stable) for the two CLIs and the `groth16-prover` binaries.
- **circom** and **snarkjs** — but only if you want to compile a circuit yourself. For most of this tutorial the circuit is already compiled, so this is optional.

Three crates, three jobs:

| Where | What it is | What you'll run |
|-------|-----------|-----------------|
| `groth16-prover/` | The library + the didactic binaries | `benchmark_provers`, `print_qap_engines`, and friends |
| `clis/trusted-setup/` | The ceremony CLI (`trusted-setup`) | `ceremony-dev`, later `phase2` |
| `clis/groth16/` | The proving CLI (`groth16`) | `prove`, `verify`, `export-vk` |

Build them once, up front (a few minutes with `--release`):

```bash
cd groth16-prover && cargo build --release --features bins
cd clis/trusted-setup   && cargo build --release
cd clis/groth16         && cargo build --release
```

The tutorial circuit is the same 5-constraint `SumOfProducts` we met in Installment 1 — you'll find it (already compiled, plus a ready witness) in the repo:

```bash
cd circom/SumOfProducts
ls           # input.json, sum_of_products.r1cs, witness.wtns, ...
```

From here on, "your terminal" means `cd`'d to the directory shown in each snippet. If you prefer to see every intermediate quantity, keep the `print_*` binaries from Installment 1 handy — do **not** delete that `groth16-prover/target` directory, or you'll have to rebuild it.

> **A note on numbers.** Times in this document come from two sources: the reference benchmark tables in `groth16-prover/README.md`, and measurements taken on a mid-range laptop. Absolute numbers will differ on your machine — what matters are the *shapes*: which configurations are faster, and *why*. We'll always tell you which is which.

---

## The baseline: Implementation 1 — dense monomial

Installment 1 shipped a working prover we here call **Implementation 1**: the `DenseQapEngine` (every polynomial is a plain coefficient vector, built by *Lagrange interpolation* at the constraint points) driving the `NaiveProver` (every group operation one point at a time). Nothing about it is wrong. It just doesn't *scale*.

Three things are expensive, and each bites harder as the circuit grows:

1. **QAP construction is O(n²).** To build a single `u_s(x)` we solve a Lagrange interpolation over `n` constraint points — and we do that for every one of the `m` wires. Building the whole QAP is `O(n · m)` field operations. For 5 constraints that's nothing. For 79,000 (a Blake2b-224 hash) it's billions. For 4 million (an Ed25519 signature) it's effectively impossible.

2. **Polynomial arithmetic is O(n²).** Multiplying `l(x) · r(x)` with schoolbook (dense) multiplication is quadratic in the degree. Dividing `l·r − o` by the target polynomial is long division — also quadratic. The quotient `h(x)` alone, for a 4-million-constraint circuit, would take roughly 16 *trillion* field multiplications.

3. **Proof assembly is O(n) scalar-multiplies.** Each commitment `A, B, C` is built by adding up hundreds of thousands of curve points, one scalar multiplication at a time — the `NaiveProver` never batches.

The first two are what Implementation 2 attacks. The third waits for Implementation 3.

There's a fourth, humiliating ceiling that makes the point without any math: **the dense engine refuses to build a QAP for more than 14 constraints.**

```rust
// clis/trusted-setup/src/engine.rs — DenseQapEngine::build_qap
assert!(n_constraints >= 1 && n_constraints <= 14,
    "DenseQapEngine supports 1-14 constraints, got {}", n_constraints);
```

Try it yourself — point the dense engine at a real circuit:

```bash
cd circom/PoseidonMerkle
groth16 prove --circuit poseidon_merkle_depth2.r1cs \
              --witness witness.wtns \
              --engine dense --out /tmp/x.proof
```

(That circuit has 1,911 constraints.) The output is a hard panic:

```
thread 'main' panicked at .../src/engine.rs:72:9:
DenseQapEngine supports 1-14 constraints, got 1911
```

The 14-constraint cap is not a lazy engineer's shortcut — it is an honest admission that the dense representation is a teaching tool. Lagrange interpolation at `{0, 1, …, n−1}` and schoolbook polynomial math are the *definition* of Groth16; they are just not an *implementation* of it that anyone can afford past a handful of gates. Keep that cap in mind — it's the reason the first real optimization exists at all.

So the shape of the fix is clear before we write any code: **stop doing polynomial algebra in coefficient form, and stop using `{0, 1, …, n−1}` as our playground.** That is exactly what the next section does.

---

## The optimization sprint

The codebase organizes its growth into a ladder of implementations. Each rung keeps the *same protocol* — the same R1CS, the same QAP identity `l(x)·r(x) − o(x) = h(x)·T(x)`, the same Groth16 proof shape, the same pairing check — and only swaps the machinery underneath. That is the whole trick: the cryptography never changes, so we are free to make it fast.

| Impl | Engine | Prover | What it fixes | Status |
|------|--------|--------|---------------|--------|
| 1 | `DenseQapEngine` | `NaiveProver` | Baseline: Lagrange + dense polynomials + scalar-by-scalar MSM | [done] Installment 1 |
| 2 | `FftQapEngine` | `NaiveProver` | Polynomial ops O(n²) → O(n log n); unlocks any circuit size | [done] **this section** |
| 3 | `FftQapEngine` | `PippengerProver` | Proof assembly O(n) → O(n log n) batched MSM | [done] **this section** |
| 4 | Circom adapter `.r1cs`/`.wtns` | — | Consume real circuits instead of hard-coded matrices | [planned] later |
| 5 | Full proving key + on-the-fly QAP | — | Drops the per-proof QAP, makes a ceremony meaningful | [planned] later |
| 6 | Sparse matrices | — | Memory O(n²) → O(#non-zero entries) | [planned] later |
| 7 | h-query scalar compression | — | Cuts proving-key size & drops the h MSM | [planned] later |

Every later rung builds on the one before it, and all of them keep Implementation 1's interface. Let's climb the first one.

---

## Implementation 2 — FFT

The goal, in one sentence: **replace the O(n²) polynomial bookkeeping of Implementation 1 with FFT, so that a circuit the dense engine could never even build becomes a routine 5-second prove.**

### The bottleneck, in plain words

Every Groth16 prover runs the same playbook:

1. build the QAP polynomials `u_s(x), v_s(x), w_s(x)` from the constraint matrices;
2. assemble `l(x) = Σ a_s·u_s(x)`, `r(x) = Σ a_s·v_s(x)`, `o(x) = Σ a_s·w_s(x)`;
3. compute the quotient `h(x) = (l·r − o) / T(x)`;
4. evaluate everything at the secret point τ, "in the exponent".

Steps 1–3 are pure polynomial arithmetic, and in Implementation 1 every one of them is implemented in the most literal, "schoolbook" way possible:

- interpolation — solving for `n` unknown coefficients from `n` points by brute force (O(n²));
- multiplication `l·r` — the nested loop you learned in middle school (O(n²));
- division `(l·r − o) / T` — long division, position by position (O(n²)).

Nothing is wrong with any of it. But "schoolbook" is the slowest valid recipe, and for a circuit with `n` constraints the cost of the whole polynomial section is quadratic in `n`. Quadratic is the wall: at 79,000 constraints the multiplication inside `h(x)` is already `~6·10⁹` field operations, and at 4 million it explodes beyond feasibility — before a single curve point is touched.

### The idea

There is a fundamentally better way to work with polynomials, and it has two ingredients.

**Ingredient 1: a polynomial is two interchangeable representations.** Any polynomial of degree < N can be written either as a list of `N` *coefficients* (`c₀ + c₁x + c₂x² + …`) or as a list of `N` *evaluations* (`P(x₀), P(x₁), …, P(x_{N−1})`). Same animal, two passports. The passport costs nothing to pick — you just have to be careful never to *mix* them.

Why does anyone care? Because some operations are cheap in one passport and expensive in the other:

- **Multiplying** two polynomials. In coefficient form this is the O(n²) schoolbook loop. But in evaluation form it's a **pointwise product** — multiply the two lists entry by entry, O(n), done. (A degree-(d) product is determined by its values at 2d+1 points; if we agreed to work below that, the pointwise product *is* the product.)
- **Evaluating** at a point, or **interpolating** back to coefficients: in coefficient form these are also O(n²) for us. But there's a pair of algorithms — the **FFT** and its inverse — that converts between the two passports in **O(n log n)**.

So the grand bargain is: *do the arithmetic in evaluation form (cheap), and use the FFT only to convert in and out (still cheap).*

**Ingredient 2: pick the right points.** The FFT is fast specifically because it evaluates at very special points: the **N-th roots of unity** — the N numbers `ω⁰, ω¹, …, ω^{N−1}` in our field with the property that `ω^N = 1`. Their beauty is algebra: because they close under multiplication (`ω^i · ω^j = ω^{i+j mod N}`), evaluating a polynomial at all of them can be shared and reused — that sharing is precisely where the log factor comes from. (Rest assured: over BLS12-381's scalar field there are roots of unity of every power-of-two size we will ever need, up to 2²⁵⁵.)

For a circuit with `n` constraints we:

1. choose `N = next power of two ≥ n` (that's our evaluation domain size);
2. stick the constraints on the points `ω⁰, …, ω^{n−1}` instead of `0, 1, …, n−1`;
3. zero-pad the constraint matrices up to `N` rows (the last few evaluation slots just say "constraint value 0").

Everything downstream now falls out of these two choices:

- **QAP construction becomes one IFFT per column.** A column of the padded matrix (with a 1 in row `j`, elsewhere 0) is, by definition, the evaluation form of Lagrange basis polynomial `ℓ_j(x)` — the *unique* degree-<N polynomial that is 1 at `ωʲ` and 0 at the other `N−1` points. So instead of *solving* for `u_s(x)` by Lagrange's formula, we **inverse-FFT** the column into coefficient form. Same polynomial, O(N log N) instead of O(n²).

- **The target polynomial becomes trivial.** `T(x) = x^N − 1` — the monic polynomial with exactly the roots of unity as its roots. No `(x−0)(x−1)…(x−n+1)` product needed; it's two non-zero coefficients.

- **The quotient uses a vanishing-poly division.** `T(x) = x^N − 1` is a "vanishing polynomial" over our domain, and dividing by it has a dedicated fast routine (`divide_by_vanishing_poly`). Combined with the FFT-based product `l·r` (pointwise, O(N)), the whole quotient step drops from quadratic to O(N log N).

That's the whole optimization. Nothing about the *proof* changes — same witness, same QAP identity, same A/B/C, same pairing check. We only changed *where we stand* and *how we compute*. It deserves emphasis:

> **Implementation 2 is not a different proof system. It is the same proof system with cheaper machinery.** Swapping the engine does not change a single proof that Installment 1 verified — it changes the price of producing it.

### The code change is one word

Because both engines back the same trait, the switch is embarrassingly small:

```rust
// Before (Implementation 1)
let engine = DenseQapEngine::new();

// After (Implementation 2)
let engine = FftQapEngine::new();
```

Both satisfy the `QapEngine` trait (`build_qap`, `target_poly`, `compute_quotient`, `evaluate_qap_at_tau`, and friends in `clis/trusted-setup/src/engine.rs`), and the prover — the thing that turns the QAP into a proof — never looks at which engine it is holding. This trait is the architectural bet the whole sprint relies on: **optimizations are experiment swap**, not protocol surgery. The CLI exposes exactly this knob:

```bash
groth16 prove ... --engine dense   # Implementation 1 machinery
groth16 prove ... --engine fft     # Implementation 2 machinery
```

### Wait — the two engines produce *different* proofs. Is that a bug?

Great question, and no. The dense engine anchors its constraints at `{0, 1, …, n−1}`; the FFT engine anchors them at the `N`-th roots of unity. Those are *different points*, so the QAP polynomials — and hence the concrete values of `A, B, C` — come out different.

Think of it like two survey teams mapping the same square mile: one uses metric coordinates, the other imperial. Both maps are internally consistent; a route planned on one map simply cannot be overlaid on the other. In Groth16 the "units" are baked into the ceremony (the target polynomial `T`, and every SRS point): a proof built against the roots-of-unity `T(x) = x^N − 1` only verifies against a ceremony that committed to *that* `T`. The pairing check knows nothing about engines — it just verifies the algebra `A·B = α·β · V·γ · C·δ` — and that algebra passes exactly when the proof and the ceremony speak the same coordinate system, regardless of which one it is.

The corollary is something you can *demonstrate* in one command (and enjoy doing so): use an FFT ceremony's proving key but ask the dense engine to produce the proof. It is a perfectly reasonable proof — fed to the *right* verifier. Fed to this one, it's garbage, and the verifier says so.

### Try it yourself

**1. See both engines build the same toy circuit.**

```bash
cd groth16-prover
cargo run --release --features bins --bin print_qap_engines
```

This prints the dense QAP (constraint points `{0,1,2}`) and the FFT QAP (domain size 4, roots of unity) for the 3-constraint multiplier circuit, then the two target polynomials. Note the shapes:

- dense: `T(x)` printed with degree 3, coefficients `["", "2", "…510", "1"]` — a real product `(x)(x−1)(x−2)`, ending in `1`;
- FFT: `T(x)` printed with degree 4, coefficients `["…512", "", "", "", "1"]` — read as `x⁴ − 1`, two non-zero terms (the silent `"…512"` entries are `-1` / `0` printed as field elements).

Two different `T`, two different worlds — both perfectly fine.

**2. Benchmark the switch (Implementation 1 vs 2 in the scalar path).**

```bash
cd groth16-prover
cargo run --release --features bins --bin benchmark_provers   # ~5–7 minutes, 10,000 proofs each
```

On the reference machine from `README.md` (3-constraint multiplier, single core):

| Implementation | Engine | Prover | Per-proof | vs. Impl 1 |
|----------------|--------|--------|-----------|------------|
| 1 (dense) | `DenseQapEngine` | `NaiveProver` | 3.99 ms | — |
| 2 (FFT) | `FftQapEngine` | `NaiveProver` | 5.56 ms | 0.72× |

Let's be honest about what this shows: **on a 3-constraint toy, the FFT path is a bit *slower*.** The padding overhead (N = 4, plus extra IFFT steps) outweighs the O(n log n) win at this size. Nothing is broken — quadratic beats `n log n` for tiny `n`. The tables turn the moment the circuit stops being toy-sized, which is exactly what the numbers in [What it achieves](#what-it-achieves-at-scale) show. Benchmark runs on your machine will produce different absolutes but the same story.

**3. Prove the same statement through both engines end-to-end.**

Use the deterministic on-the-fly ceremony (no proving key) — each engine generates its own ceremony with the *same* scalars, so the comparison is apples-to-apples:

```bash
cd circom/SumOfProducts
G=../../clis/groth16/target/release/groth16

# Implementation 1 machinery — dense engine, naive prover, scalar QAP path
$G prove --circuit sum_of_products.r1cs --witness witness.wtns \
         --engine dense --prover naive --qap-not-on-fly --out /tmp/sop_dense.proof
$G verify --proof /tmp/sop_dense.proof --public /tmp/sop_dense.pub
# → Verification result: VALID

# Implementation 2 machinery — FFT engine, naive prover, scalar QAP path
$G prove --circuit sum_of_products.r1cs --witness witness.wtns \
         --engine fft --prover naive --qap-not-on-fly --out /tmp/sop_fft.proof
$G verify --proof /tmp/sop_fft.proof --public /tmp/sop_fft.pub
# → Verification result: VALID

# Same statement, same witness, same scalars — but different proof bytes:
cmp /tmp/sop_dense.proof /tmp/sop_fft.proof && echo "same" || echo "different"
# → different
```

Both verify. The bytes differ. Same system, different coordinates — just as promised.

> **A note on `--prover naive --qap-not-on-fly`.** The CLI's *default* prover is already Pippenger, and you will meet it in the next section. Since Pippenger produces bit-for-bit identical proofs, the choice between naive and Pippenger does not change this comparison — we only pinned the flags here so the labels match the rungs on the ladder honestly.

**4. Watch the coordinate systems collide.**

Now run a proper FFT ceremony (the real thing, via `ceremony-dev`), then ask the *dense* engine to prove against it:

```bash
TS=../../clis/trusted-setup/target/release/trusted-setup
cd circom/SumOfProducts

# FFT ceremony → /tmp/sop.pk (and a matching verifying key)
$TS ceremony-dev --circuit sum_of_products.r1cs \
                 --proving-key /tmp/sop.pk --verifying-key /tmp/sop.vk

# Dense-engine proof against the FFT ceremony's key — square peg, round hole:
$G prove --circuit sum_of_products.r1cs --witness witness.wtns \
         --proving-key /tmp/sop.pk --engine dense --out /tmp/sop_mix.proof
$G verify --proof /tmp/sop_mix.proof --public /tmp/sop_mix.pub \
          --verifying-key /tmp/sop.vk
# → Error: "Verification result: INVALID — pairing equation does not hold"

# Same ceremony key, FFT engine → fine:
$G prove --circuit sum_of_products.r1cs --witness witness.wtns \
         --proving-key /tmp/sop.pk --engine fft --out /tmp/sop_match.proof
$G verify --proof /tmp/sop_match.proof --public /tmp/sop_match.pub \
          --verifying-key /tmp/sop.vk
# → Verification result: VALID
```

The moral: engines aren't interchangeable at the ceremony level — they each define their own QAP `T`. Pick one when you run the ceremony, and stay with it. In this repo, the ceremony always uses FFT.

> **What you just achieved.** You ran Implementation 2 back-to-back with Implementation 1, saw both produce valid proofs for the same statement, saw the two coordinate systems collide when mixed, and confirmed the FFT engine certifies proofs for the multi-thousand-constraint circuits the dense engine refuses to touch. Don't worry about the toy-speed being "slower" — that's the O(n²) curve briefly winning a race it always loses. Now watch Implementation 2 earn its keep on a real circuit.

### A first real circuit: Poseidon

The toy is lovely, and useless. Our first "real" circuit is a **Merkle-tree membership proof** built on the **Poseidon hash** — it lives in `circom/PoseidonMerkle/`. It plays the same role (a privacy gadget) as circuits we'll revisit in later installments: prove *"I know a secret commitment that sits inside this public Merkle tree whose root is `digest`"* — without revealing which leaf you mean, or any of the path.

**What is Poseidon, and why was it invented?** Poseidon is a hash function introduced in 2019 by Grassi, Rechberger, Rotaru, Scholl, and Smart, with a single design goal: *be cheap to compute inside a zero-knowledge circuit.* The problem it attacks is that classic hashes are built for the wrong machine:

- **SHA-256 is a chip hash.** Its ANDs, XORs, and rotates are free on a CPU but brutal in an arithmetic circuit over a large prime field — every bit of every word has to be turned into constraints. A SHA-256 hash inside a circuit costs roughly **27,000 constraints**.
- **Poseidon is a field hash.** Its only operations are field additions and field multiplications — precisely the one thing an R1CS constraint already is. No bit-slicing, no integer emulation, no overhead.

Mechanically, Poseidon is a **sponge built on a permutation** over the field, arranged as an SPN: rounds of a tiny S-box (`x → x⁵`, chosen so it permutes the field), a linear diffusion layer (an MDS matrix), and round constants. To keep constraints low it uses the **Hades** round structure — most rounds are *partial* (only one S-box fires) with a few *full* rounds providing the security. The payoff: **a complete 2-to-1 Poseidon compression costs on the order of ~250 constraints** — about a *hundredth* of SHA-256 — and an entire Merkle *path*, the whole membership circuit above, fits in roughly 2,000.

Why is this our "slightly bigger" circuit? Because Poseidon is instantiated **over the exact scalar field we already prove in** (`PoseidonBLS12_381`): the hash field and the proof field are the same field, so hashing inside the circuit costs native field multiplications — no cross-field plumbing. That one property is what lets the stack ship real, on-chain-verifiable membership logic at all, and it's why a "slightly bigger" circuit means **1,911 constraints** here instead of hundreds of thousands. (For context, the earlier field-hash standard *MiMC* was even cheaper per level — the README notes ~38 vs ~250 constraints — but Poseidon carries far better security margins against the algebraic attacks that field hashes attract, and it is already the hash used everywhere else in this BLS12-381 stack.)

### Try it on a slightly bigger circuit

Now the payoff. Point the two engines at the membership circuit and watch:

```bash
cd circom/PoseidonMerkle

# Implementation 2 machinery (FFT, naive scalar path) on a real circuit:
groth16 prove --circuit poseidon_merkle_depth2.r1cs \
              --witness witness.wtns \
              --engine fft --prover naive --qap-not-on-fly \
              --out /tmp/pm.proof
groth16 verify --proof /tmp/pm.proof --public /tmp/pm.pub
# → Verification result: VALID

# Now retry the same statement with the dense engine:
groth16 prove --circuit poseidon_merkle_depth2.r1cs \
              --witness witness.wtns \
              --engine dense --out /tmp/x.proof
# → thread 'main' panicked ... DenseQapEngine supports 1-14 constraints, got 1911
```

(`--qap-not-on-fly` keeps us strictly on Implementation 2's machinery — the Impl 1/2 scalar path — rather than the on-the-fly shortcut we'll meet as Implementation 5.)

On this tutorial's machine (single core, `--release`), one run looked like this:

| | toy (drill 2's multiplier) | PoseidonMerkle depth-2 |
|---|---|---|
| constraints / wires | 3 / 8 | 1,911 / 1,914 |
| dense engine (Impl 1) | works — ~14 ms/proof | **refuses** (14-constraint cap) |
| FFT engine, scalar path (Impl 2) | works — ~15 ms/proof | works — ~27 s, proof VALID |
| ceremony `ceremony-dev --sparse` | instant | ~2 s |

(The toy rows come from `benchmark_provers` in drill 2 — its hard-coded 3-gate multiplier. Our 5-gate `SumOfProducts` sits in the same millisecond band, as you saw in drills 3–4.)

Read that table like a story. At toy scale the FFT engine is a hair slower than dense, and nobody cares. At two thousand constraints the dense engine is not slower — it has **stopped existing** — while the FFT engine calmly produces a valid proof in ~27 s on this laptop. The reference machine in the README clocks the same shape at a friendlier ~7 s for the comparable 1,107-constraint circuit, and by the time we've climbed Implementations 5–7 the same 1.9K-constraint proof drops to well under a second there. That gap — "impossible" on the left side of the table, "routine" on the right — is precisely the O(n²) → O(n log n) curve we sketched in [The idea](#the-idea), showing up in the real world.

> **What this section achieves.** You watched the FFT engine cross the line the dense engine can never cross: a non-toy circuit, thousands of constraints, produced and verified end-to-end on implementation 2's own machinery. The ~27 s is the last time we pay the naive-tax at this scale on purpose — Implementations 3–7 exist to break exactly that cost, and we get to dismantle it one wall at a time.

### What it achieves, at scale

The dense engine's 14-constraint cap means the comparison can't even be run head-to-head on real circuits — that's the point. Here is what the FFT path buys relative to the implementation we left behind (`groth16-prover/README.md`):

- **~1000× faster QAP construction at 10⁴ gates.** Per the reference benchmarks, the dense Lagrange path is O(n²) while the FFT path is O(N log N); at ten thousand gates the ratio is on the order of a thousand-fold, and it grows from there.
- **Multi-million-constraint circuits become provable.** The Ed25519 signature circuit in this repo has ~4M constraints / ~4M wires. The dense engine cannot even *start*. With the FFT engine the same circuit proves end-to-end on commodity hardware.
- **The quotient step alone went from >30 min to ~48 s** on the ~79K-constraint Blake2b-224 circuit once `l·r` switched from schoolbook to FFT-based multiplication (`README.md`, Implementation 6 notes).

None of that is magic — it's the textbook O(n²) → O(n log n) curve, applied to a pipeline where `n` routinely reaches tens of thousands. The next implementations don't change the polynomial math; they attack the *other* walls: the O(n) scalar-multiplication loop in proof assembly (Implementation 3), and the O(n²) *memory* of dense matrices (Implementations 6, 7).

---

## Implementation 3 — Pippenger MSM

The goal, in one sentence: **replace the O(n) scalar-multiplication loop in proof assembly with a batched multi-scalar multiplication, so that the prover can handle circuits where proof assembly would otherwise take thousands of independent curve-point multiplications.**

### The bottleneck, in plain words

Implementation 2 fixed the polynomial math. But once the QAP polynomials are evaluated at τ, the proof is still *assembled* one point at a time:

- `C = Σ_private a_i·Ψ_i + h(τ)·T(τ)/δ·G1` — one scalar multiplication per private wire;
- `V = Σ_public a_i·Ψ_i` — one per public wire;
- `A` and `B` — two more (small constants).

Each of those scalar multiplications is a full "double-and-add" ladder: roughly 255 doublings and 128 additions for a 256-bit scalar, all independent. With thousands of wires, that's thousands of separate ladders. The code is clear about this — it is a `for` loop calling `generator * (psi * witness)` in each iteration (`clis/trusted-setup/src/prover.rs`, lines 285–289):

```rust
// C = sum_{private} a_i·Psi_P_G1 + h(tau)·T(tau)/delta·G1
let mut c_proj = G1Projective::zero();
for i in 2..witness.len() {
    let psi_scalar = (vs_tau[i] * alpha + us_tau[i] * beta + ws_tau[i]) * delta_inv;
    c_proj += g1_proj * (psi_scalar * witness[i]);
}
```

Every iteration does an independent full scalar multiplication — roughly 255 doublings and 128 additions, repeated for every wire. No sharing. That is the last O(n) wall left from Implementation 1.

### The idea: Pippenger's bucket algorithm

The insight is simple: each scalar-multiplication ladder independently goes through ~255 doublings to reach its power of the generator, even though *all the points share the same base* and differ only in their scalar. If you could somehow share that ladder across points, you would save massively.

That is exactly what **Pippenger's bucket MSM** (multi-scalar multiplication) does, introduced in 1987:

1. **Split each scalar into fixed-width windows.** With `c` bits per window, a 256-bit scalar yields roughly `256/c` digit positions. Pick `c = 4` — that gives 64 windows, each with 16 possible digits (0–15).

2. **One pass over all the points per window.** For each window position, sort the points into `2^c` buckets by their scalar's digit at that position — a point whose digit is `d` at window position `w` lands in bucket `d`. Each point gets added to exactly one bucket per window. Cost: `n` point-additions per window.

3. **Combine each bucket with a running sum.** Within a window position, the buckets share a "place value" (the `w·c` doublings needed to shift to that position). So instead of combining them independently, add them once from the highest bucket down, accumulating into a running total. That is `2^c` additions, not `2^c` scalar multiplications.

4. **Shift the accumulator across windows.** Moving from one window position to the next means shifting the place value up by `c` bits — a batch of `c` doublings. Combine the window accumulator into the final result.

The cost arithmetic is now: `n × (256/c)` point-additions (filling buckets across windows) + `(256/c) × 2^c` additions (combining buckets within windows). That is roughly **`n × 64` additions** instead of **`n × ~383` operations** — about a **6× reduction in group operations** for `c = 4`, and the per-point cost drops from "full double-and-add ladder" to "one addition per window."

> **A shopkeeper analogy.** Pippenger is the difference between counting a pile of coins one at a time and sorting them into denomination piles first — once sorted, you count each pile once instead of once per coin.

In code, the switch is from the for-loop `c_proj += g1_proj * scalar` to `G1Projective::msm(bases, scalars)` — a single library call to arkworks' Pippenger implementation (`clis/trusted-setup/src/prover.rs`, lines 470–472):

```rust
// Before (NaiveProver) — one scalar mul per wire
c_proj += g1_proj * (psi_scalar * witness[i]);

// After (PippengerProver) — batched MSM over all wires
c_proj = G1Projective::msm(&c_bases, &c_scalars).unwrap();
```

### The code change is one struct name

Like the engine swap, the prover swap is trait-based — the `Prover` trait has `prove`, `prove_with_full_pk`, `prove_with_full_pk_sparse`, and the prover's job is only the *group arithmetic* of proof assembly:

```rust
// Before (Implementation 2)
let prover = NaiveProver::new();

// After (Implementation 3)
let prover = PippengerProver::new();
```

Both `NaiveProver` and `PippengerProver` live in `clis/trusted-setup/src/prover.rs` and implement the same `Prover` trait. The engine, the witness, the QAP — none of that changes. You just hand the same inputs to a prover that batches its group arithmetic.

The CLI exposes exactly this knob:

```bash
groth16 prove ... --prover naive      # Implementation 2 prover
groth16 prove ... --prover pippenger  # Implementation 3 prover (default)
```

> **The CLI's default prover is already Pippenger.** Every drill in the Implementation 2 section that omitted `--prover` was *already* running the Implementation 3 prover — the QAP step differs, so the *engine* label was correct, but the proof assembly used Pippenger all along. We only added `--prover naive` in drills 3–4 so the labels matched the rungs on the ladder honestly.

### Different proof? No — byte-identical

This is the sharpest contrast to the FFT switch. Implementation 2 changed the *coordinate system* (roots of unity vs `0…n−1`), so the proof bytes changed. Implementation 3 changes only *how the group arithmetic is batched* — same scalars, same bases, same group elements, just computed in a different order. The result is **bit-for-bit identical**.

You can prove it:

```bash
cd groth16-prover
cargo run --release --features bins --bin print_proof_pippenger
```

This binary proves the toy 3-constraint circuit twice — once with `NaiveProver`, once with `PippengerProver` — and asserts that `A`, `B`, `C`, and `V` are element-equal (`groth16-prover/src/bin/print_proof_pippenger.rs`, lines 56–59):

```rust
assert_eq!(proof_naive.a, proof_pip.a, "A must match");
assert_eq!(proof_naive.b, proof_pip.b, "B must match");
assert_eq!(proof_naive.c, proof_pip.c, "C must match");
assert_eq!(public_naive.v, public_pip.v, "V must match");
```

Output (bit-for-bit parity and pairing check):

```
✓ Pippenger proof matches naive proof bit-for-bit.
✓ Both proofs pass pairing check.
```

### Try it yourself

**1. Toy: byte parity and the benchmark.**

The benchmark binary (`groth16-prover/src/bin/benchmark_provers.rs`) runs all three implementation paths on the 3-constraint multiplier, 10,000 proofs each:

```bash
cd groth16-prover
cargo run --release --features bins --bin benchmark_provers   # ~5–7 minutes
```

On this laptop (fresh release build, single core):

| Impl | Per-proof | vs Impl 2 |
|------|-----------|-----------|
| 1 (dense, naive) | ~13.86 ms | 0.94× (dense faster — overhead wins at tiny scale) |
| 2 (FFT, naive) | ~14.68 ms | — |
| 3 (FFT, Pippenger) | ~11.42 ms | **1.29×** |

Reference machine from `README.md` (same circuit, same 10k proofs):

| Impl | Per-proof | vs Impl 2 |
|------|-----------|-----------|
| 1 (dense, naive) | 3.99 ms | 0.72× |
| 2 (FFT, naive) | 5.56 ms | — |
| 3 (FFT, Pippenger) | 3.76 ms | **1.48×** |

At toy scale the FFT path is a hair slower than dense (padded overhead outweighs polynomial savings at 3 constraints), and Pippenger barely squeezes past naive — there are only a handful of scalar multiplications, and the MSM machinery has some fixed overhead. The real story is at scale, where the MSM overhead is dwarfed by the savings. Next drill.

**2. Poseidon 1,911 constraints: the FullProvingKey path.**

The scalar path's QAP construction is so expensive relative to the MSMs that it drowns out Pippenger's advantage. The *FullProvingKey* path — used when you supply a `.pk` file from the ceremony — is where Pippenger shines: the QAP is already baked into the proving key, and per-proof time is dominated by MSMs over the full key vectors.

```bash
cd circom/PoseidonMerkle
TS=../../clis/trusted-setup/target/release/trusted-setup
G=../../clis/groth16/target/release/groth16

# Build a full proving key (uses Impl 2/3 machinery already — production shape):
$TS ceremony-dev --circuit poseidon_merkle_depth2.r1cs \
                 --proving-key /tmp/pm.pk --verifying-key /tmp/pm.vk \
                 --sparse

# Prove with naive prover (Implementation 5 machinery, naive assembly):
$G prove --circuit poseidon_merkle_depth2.r1cs --witness witness.wtns \
         --proving-key /tmp/pm.pk --prover naive --out /tmp/pm_n.proof

# Prove with Pippenger prover — same key, same witness, one struct swap:
$G prove --circuit poseidon_merkle_depth2.r1cs --witness witness.wtns \
         --proving-key /tmp/pm.pk --prover pippenger --out /tmp/pm_p.proof

# Verify both:
$G verify --proof /tmp/pm_n.proof --public /tmp/pm_n.pub --verifying-key /tmp/pm.vk
# → Verification result: VALID
$G verify --proof /tmp/pm_p.proof --public /tmp/pm_p.pub --verifying-key /tmp/pm.vk
# → Verification result: VALID

# Proof bytes — bit-for-bit identical:
cmp /tmp/pm_n.proof /tmp/pm_p.proof && echo "IDENTICAL" || echo "different"
# → IDENTICAL
```

On this laptop (fresh release build, single core):

| | naive | Pippenger | ratio |
|---|---|---|---|
| Poseidon FPK (1,911 constraints) | ~25.2 s | ~19.9 s | **1.26×** |

The proof bytes are bit-for-bit identical; the difference is purely a speedup on the same group arithmetic.

**3. Scalar-path warning: why Pippenger helps little here.**

If you run the same circuit on the *scalar* path (no `.pk`, `--qap-not-on-fly`):

```bash
$G prove --circuit poseidon_merkle_depth2.r1cs --witness witness.wtns \
         --engine fft --prover naive --qap-not-on-fly --out /tmp/pm_scalar_n.proof
$G prove --circuit poseidon_merkle_depth2.r1cs --witness witness.wtns \
         --engine fft --prover pippenger --qap-not-on-fly --out /tmp/pm_scalar_p.proof
```

The results are only ~1.06× (27.0 s → 25.4 s) — the MSMs are a small slice of scalar-path time, because the QAP construction (`build_qap` + per-wire polynomial evaluation) dominates. **This is precisely why Implementations 5–7 exist:** once the ceremony bakes the QAP into a full proving key, the per-proof cost collapses to just the MSMs, and Pippenger's savings are no longer buried under the QAP tax. On the FullProvingKey path at 1.9K constraints, Pippenger delivers a credible 1.26× improvement; on larger circuits the gain is larger still.

> **What this section achieves.** You swapped one struct name, and the proof assembly changed from O(n) independent scalar multiplications to a batched Pippenger MSM — the single most important optimization for proving at scale. The proof did not change bytes (unlike the FFT switch), confirming that this is purely a speed optimization, not a protocol change. You measured the gain on a real 1,911-constraint circuit and saw it land: modest on the scalar path (where QAP build dominates), solid on the FullProvingKey path (where MSMs are the game), and waiting to grow as circuits scale up.

### What it achieves, at scale

Pippenger's advantage compounds as circuits grow, because the MSM share of prove time grows — and it is already large on production circuits:

- **At ~1.9K constraints:** 1.26× on the FullProvingKey path (your measured number above).
- **At ~79K constraints (Blake2b-224):** proof assembly MSMs are a major slice of the already-improved post-Impl-5 times, and Pippenger reduces them substantially.
- **At ~4M constraints (Ed25519):** the `h_query` MSM *alone* consumed ~55% of prove time (~163 s out of ~295 s) — before Implementations 5–7. Pippenger reduces that to O(n/log n) additions instead of O(n) scalar muls, and is the only reason the prover terminates in minutes rather than hours.

The key: as circuits grow, the fraction of prove time spent in MSMs *grows*, and Pippenger's O(n/log n) scales better with n than naive's O(n) — the window width can increase with n to flatten the overhead further.

### What comes next

Implementation 3 attacks only the proof assembly MSMs. The QAP construction is still per-proof on the scalar path, and the constraint matrices are still allocated densely in memory — Implementations 4–7 continue the attack:

| Impl | What it attacks | Relationship to this section |
|------|-----------------|------------------------------|
| 4 | Circom adapter | Unlocks real circuits from the command line (builds, not proofs) |
| 5 | On-the-fly QAP | Drops the per-proof QAP build — MSMs become the *whole* prover, so Pippenger's 1.26× applies to the full proving time |
| 6 | Sparse matrices | Drops the O(n²) memory of dense constraint matrices — complements the per-proof speedups here |
| 7 | h-query scalar compression | Collapses the largest MSM (h_query) to a single scalar mul |

The next section tackles Implementation 4: reading `.r1cs` and `.wtns` files from circom, so you can run the whole stack on circuits you wrote yourself.

---

## Implementations 4–7 *(to be written)*

Coming in later passes:

- **4 — Circom adapter**: read `.r1cs` constraints and `.wtns` witnesses from real circuits instead of hard-coded matrices.
- **5 — Full proving key + on-the-fly QAP**: ceremony outputs group elements only (no scalars survive); the prover accumulates witness polynomials on the fly instead of materialising every `u_s(x)`.
- **6 — Sparse matrices**: keep `.r1cs`' native sparsity instead of inflating to `n_constraints × n_wires`; memory drops from ~200 GiB (Blake2b-224) to ~280 MiB.
- **7 — h-query scalar compression + parallel proof assembly**: collapse the h-query G1 vector to one scalar, shrinking the proving key and removing the h MSM.

---

## The trusted-setup ceremony

The engineering sprint makes Groth16 *fast*; the ceremony makes it *secure*. It is the one production concern we must get right before any of the speed matters — a fast prover for a broken system is just a fast way to forge. Here are the foundations; a full hands-on walkthrough of the production ceremony lands in a later section.

### Why the scalars must be secret and random

The five scalars `τ, α, β, γ, δ` are the *cryptographic heart* of Groth16. If any party knows them, the entire proof system collapses. This is not an exaggeration — it is a mathematical theorem. Let us see why.

> **Recap from Installment 1.** The prover evaluates polynomials at a single secret point `τ` "in the exponent": proof element `A` encodes `l(τ) + α`, element `B` encodes `r(τ) + β`, and element `C` locks the witness to the circuit through `α`, `β`, `γ`, `δ`. The verifier never sees `τ` — it only sees the curve points `τⁱ·G1`, `τⁱ·G2` produced by the ceremony. The entire protocol rests on `τ` (and its friends) staying secret forever.

#### The forgery attack if τ is known

Suppose an attacker learns `τ = 6`. They can now compute `T(τ) = 720` directly. They can pick *any* fake witness they want — say, `a = 100, b = 100, c = 100, d = 100, e = 100, f = 100, g = 100, h = 100` — which gives intermediates `p1 = 10000, p2 = 10000, p3 = 10000, p4 = 10000, p5 = 10000, p6 = 10000`. This witness does not need to satisfy the R1CS constraints in the polynomial sense; the attacker can simply compute `l(τ), r(τ), o(τ)` and then *choose* `h(τ)` to make the equation balance:

```
h(τ) = (l(τ)·r(τ) − o(τ)) / T(τ)
```

Because the attacker knows `τ`, they can compute this quotient even when the witness is garbage. They then build proof elements `A, B, C` using the *legitimate* SRS points (which are public) and their chosen `h(τ)`. The verifier's pairing check will pass — because the equation is algebraically satisfied at `τ` — even though the witness violates the actual circuit constraints at every other point.

In other words, **knowledge of `τ` lets the attacker "cheat" the single-point check without ever satisfying the multiplicative constraints.** The same logic applies to `α, β, γ, δ`: if any of them are known, the attacker can separate the public and private parts of the proof arbitrarily, forging a valid-looking proof for any statement.

#### Why randomness matters

You might ask: why not just hard-code `τ = 42` and publish it? Everyone would know it, but at least the system would be transparent.

The problem is **precomputation attacks.** If `τ` is predictable, an attacker with enough resources could compute `τ^i · G1` and `τ^i · G2` for astronomically large `i` *before* the SRS is even published. They could then break the discrete logarithm problem in the exponent using pre-computed tables. Randomness ensures that no one can prepare for the setup in advance.

Moreover, `α, β, γ, δ` must be *independent* random values. If `α = β`, the proof element `C` loses its binding to the left input, and an attacker can swap `l(τ)` and `r(τ)` without detection. If `γ = δ`, the public and private input commitments collapse into one, destroying the zero-knowledge property.

#### The ceremony intuition: 1-of-N trust

Groth16 solves this with a **trusted setup ceremony**: multiple participants jointly generate the scalars, each contributing their own randomness. The security guarantee is simple and powerful:

> **As long as at least one participant was honest and truly destroyed their randomness, the final `τ` remains unknown forever.**

Even if every other participant colluded and shared their secrets, they cannot reconstruct `τ` without the missing contribution. This is why the ceremony needs many independent participants — the probability that *everyone* is dishonest and keeps a backup decreases as the participant count grows.

#### Dev ceremony vs. production ceremony

Our repository uses two different approaches for two different purposes:

| Purpose | Scalars | Security | Why we use it |
|---------|---------|----------|---------------|
| **Learning & debugging** (`ceremony-dev`) | Fixed small primes (`τ=6, α=5, ...`) | **None** — anyone can forge | Every value is printable and reproducible. You can add a `println!` and see exactly what the code does. |
| **Production** | Large random field elements, generated in a ceremony | Secure if at least one ceremony participant was honest | The scalars are never assembled in one place. Only the curve points `τ^i·G1`, `τ^i·G2`, etc. are published. |

The dev ceremony is completely insecure for production — anyone who reads the source code knows `τ` and can forge proofs. But it is invaluable for learning, which is why Installment 1 uses it at every step. The production ceremony is what makes Groth16 safe for real-world deployments.

> **The bottom line.** Groth16's speed and compactness come from a *single* secret evaluation point `τ`. That point must remain secret forever, or the proof system becomes a forgery factory. The trusted setup ceremony is the mechanism that creates `τ`, embeds it into curve points, and then destroys it — provided at least one participant was honest. This is the fundamental trade-off of Groth16: you get the smallest and fastest proofs in cryptography, but you must trust the ceremony once.

### The scalars and who must not know them

All five scalars must be unknown to every party after the ceremony — the prover, the verifier, and any third party. The ceremony is run by a dedicated group of **organizers** who are independent of both the prover and the verifier: they generate the scalars jointly, embed them into curve points (the SRS), and then destroy the raw scalars. The prover and verifier never participate in the ceremony and never see the raw scalars — they interact only with the curve points. The prover uses the full SRS (power tables + proving key), and the verifier uses only a small subset (the verifying key). This is why the setup is "trusted": the security guarantee is that at least one organizer honestly destroyed their contribution, making it impossible to reconstruct any of the five scalars.

| Parameter | Value (dev) | Role | Risk if leaked |
|-----------|-------------|------|----------------|
| `τ` (tau)   | 6   | Secret evaluation point — encodes the SRS power tables `τⁱ·G1`, `τⁱ·G2` | Attacker computes `h(τ)` for any fake witness, forging proofs for false statements |
| `α` (alpha) | 5   | Binds proof element `A` to proof element `C` — prevents the prover from decoupling the left and right witness polynomials | Attacker can swap `l(τ)` and `r(τ)` without detection, breaking the binding between proof elements |
| `β` (beta)  | 7   | Binds proof element `B` to proof element `C` — ties the right witness polynomial into the same commitment as the quotient | Same as `α`: attacker can separate `B` from `C`, breaking soundness |
| `γ` (gamma) | 11  | Denominator for **public-input** CRS elements — separates the public-input commitment `V` from the private-input part of `C` | Public and private input commitments collapse; attacker can forge proofs by manipulating the public-input split |
| `δ` (delta) | 13  | Denominator for **private-input** CRS elements — ensures the prover cannot tamper with the private-input commitment in `C` without `δ`'s knowledge | Attacker can fabricate the private-input part of `C`, forging proofs without a valid witness |

Note the *dev* values in the table are deterministic and public — that is exactly why the dev ceremony is unsafe for production. In production the same five roles are filled by large random field elements. For the 5-constraint `SumOfProducts` circuit, `τ = 6` is required because the constraint points are `{0, 1, 2, 3, 4}` — using `τ = 3` or `τ = 4` would make `T(τ) = 0` and break the proof.

> **The CRS vs. the SRS.** The SRS is the *power table* (`τ^i·G1`, `τ^i·G2`) — it lets the prover evaluate arbitrary polynomials at `τ`. The CRS *fixed points* are the *anchor points* (`α·G1`, `β·G2`, `γ·G2`, `δ·G2`) — they encode the mixed scalars that tie the proof to the specific circuit. In a production trusted setup, the SRS is universal (can be reused for many circuits), while the CRS fixed points are circuit-specific because they depend on `α`, `β`, `γ`, `δ`.

### The ceremony in our repository

The trusted-setup ceremony lives in the standalone [`clis/trusted-setup`](https://github.com/cardano-foundation/bls/blob/main/clis/trusted-setup/) crate (the `trusted_setup` library plus the `trusted-setup` CLI). Proof generation, verification, and verifying-key export live in the separate `groth16` CLI (`clis/groth16`). This split is deliberate: the ceremony is a one-time, circuit-lifecycle operation, while proving/verifying is what happens at runtime. The crate exposes the ceremony core as a reusable library with the modules `r1cs`, `qap`, `engine`, `ceremony`, `phase2`, `ptau`, `circom_adapter`, `prover`, and `cmd`; the `groth16-prover` library re-exports these modules.

#### `ceremony-dev` — the single-party dev ceremony

```bash
cd clis/trusted-setup
cargo build --release

trusted-setup ceremony-dev \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk
```

A single-party ceremony that generates fixed local scalars deterministically (for debugging) or local randomness (for benchmarking), evaluates the QAP polynomials, and writes a `FullProvingKey` (group elements only — no scalars survive). It is fast (milliseconds) and insecure — which is exactly what Installment 1 needed for reproducible printouts, and what CI needs for cheap roundtrips.

Two flags matter when we move to production-sized circuits:

- `--sparse` — use the sparse constraint representation (Implementation 6). Avoids dense matrix allocation for large circuits (e.g. Blake2b-224, Ed25519).
- `--h-scalar` — use h-query scalar compression (Implementation 7). Stores a single scalar `delta_inv * T(tau)` instead of the full `h_query` G1 vector, cutting proving-key size and eliminating the h MSM.

```bash
trusted-setup ceremony-dev \
  --circuit circuit.r1cs \
  --proving-key circuit.pk \
  --verifying-key circuit.vk \
  --sparse \
  --h-scalar
```

#### `phase2` — the production MPC ceremony

The production ceremony is a **multi-party Phase-2 ceremony** that reuses a publicly verified Phase-1 SRS (e.g. the **Perpetual Powers of Tau**). Each participant contributes randomness locally; the coordinator is just a passive file host. The workflow is split into four subcommands:

| Subcommand | Purpose |
|------------|---------|
| `new` | Create initial accumulator from `.ptau` SRS + `.r1cs` |
| `contribute` | Add your randomness contribution |
| `verify` | Check all contributions are valid |
| `finalize` | Convert accumulator to `.pk` / `.vk` |

The full workflow:

```bash
# 1. Initialize from universal SRS
trusted-setup phase2 new \
  --circuit circuit.r1cs \
  --srs universal.ptau \
  --zkey circuit_0000.zkey

# 2. Participants contribute sequentially (each independently, in turn)
trusted-setup phase2 contribute \
  --zkey-in circuit_0000.zkey \
  --zkey-out circuit_0001.zkey \
  --name "Alice"

trusted-setup phase2 contribute \
  --zkey-in circuit_0001.zkey \
  --zkey-out circuit_final.zkey \
  --name "Bob"

# 3. Verify the accumulator
trusted-setup phase2 verify --zkey circuit_final.zkey

# 4. Finalize to .pk / .vk
trusted-setup phase2 finalize \
  --zkey circuit_final.zkey \
  --proving-key circuit.pk \
  --verifying-key circuit.vk
```

**Why this is secure.** The power table `τⁱ·G1`, `τⁱ·G2` is a Phase-1 (universal) artifact produced by a public ceremony such as PPoT, where `τ` cannot be reconstructed as long as one contributor was honest. Phase 2 then *locks* that universal SRS to a specific circuit's QAP. The scalars never exist in one place at one time: each `contribute` step re-randomizes the accumulator under the previous participant's randomness, and `verify` checks that each contribution was valid without learning any secret. If the finalize production uses random scalars and every raw scalar is destroyed, the 1-of-N guarantee from [The ceremony intuition](#the-ceremony-intuition-1-of-n-trust) holds.

The `.pk` / `.vk` files produced by `ceremony-dev` or `phase2 finalize` are consumed by the `groth16` CLI (`prove` / `verify` / `export-vk`) and by the on-chain Aiken verifiers; both key formats are auto-detected on load (`FullProvingKey` uses the fast MSM prover path; the deprecated legacy `ProvingKey`, from the old `ceremony` command, falls back to the scalar-based prover path).

> **The legacy `ceremony` command is deprecated.** It produces a `ProvingKey` that contains scalar toxic waste — unsuitable for production. Use `ceremony-dev` for dev/testing and `phase2` for production.

---

## What's next in this installment

This document is being written implementation by implementation. The full path through the sprint and ceremony:

| Bottleneck | First-principles fix (Installment 1) | Production fix (this installment) | Status |
|------------|--------------------------------------|-----------------------------------|--------|
| Polynomial ops are O(n²) | Dense coefficient vectors | **FFT over roots of unity** | [done] above |
| Proof assembly is O(n) scalar muls | One-by-one multiplication | Pippenger multi-scalar multiplication | [done] above |
| Matrices explode memory | Dense `Vec<Vec<Fr>>` | Native sparse constraint representation | [planned] later |
| Trusted setup is single-party | Deterministic dev scalars | Multi-party MPC ceremony on PPoT | [next] upcoming |
| QAP materialises all polynomials | `build_qap()` returns every `u_i(x)` | On-the-fly witness-polynomial accumulation | [planned] later |

Beyond Groth16, we will survey the landscape: **PLONK** (universal trusted setup, custom gates), **Bulletproofs / Bulletproofs++** (no trusted setup at all), **STARKs / JOLT** (transparent, post-quantum), and **VM approaches (RISC Zero, zkVMs)** that prove arbitrary program execution without hand-writing circuits — folding the former zkVM installment into this one. From here, Installment 3 proves Cardano key ownership, Installment 4 applies the full stack to selective disclosure, and Installment 5 surveys quantum-resistant (lattice-based) systems that will one day replace the pairing-based assumption this whole series is built on.