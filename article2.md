# Zero Knowledge Proof from first principles

> **Installment 1 of 3.** This article introduces the mathematical intuition behind zk-SNARKs, walks through the simplest possible non-trivial circuit, and shows how to generate and verify a Groth16 proof end-to-end on Cardano using nothing but first-principles code. No black boxes, no hand-waving — every intermediate value can be printed and inspected.
>
> In the next installment we will explore the engineering optimizations that turn this slow-but-transparent pipeline into a production prover (FFT, Pippenger MSM, sparse matrices, trusted-setup ceremonies), survey competing proof systems (PLONK, Bulletproofs, JOLT, STARKs, VM approaches), and map the trade-offs. In the third and final installment we will show how Groth16 enables selective disclosure of credentials without revealing identity, building on the [`aiken/selective-disclosure`](../../aiken/selective-disclosure/README.md) work.

---

## Table of Contents

- [The paradox](#the-paradox)
- [Why Groth16 matters](#why-groth16-matters)
- [From computation to gates](#from-computation-to-gates)
- [A 4-constraint "hello world"](#a-4-constraint-hello-world)
- [Why polynomials? (QAP)](#why-polynomials-qap)
- [The trusted setup](#the-trusted-setup)
- [The proof: three curve points](#the-proof-three-curve-points)
- [Verification: one equation](#verification-one-equation)
- [Running it on Cardano](#running-it-on-cardano)
- [The full pipeline in our repo](#the-full-pipeline-in-our-repo)
- [What's next](#whats-next)

---

## The paradox

Imagine you have solved a Sudoku puzzle. I want to be convinced that you know a valid solution, but I do not want you to show me the completed grid — perhaps because the solution encodes a password, or because I want to preserve your ability to challenge someone else with the same puzzle.

Traditional cryptography offers encryption and signatures, but nothing that solves this exact problem: **proving knowledge of a secret without revealing the secret itself**.

Zero-knowledge proofs (ZKPs) do exactly that. A ZKP is a mathematical object — a short string of bytes — that convinces any verifier that a statement is true, while giving the verifier zero information about the evidence that makes it true.

The most practical and widely deployed family of ZKPs today is called **zk-SNARKs**: *Zero-Knowledge Succinct Non-Interactive Arguments of Knowledge*. "Succinct" means the proof is tiny (a few hundred bytes). "Non-interactive" means the prover sends a single message; no back-and-forth challenge protocol is needed. "Argument of knowledge" means the proof does not just show that a solution exists — it shows that the prover actually *knows* one.

This article focuses on **Groth16**, the fastest and most compact zk-SNARK construction in production today. A Groth16 proof is 192 bytes. Verification requires only three elliptic-curve pairings. And since Cardano's Plutus V3 already exposes BLS12-381 pairing primitives natively, Groth16 verification can run inside an Aiken smart contract with no protocol changes.

But before we get to smart contracts, we need to understand what the proof actually *is*. We will build it from scratch, step by step, using the simplest possible circuit that is still non-trivial: a 4-constraint sum-of-products.

---

## Why Groth16 matters

The idea of a zero-knowledge proof is old — it dates back to Goldwasser, Micali, and Rackoff in the 1980s. But for decades ZKPs were theoretical curiosities: interactive, expensive, and impractical for real systems. The breakthrough came in 2012 when Rosario Gennaro, Craig Gentry, Bryan Parno, and Mariana Raykova showed how to compress an arbitrary computation into a **Quadratic Arithmetic Program** (QAP) and then prove its correct evaluation with a short, non-interactive argument built from elliptic-curve pairings. This was the birth of the zk-SNARK.

Four years later, Jens Groth published the paper that distilled the idea to its absolute minimum:

> **Jens Groth, "On the Size of Pairing-Based Non-interactive Arguments", *EUROCRYPT 2016*.**
> [https://eprint.iacr.org/2016/260](https://eprint.iacr.org/2016/260)

Groth's construction — now universally called **Groth16** — achieves something that no previous scheme had:

- **Proof size:** exactly **3 curve points** (2 in G1, 1 in G2). Compressed: **192 bytes**.
- **Verification cost:** **3 pairings** and a handful of multi-scalar multiplications in G1. On modern hardware: a few milliseconds.
- **CRS size:** linear in the circuit size, but the *verifying key* is constant-size for a given circuit.
- **Security:** perfect zero-knowledge and computationally sound knowledge extraction under the standard q-PKE and q-SDH assumptions on pairing-friendly curves.

These numbers are not merely good — they are **optimal** for the pairing-based model. No scheme with the same trust assumptions can have asymptotically smaller proofs or faster verification. This is why Groth16 became the engine behind Zcash's shielded transactions, Filecoin's replication proofs, and dozens of other production systems.

### Why Groth16 is the prerequisite

If you want to understand modern zero-knowledge proof systems, you must understand Groth16 first. Every other construction is best understood as a deliberate trade-off *against* the Groth16 baseline:

| System | What it keeps from Groth16 | What it changes | Cost of the change |
|--------|---------------------------|---------------|-------------------|
| **PLONK** | R1CS, QAP-style polynomial encoding, pairing-based verification | Universal trusted setup; custom gates; permutation argument | Slightly larger proofs, but one SRS serves all circuits |
| **Bulletproofs** | R1CS, inner-product argument structure | No trusted setup at all; no pairings; proofs grow logarithmically | Proof size ~1–2 KB (10× larger); verification is O(n) |
| **STARKs** | Polynomial commitment + FRI | Transparent setup (hashes only); post-quantum | Proof size ~50–200 KB; no elliptic curves needed |
| **JOLT / zkVMs** | The *goal* (prove arbitrary computation) | Replace hand-written circuits with VM execution traces + lookup arguments | Massive proof overhead, but no circuit engineering |

Groth16 teaches the fundamental pipeline that every other system either inherits or reacts against:

1. **Computation → Constraints** (R1CS)
2. **Constraints → Polynomials** (QAP)
3. **Polynomials → Encrypted Evaluations** (trusted setup / SRS)
4. **Witness + SRS → Proof** (prover algorithm)
5. **Proof + Public Inputs + VK → Yes/No** (pairing or commitment check)

Once you have walked through this pipeline by hand — as we do in this article with the dense monomial implementation — you possess the mental model necessary to evaluate *any* proof system. You will know what "removing the trusted setup" actually means, why "universal CRS" matters, and why "post-quantum" constructions pay the price they do.

This is why our repository begins with `Implementation 1`: a hard-coded circuit, dense polynomials, naive scalar-by-scalar proof assembly, and deterministic toxic waste. It is the slowest possible path, but it is also the *most educational*. Every other system is a speedup or a trade-off applied to this same skeleton.

---

## From computation to gates

A zk-SNARK does not prove arbitrary Python or C code. It proves the correct execution of an **arithmetic circuit**: a directed acyclic graph where every node is either an addition or a multiplication, and the edges are *wires* carrying numbers from a finite field.

In practice, we write circuits in a domain-specific language like **Circom**, which compiles to a format called **R1CS** (Rank-1 Constraint System). An R1CS constraint has the shape:

```
(A · w) * (B · w) = (C · w)
```

where `w` is the *witness vector* (all wire values, both public and private) and `A`, `B`, `C` are sparse matrices. Each row of the matrices encodes one multiplication gate. Addition is "free" — it happens inside the linear combinations `A·w`, `B·w`, and `C·w` without needing a separate gate.

This is the key insight: **multiplication costs a constraint; addition does not.** The art of circuit design is therefore minimizing multiplications.

---

## A 4-constraint "hello world"

Our repository already contains a 3-gate multiplication chain (`multiplier.circom`) that proves `a = x1·x2·x3·x4`. To make the pedagogical step slightly richer, we introduce a new 4-gate circuit that proves a *sum of pairwise products*:

```
t1 = a * b
t2 = c * d
t3 = e * f
t4 = g * h
out = t1 + t2 + t3 + t4
```

This circuit has 8 private inputs, 4 intermediate wires, and 1 public output. In R1CS form it yields exactly 4 constraints — one per multiplication. The source lives in [`groth16-prover/circom/SumOfProducts/sum_of_products.circom`](../../groth16-prover/circom/SumOfProducts/sum_of_products.circom):

```circom
pragma circom 2.0.0;

template SumOfProducts() {
    signal input a;  signal input b;
    signal input c;  signal input d;
    signal input e;  signal input f;
    signal input g;  signal input h;

    signal t1; signal t2; signal t3; signal t4;
    signal output out;

    t1 <== a * b;
    t2 <== c * d;
    t3 <== e * f;
    t4 <== g * h;
    out <== t1 + t2 + t3 + t4;
}

component main = SumOfProducts();
```

With the input [`input.json`](../../groth16-prover/circom/SumOfProducts/input.json):

```json
{ "a": "1", "b": "2", "c": "3", "d": "4",
  "e": "5", "f": "6", "g": "7", "h": "8" }
```

the witness vector is:

```
[1, 100, 1, 2, 3, 4, 5, 6, 7, 8, 2, 12, 30, 56]
```

where `100 = 2 + 12 + 30 + 56` is the only public value besides the constant `1`.

---

## Why polynomials? (QAP)

R1CS is a matrix format — good for compilers, bad for cryptography. The breakthrough idea behind zk-SNARKs (originally due to Gennaro, Gentry, Parno, and Raykova, then refined by Groth) is to turn the matrix into **polynomials**.

For each wire `i`, we build three polynomials `u_i(x)`, `v_i(x)`, `w_i(x)` such that at constraint point `j`:

```
u_i(j) = A[j][i]
v_i(j) = B[j][i]
w_i(j) = C[j][i]
```

The prover then forms the *witness polynomials* by summing each family weighted by the witness values:

```
l(x) = Σ a_i · u_i(x)
r(x) = Σ a_i · v_i(x)
o(x) = Σ a_i · w_i(x)
```

If the witness is correct, then at every constraint point `j`:

```
l(j) · r(j) = o(j)
```

This means the polynomial `l(x)·r(x) − o(x)` is zero at every constraint point. Therefore it is divisible by the *target polynomial* `T(x)`, which is simply the product of `(x − j)` over all constraint points `j`.

The prover computes the **quotient polynomial**:

```
h(x) = (l(x)·r(x) − o(x)) / T(x)
```

If `h(x)` exists (i.e., the division has zero remainder), the constraints are satisfied. This is the core mathematical check that Groth16 performs — not by evaluating at every point, but by evaluating at a single secret point `τ`.

This transformation from matrices to polynomials is called the **Quadratic Arithmetic Program (QAP)**. It is the bridge between computer science and cryptography.

---

## The trusted setup

Groth16 requires a **trusted setup**: a one-time ceremony that produces a *Structured Reference String* (SRS) — a list of elliptic-curve points encoding powers of a secret scalar `τ`.

The SRS looks like this:

```
G1, τ·G1, τ²·G1, ..., τ^N·G1
G2, τ·G2, τ²·G2, ..., τ^N·G2
```

where `G1` and `G2` are base points on the BLS12-381 curve. The scalar `τ` itself is called **toxic waste**: if anyone knows it, they can forge proofs. The security of the entire system rests on the fact that `τ` was generated honestly and then destroyed.

In our pedagogical `Implementation 1` ([`groth16-prover/src/r1cs.rs`](../../groth16-prover/src/r1cs.rs) and [`src/bin/print_toxic_waste.rs`](../../groth16-prover/src/bin/print_toxic_waste.rs)), we use small deterministic scalars so that every intermediate value is reproducible:

| Parameter | Value | Role |
|-----------|-------|------|
| `τ` (tau)   | 3   | Secret evaluation point |
| `α` (alpha) | 5   | Mixed term for proof `C` |
| `β` (beta)  | 7   | Mixed term for proof `B` and `C` |
| `γ` (gamma) | 11  | Public-input denominator |
| `δ` (delta) | 13  | Private-input denominator |

In a production deployment these are large random field elements generated during a multi-party computation (MPC) ceremony. As long as **at least one participant** in the ceremony was honest and discarded their randomness, the toxic waste remains unknown. Our repository implements both a single-party dev ceremony (`ceremony-dev`) and a full Phase-2 MPC on top of the Perpetual Powers of Tau (PPoT) universal SRS. We will cover the production ceremony in detail in the next installment.

---

## The proof: three curve points

A Groth16 proof consists of exactly three elliptic-curve points:

| Point | Group | What it encodes |
|-------|-------|-----------------|
| **A** | G1    | `l(τ)·G1 + α·G1` plus a randomizer |
| **B** | G2    | `r(τ)·G2 + β·G2` plus a randomizer |
| **C** | G1    | `Σ a_i·Ψ_P_G1[i] + h(τ)·T(τ)/δ·G1` plus a randomizer |

The `Ψ_P_G1` terms are *per-variable proving-key elements* pre-computed during the trusted setup. They encode the QAP polynomials evaluated at `τ`, scaled by `1/δ` and mixed with `α` and `β`. The prover computes `C` by taking a linear combination of these elements weighted by the witness values, then adding the quotient term `h(τ)·T(τ)/δ·G1`.

In our `Implementation 1` ([`src/bin/print_proof_a.rs`](../../groth16-prover/src/bin/print_proof_a.rs), [`print_proof_b.rs`](../../groth16-prover/src/bin/print_proof_b.rs), [`print_proof_c.rs`](../../groth16-prover/src/bin/print_proof_c.rs)), each of these points is built by naive scalar-by-scalar multiplication so that you can print the exact scalar being multiplied at every step. For the 4-constraint `SumOfProducts` circuit the scalars are different, but the formulas are identical.

Because the proof lives entirely on the BLS12-381 curve, it compresses to **192 bytes** (48 bytes for each G1 point, 96 bytes for the G2 point). This is the "succinct" in zk-SNARK.

---

## Verification: one equation

The verifier does not know the witness. It knows only:
- the proof `(A, B, C)`
- the public inputs (in our case: `1` and `100`)
- the verifying key `(α·G1, β·G2, γ·G2, δ·G2, Ψ_V_G1)`

The verifier first computes a **public-input commitment** `V` by taking a linear combination of the per-variable verification elements `Ψ_V_G1` weighted by the public input values. For our toy circuit with public inputs `[1, 100]`:

```
V = 1·Ψ_V_G1[0] + 100·Ψ_V_G1[1]
```

It then checks a single **pairing equation**:

```
e(A, B) == e(α·G1, β·G2) · e(C, δ·G2) · e(V, γ·G2)
```

where `e` is the bilinear pairing on BLS12-381. If the equation holds, the proof is valid. If it does not, the proof is rejected.

This is the entire verification algorithm. No witness reconstruction, no constraint evaluation, no polynomial division — just one multiplicative pairing equation. That is why Groth16 verification is so fast (milliseconds) and why it fits inside a Cardano transaction budget.

In our repo, the pairing check is implemented in [`src/bin/print_pairing.rs`](../../groth16-prover/src/bin/print_pairing.rs) and cross-checked bit-for-bit against an independent [Sage](https://www.sagemath.org/) script ([`sage/groth16.sage`](../../sage/groth16.sage)).

---

## Running it on Cardano

Cardano's Plutus V3 ships with native BLS12-381 primitives:

- `bls12_381_g1_element` and `bls12_381_g2_element` types
- `bls12_381_g1_scalar_mul`, `bls12_381_g2_scalar_mul`
- `bls12_381_miller_loop`
- `bls12_381_final_verify`

These are exactly the operations needed for the Groth16 pairing check. The Aiken standard library wraps them in a clean API under `aiken/crypto/bls12_381`.

Our [`aiken/groth16`](../../aiken/groth16/README.md) package implements a fully parameterized Groth16 verifier in Aiken. It accepts any verification key, any list of public inputs, and any proof, then runs the standard pairing check. The verifier has been validated against proofs produced by our Rust prover for the 3-gate multiplier, the 4-gate `SumOfProducts`, the 1,107-gate privacy spend, and the 1,911-gate Poseidon Merkle circuits.

The on-chain cost of verifying a Groth16 proof with ~5 public inputs is well within Cardano's per-transaction execution budget. This means a smart contract can release funds, grant access, or mint tokens based solely on the validity of a ZK proof — without ever learning the user's identity, credentials, or secret inputs.

---

## The full pipeline in our repo

Our `groth16-prover` crate implements the entire Groth16 lifecycle, with six progressively more optimized implementations. For this first-principles article we focus on **Implementation 1** (`DenseQapEngine` + `NaiveProver`), where every sub-step is explicit and printable:

| Step | Binary | What it prints |
|------|--------|---------------|
| 1.1 | `print_r1cs` | R1CS matrices `L`, `R`, `O` and the witness vector |
| 1.2 | `print_field` | The BLS12-381 scalar field `Fr` |
| 1.3–1.5 | `print_qap` | QAP polynomials `u_i(x)`, `v_i(x)`, `w_i(x)` and target `T(x)` |
| 1.6 | `print_toxic_waste` | Deterministic scalars `τ, α, β, γ, δ` |
| 1.7 | `print_srs` | SRS points `τ^i·G1`, `τ^i·G2` |
| 1.8 | `print_crs` | CRS fixed points `α·G1`, `β·G2`, `γ·G2`, `δ·G2` |
| 1.9 | `print_psi` | Per-variable proving/verification elements |
| 1.10 | `print_witness_polys` | Witness polynomials `l(x)`, `r(x)`, `o(x)` |
| 1.11 | `print_quotient` | Quotient `h(x) = (l·r − o) / T` |
| 1.12 | `print_proof_a` | Proof point `A` |
| 1.13 | `print_proof_b` | Proof point `B` |
| 1.14 | `print_proof_c` | Proof point `C` |
| 1.15 | `print_public_input` | Public-input commitment `V` |
| 1.16 | `print_pairing` | Final pairing check |

Run any step in isolation:

```bash
cd groth16-prover
cargo run --bin print_r1cs
cargo run --bin print_qap
cargo run --bin print_proof_a
...
```

To see the full pipeline for the new `SumOfProducts` circuit:

```bash
# 1. Compile the circuit
cd groth16-prover/circom/SumOfProducts
circom sum_of_products.circom --r1cs --wasm --sym --prime bls12381

# 2. Generate the witness (snarkjs, temporary)
snarkjs wtns calculate sum_of_products.wasm input.json witness.wtns

# 3. Dev ceremony → pk + vk
cd ../../cli
cargo run --release -- ceremony-dev \
  --circuit ../circom/SumOfProducts/sum_of_products.r1cs \
  --proving-key /tmp/sum_of_products.pk \
  --verifying-key /tmp/sum_of_products.vk

# 4. Prove
cargo run --release -- prove \
  --circuit ../circom/SumOfProducts/sum_of_products.r1cs \
  --witness ../circom/SumOfProducts/witness.wtns \
  --proving-key /tmp/sum_of_products.pk \
  --out /tmp/proof.bin

# 5. Export verifying key to Aiken
cargo run --release -- export-vk \
  --verifying-key /tmp/sum_of_products.vk \
  --out /tmp/sum_of_products_vk.ak

# 6. Verify on-chain: paste the proof bytes and public inputs [1, 100]
#    into an Aiken test using aiken/groth16/lib/groth16/verifier.ak
```

For the hard-coded 3-gate circuit, every printed scalar and every curve point has been cross-checked line-by-line against the independent Sage reference. The full bit-for-bit comparison is documented in [`RustGroth16Correctness.md`](../../groth16-prover/RustGroth16Correctness.md).

---

## Implementation walkthrough: Step 1.1 — R1CS matrices and witness

The binaries in our repository walk through every sub-step of the dense Groth16 pipeline. Each one corresponds to a numbered step in [`RustGroth16Correctness.md`](../../groth16-prover/RustGroth16Correctness.md). In this section we run them one by one, show the actual output, and derive the same numbers with pen and paper so you can see that nothing is hidden.

> **The circuit we trace.** The hard-coded `Implementation 1` uses the 3-gate multiplication chain from `multiplier.circom`:
> ```
> x5 = x1 * x2
> x6 = x3 * x4
> a  = x5 * x6
> ```
> Witness ordering: `[1, a, x1, x2, x3, x4, x5, x6]`
> With inputs `x1=2, x2=2, x3=3, x4=4` we get `x5=4, x6=12, a=48`.
>
> The witness vector is therefore **`[1, 48, 2, 2, 3, 4, 4, 12]`**.
>
> The 4-gate `SumOfProducts` circuit follows the exact same mathematics with one additional constraint; everything below generalises naturally.

---

### Step 1.1: R1CS matrices and witness

**What this step does.** Before any cryptography happens, we must express the circuit as a system of rank-1 constraints. Each constraint says: "the dot product of the left matrix row with the witness, multiplied by the dot product of the right matrix row with the witness, equals the dot product of the output matrix row with the witness."

**Paper and pencil.**

There are 3 multiplication gates, so we need 3 constraints. The witness vector has 8 entries:

```
w = [1, a, x1, x2, x3, x4, x5, x6]
    [0, 1,  2,  3,  4,  5,  6,  7]   <-- indices
```

**Constraint 0:** `x5 = x1 * x2`
- Left side picks `x1`  → `L[0][2] = 1`
- Right side picks `x2` → `R[0][3] = 1`
- Output picks `x5`     → `O[0][6] = 1`

**Constraint 1:** `x6 = x3 * x4`
- Left side picks `x3`  → `L[1][4] = 1`
- Right side picks `x4` → `R[1][5] = 1`
- Output picks `x6`     → `O[1][7] = 1`

**Constraint 2:** `a = x5 * x6`
- Left side picks `x5`  → `L[2][6] = 1`
- Right side picks `x6` → `R[2][7] = 1`
- Output picks `a`      → `O[2][1] = 1`

All other entries are zero.

**Running the code:**

```bash
cd groth16-prover
cargo run --bin print_r1cs
```

**Actual output:**

```
=== Step 1.1: R1CS Matrices and Witness ===

Witness a = [1, 48, 2, 2, 3, 4, 4, 12]

L matrix:
  [0, 0, 1, 0, 0, 0, 0, 0]
  [0, 0, 0, 0, 1, 0, 0, 0]
  [0, 0, 0, 0, 0, 0, 1, 0]

R matrix:
  [0, 0, 0, 1, 0, 0, 0, 0]
  [0, 0, 0, 0, 0, 1, 0, 0]
  [0, 0, 0, 0, 0, 0, 0, 1]

O matrix:
  [0, 0, 0, 0, 0, 0, 1, 0]
  [0, 0, 0, 0, 0, 0, 0, 1]
  [0, 1, 0, 0, 0, 0, 0, 0]

L · a = ["2", "3", "4"]
R · a = ["2", "4", "12"]
O · a = ["4", "12", "48"]

Element-wise (L·a) * (R·a):
  constraint 0: 2 * 2 = 4  (O·a = 4)   ✓
  constraint 1: 3 * 4 = 12 (O·a = 12)  ✓
  constraint 2: 4 * 12 = 48 (O·a = 48) ✓

✓ R1CS relation verified.
```

**Checking by hand:**

| Constraint | `L·a` | `R·a` | `(L·a)*(R·a)` | `O·a` | Match? |
|------------|-------|-------|---------------|-------|--------|
| 0 (`x5 = x1*x2`) | `x1 = 2` | `x2 = 2` | `4` | `x5 = 4` | ✓ |
| 1 (`x6 = x3*x4`) | `x3 = 3` | `x4 = 4` | `12` | `x6 = 12` | ✓ |
| 2 (`a = x5*x6`) | `x5 = 4` | `x6 = 12` | `48` | `a = 48` | ✓ |

The relation `(L·a) ∘ (R·a) = O·a` holds element-wise. This is the only thing the circuit "knows" — everything else in Groth16 is cryptography built on top of this simple matrix equation.

---

### Step 1.2: The finite field

**What this step does.** Every number in the circuit — the witness values, the matrix entries, the polynomial coefficients, the secret scalars — lives inside a **finite field**, not the integers you learned in school. A finite field is a set of numbers with a fixed size, where addition, subtraction, multiplication, and division (except by zero) always stay inside the set. Think of it as clock arithmetic, but with a prime number of hours instead of 12.

Groth16 needs a **prime field** because polynomials behave well over prime fields: a polynomial of degree `d` has at most `d` roots, and every non-zero number has a multiplicative inverse. These properties are essential for the QAP construction and the pairing check.

**Why BLS12-381.** The field we use is the **scalar field** of the BLS12-381 elliptic curve, denoted **Fr**. This is the field in which the curve's group order lives. We choose BLS12-381 because it is *pairing-friendly*: it supports a bilinear map `e: G1 × G2 → GT` that Groth16 verification depends on. And we choose it specifically for Cardano because Plutus V3 already has native BLS12-381 builtins.

**Paper and pencil.**

The modulus of Fr is the prime `q`:

```
q = 52435875175126190479447740508185965837690552500527637822603658699938581184513
```

This is a 253-bit prime. Every field element is an integer in the range `[0, q−1]`. Addition and multiplication are followed by a modulo `q` reduction. Subtraction is handled by adding `q` if the result is negative. Division is multiplication by the modular inverse, which exists for every non-zero element because `q` is prime.

**The modular inverse.** In a prime field, Fermat's little theorem tells us that for any `a ≠ 0`:

```
a^(q−2) ≡ a^(−1)  (mod q)
```

So the inverse of `5` is `5^(q−2) mod q`. This is a gigantic exponent, but fast modular exponentiation (square-and-multiply) handles it in O(log q) steps. The Rust implementation uses arkworks' optimised field arithmetic.

**Running the code:**

```bash
cargo run --bin print_field
```

**Actual output:**

```
=== Step 1.2: BLS12-381 Scalar Field Fr ===

Fr modulus q = 52435875175126190479447740508185965837690552500527637822603658699938581184513

Sample operations:
  a = 5
  b = 7
  a + b = 12
  a * b = 35
  a^-1  = 31461525105075714287668644304911579502614331500316582693562195219963148710708

Larger sample operations:
  c = 123456789
  d = 987654321
  c + d = 1111111110
  c * d = 121932631112635269
  c^-1  = 33425547577840145493174542821492773921169917356880302182737906958068561524687
```

**Checking by hand:**

The small numbers (`5 + 7 = 12`, `5 * 7 = 35`) do not exceed `q`, so the modulo reduction is invisible. But the inverse is where the field magic happens. Let us verify that `5 * 5^(−1) ≡ 1 (mod q)`.

The printed inverse of `5` is:

```
inv5 = 31461525105075714287668644304911579502614331500316582693562195219963148710708
```

Multiplying:

```
5 * inv5 = 157307625525378571438343221524557897513071657501582913467810976099815743553540
```

Now divide by `q`. A quick observation: `5 * inv5` is very close to `3 * q`:

```
3 * q = 157307625525371371438343221524547897513071657501582913467810976099815743553539
```

The difference is exactly `1`. Therefore:

```
5 * inv5 ≡ 1  (mod q)   ✓
```

This confirms the inverse is correct. Every division in the Groth16 pipeline — computing `h(x)`, scaling by `1/δ`, mixing `α` and `β` — relies on this property.

> **Why the constant `1` appears in the witness.** The first entry of every witness vector is always `1`. In the field Fr, `1` is the multiplicative identity: `1 * a = a` for any `a`. It serves as a "bias" term that lets constraints add constants without extra variables. For example, if a constraint needed to add `3` to a product, the matrix would include `3` in the column corresponding to the constant wire `w[0] = 1`.

---

### Step 1.3–1.5: QAP polynomials and target polynomial

**What these steps do.** The R1CS matrices are a *discrete* description of the circuit: they tell us what happens at each constraint index `j = 0, 1, 2`. Cryptography needs a *continuous* description: polynomials that encode the same information, so that checking the circuit reduces to checking a single identity between polynomials. The transformation from matrices to polynomials is the **Quadratic Arithmetic Program (QAP)**.

For each wire `i` we build three polynomials `u_i(x)`, `v_i(x)`, `w_i(x)` such that at constraint point `j`:

```
u_i(j) = L[j][i]
v_i(j) = R[j][i]
w_i(j) = O[j][i]
```

The simplest way to do this is **Lagrange interpolation**: we pick three distinct points (our constraint indices `0, 1, 2`), build the three *Lagrange basis polynomials* that are `1` at one point and `0` at the others, and use them as a basis.

**Paper and pencil.**

The Lagrange basis for points `{0, 1, 2}` is:

```
L_0(x) = (x−1)(x−2) / 2       =  ½x² − ³⁄₂x + 1
L_1(x) = x(x−2) / (−1)        = −x² + 2x
L_2(x) = x(x−1) / 2           =  ½x² − ½x
```

(All arithmetic is in Fr, so "½" means the modular inverse of `2`, which is `2^(−1) = (q+1)/2`.)

Because our R1CS matrices contain only `0` and `1`, each QAP polynomial is simply one of these basis polynomials (or zero). For example:

- Wire `2` (which is `x1`) appears on the left side of constraint `0` only, so `u_2(x) = L_0(x)`.
- Wire `4` (which is `x3`) appears on the left side of constraint `1` only, so `u_4(x) = L_1(x)`.
- Wire `6` (which is `x5`) appears on the left side of constraint `2` only, so `u_6(x) = L_2(x)`.

The same pattern holds for `v_i` and `w_i`.

**The target polynomial.** If the witness is correct, then at every constraint point `j`:

```
l(j) · r(j) = o(j)
```

where `l(x) = Σ a_i·u_i(x)`, `r(x) = Σ a_i·v_i(x)`, `o(x) = Σ a_i·w_i(x)`. This means the polynomial `l(x)·r(x) − o(x)` is zero at `x = 0, 1, 2`. Therefore it is divisible by:

```
T(x) = (x−0)(x−1)(x−2) = x³ − 3x² + 2x
```

`T(x)` is called the **target polynomial** (or vanishing polynomial). Its roots are exactly the constraint points.

**Running the code:**

```bash
cargo run --bin print_qap
```

**Actual output (excerpt):**

```
=== Step 1.3: QAP Polynomial Interpolation ===

u_2 coeffs = ["1", "26217937587563095239723870254092982918845276250263818911301829349969290592255",
              "26217937587563095239723870254092982918845276250263818911301829349969290592257"]
...

=== Step 1.5: QAP Verification at Constraint Points ===

  x = 0: all u_i, v_i, w_i match L, R, O columns
  x = 1: all u_i, v_i, w_i match L, R, O columns
  x = 2: all u_i, v_i, w_i match L, R, O columns

✓ All 24 evaluations (8 variables × 3 points) pass.

=== Step 1.4: Target Polynomial T(x) ===

T coeffs = ["0", "2", "52435875175126190479447740508185965837690552500527637822603658699938581184510", "1"]

T(x) vanishes at all constraint points:
  T(0) = 0
  T(1) = 0
  T(2) = 0

✓ Target polynomial verified.
```

**Checking by hand:**

Let us verify `T(x) = x³ − 3x² + 2x` in Fr. The printed coefficients are `[0, 2, q−3, 1]`, which means:

```
T(x) = 0 + 2x + (q−3)x² + 1·x³
     ≡ 2x − 3x² + x³   (mod q)
     = x(x−1)(x−2)
```

Now check the roots:

| x | T(x) = x³ − 3x² + 2x | Result |
|---|------------------------|--------|
| 0 | 0 − 0 + 0 | `0` ✓ |
| 1 | 1 − 3 + 2 | `0` ✓ |
| 2 | 8 − 12 + 4 | `0` ✓ |

All three constraint points are roots, so `T(x)` is indeed the vanishing polynomial.

**Why this matters.** The QAP transformation lets us replace "check every constraint individually" with "check that one big polynomial is divisible by `T(x)`". And polynomial divisibility can be checked at a single secret point `τ` — this is the foundation of the Groth16 proof.

---

### Step 1.6: Toxic waste

**What this step does.** Groth16 needs five secret scalars — traditionally called **toxic waste** because if any party learns them after the setup, they can forge proofs. In a production deployment these are generated jointly by multiple participants in an MPC ceremony and immediately destroyed. In our pedagogical implementation we fix them to small prime numbers so every intermediate value is deterministic and printable.

**Paper and pencil.**

The five scalars and their roles are:

| Scalar | Value | Role |
|--------|-------|------|
| `τ` (tau)   | 3   | Secret evaluation point for all polynomials |
| `α` (alpha) | 5   | Mixed term that binds proof element `C` to the left input |
| `β` (beta)  | 7   | Mixed term that binds proof element `C` to the right input |
| `γ` (gamma) | 11  | Denominator for the **public-input** CRS elements |
| `δ` (delta) | 13  | Denominator for the **private-input** CRS elements |

Why these specific values? They must be:
1. **Non-zero** — zero would collapse the pairing equation.
2. **Distinct** — if `α = β`, the proof loses its binding property.
3. **Invertible** — every scalar must have a modular inverse in Fr (true for any non-zero element since `q` is prime).

Small primes are ideal for debugging: `τ = 3` means `τ² = 9`, `τ³ = 27`, and so on, all easy to verify by hand. In production, `τ` would be a random 253-bit number.

**Running the code:**

```bash
cargo run --bin print_toxic_waste
```

**Actual output:**

```
=== Step 1.6: Toxic Waste (Fixed Deterministic Values) ===

Field modulus q = 52435875175126190479447740508185965837690552500527637822603658699938581184513

tau   = 3 (decimal)
alpha = 5 (decimal)
beta  = 7 (decimal)
gamma = 11 (decimal)
delta = 13 (decimal)

✓ All five toxic-waste values are non-zero, distinct, and invertible.
✓ Step 1.6 printouts complete.
```

**Checking by hand:**

All five values are ordinary integers smaller than `q`, so they need no modular reduction. The inverses are:

- `3^(−1) mod q = (q+1)/3`  (exists because `q ≡ 1 (mod 3)`)
- `5^(−1) mod q` — we already computed this in Step 1.2
- `7^(−1)`, `11^(−1)`, `13^(−1)` — all exist because `q` is prime and none of these divide `q`.

The distinction between `γ` and `δ` is what separates public inputs from private inputs in the proof. Public wires (the constant `1` and the output `a`) are divided by `γ`; private wires (the secret multipliers `x1..x4` and intermediates `x5, x6`) are divided by `δ`. This separation is what lets the verifier reconstruct the public-input commitment `V` without knowing the witness.

---

### Step 1.7: Structured Reference String (SRS)

**What this step does.** The SRS is the set of elliptic-curve points that the prover needs to build a proof. It is computed during the trusted setup by multiplying the curve generators `G1` and `G2` by powers of the secret scalar `τ`. Because the raw scalar `τ` is never stored — only its "shadows" on the curve — the prover can evaluate polynomials at `τ` without knowing `τ` itself. This is the core security mechanism of Groth16: the proof is built *in the exponent*.

**Paper and pencil.**

The SRS has three parts:

1. **SRS1** — `τ^i · G1` for `i = 0, 1, 2, ...`  
   Used to compute `l(τ)·G1` and other left-side terms.

2. **SRS2** — `τ^i · G2` for `i = 0, 1, 2, ...`  
   Used to compute `r(τ)·G2` and other right-side terms.

3. **SRS3** — `T(τ)·τ^i / δ · G1` for `i = 0, 1, 2, ...`  
   Used to compute the quotient term `h(τ)·T(τ)/δ·G1` in proof element `C`.

For our toy circuit we only need powers up to `τ²` because the highest-degree polynomial we encounter is degree 2 (the QAP polynomials) and the target polynomial is degree 3.

First, compute `T(τ)`:

```
T(x) = x³ − 3x² + 2x
T(3) = 27 − 27 + 6 = 6
```

This is the key scalar that appears in SRS3. The base scalar for SRS3 is `T(τ)/δ = 6/13`, which is `6 · 13^(−1) mod q`. The printed value is `4033528859625091575342133885245074295206965576963664447892589130764506244963`; we trust the library for the exact modular inverse, but we can verify that multiplying it by `13` gives `6` modulo `q`.

**Running the code:**

```bash
cargo run --bin print_srs
```

**Actual output (excerpt):**

```
=== Step 1.7: SRS Points ===

T(tau) = 6  (tau = 3, T(x) = x^3 - 3x^2 + 2x)

--- SRS1 : G1 * tau^i ---
SRS1[0] scalar = tau^0 = 1
         x = 3685416753713387016781088315183077757961620795782546409894578378688607592378376318836054947676345821548104185464507
         y = 1339506544944476473020471379941921221584933875938349620426543736416511423956333506472724655353366534992391756441569
SRS1[1] scalar = tau^1 = 3
         x = 1527649530533633684281386512094328299672026648504329745640827351945739272160755686119065091946435084697047221031460
         y = 487897572011753812113448064805964756454529228648704488481988876974355015977479905373670519228592356747638779818193
SRS1[2] scalar = tau^2 = 9
...

--- SRS2 : G2 * tau^i ---
SRS2[0] scalar = tau^0 = 1
         x = QuadExtField(352701069587466618187139116011060144890029952792775240219908644239793785735715026873347600343865175952761926303160 + ...)
...

--- SRS3 : G1 * T(tau) * tau^i / delta ---
Base scalar = T(tau)/delta = 4033528859625091575342133885245074295206965576963664447892589130764506244963
SRS3[0] scalar = T(tau)*tau^0/delta = 4033528859625091575342133885245074295206965576963664447892589130764506244963
...
SRS3[1] scalar = T(tau)*tau^1/delta = 12100586578875274726026401655735222885620896730890993343677767392293518734889
...
```

**Checking by hand:**

The only thing we can conveniently verify without a computer is `T(τ)`:

```
T(3) = 3³ − 3·3² + 2·3
     = 27 − 27 + 6
     = 6   ✓
```

This matches the printed `T(tau) = 6`.

For the curve points, the coordinates are the result of scalar multiplication on BLS12-381. The generator `G1` has known standard coordinates (set by the BLS12-381 specification), and multiplying it by `3` or `9` produces the printed `(x, y)` values. We do not verify these by hand — that would require implementing the full elliptic-curve group law — but we trust that arkworks computes them correctly. The important point is that the *scalars* (`1, 3, 9, 6/13, 18/13, ...`) are exactly the values dictated by the trusted-setup formulas.

> **What the SRS really is.** Think of the SRS as a "power table" for a secret base `τ`. Just as you can compute `f(2)` for any polynomial `f` if you know the powers `2⁰, 2¹, 2², ...`, the prover can compute `f(τ)·G1` for any polynomial `f` if it knows `τ⁰·G1, τ¹·G1, τ²·G1, ...`. The twist is that `τ` is never revealed — only its encrypted shadows on the curve. This is why the setup is called "trusted": someone must know `τ` long enough to compute the SRS, then destroy it forever.

---

### Step 1.8: CRS fixed points

**What this step does.** In addition to the SRS power tables, Groth16 needs four "fixed" curve points that encode the mixed scalars `α`, `β`, `γ`, and `δ` directly. These points appear in the verification equation exactly as printed — they are not indexed by a power of `τ`. Together with the SRS, they form the **Common Reference String (CRS)**, the complete set of public parameters that both prover and verifier share.

**Paper and pencil.**

The four fixed points are:

| Point | Formula | Group | Role in the protocol |
|-------|---------|-------|---------------------|
| `α·G1` | `alpha * G1` | G1 | Binds the left witness polynomial to proof element `C` |
| `β·G2` | `beta * G2` | G2 | Binds the right witness polynomial to proof element `B` |
| `γ·G2` | `gamma * G2` | G2 | Denominator for the public-input commitment `V` |
| `δ·G2` | `delta * G2` | G2 | Denominator for the private-input commitment in `C` |

With our deterministic scalars:

```
α·G1 = 5·G1
β·G2 = 7·G2
γ·G2 = 11·G2
δ·G2 = 13·G2
```

These are the points that the verifier will pair in the final equation:

```
e(A, B) == e(α·G1, β·G2) · e(C, δ·G2) · e(V, γ·G2)
```

Notice that `α·G1` and `β·G2` are paired together on the right-hand side — this is the "master" pairing that anchors the entire equation. The `γ·G2` and `δ·G2` points separate public inputs from private inputs.

**Running the code:**

```bash
cargo run --bin print_crs
```

**Actual output (excerpt):**

```
=== Step 1.8: CRS Fixed Points ===

--- alpha * G1 ---
scalar = alpha = 5
x = 2601793266141653880357945339922727723793268013331457916525213050197274797722760296318099993752923714935161798464476
y = 3498096627312022583321348410616510759186251088555060790999813363211667535344132702692445545590448314959259020805858

--- beta * G2 ---
scalar = beta = 7
x = QuadExtField(709940604317203372084363045234008717826848775332345256708783709065481460296552174594695120412283630827121870605628 + ...)
...

--- gamma * G2 ---
scalar = gamma = 11
...

--- delta * G2 ---
scalar = delta = 13
...
```

**Checking by hand:**

The scalars are trivially correct: `5, 7, 11, 13`. The curve coordinates are again the result of scalar multiplication on BLS12-381, which we do not verify manually. The important thing is that these four points are exactly the ones that will appear in the pairing check in Step 1.16.

> **The CRS vs. the SRS.** The SRS is the *power table* (`τ^i·G1`, `τ^i·G2`) — it lets the prover evaluate arbitrary polynomials at `τ`. The CRS *fixed points* are the *anchor points* (`α·G1`, `β·G2`, `γ·G2`, `δ·G2`) — they encode the mixed scalars that tie the proof to the specific circuit. In a production trusted setup, the SRS is universal (can be reused for many circuits), while the CRS fixed points are circuit-specific because they depend on `α`, `β`, `γ`, `δ`.

---

### Step 1.9: Per-variable CRS

**What this step does.** The prover needs a way to turn the witness values into curve points for proof element `C`. For each wire `i`, the trusted setup computes a scalar that encodes the wire's QAP polynomials evaluated at `τ`, mixed with `α` and `β`, and scaled by either `1/γ` (for public wires) or `1/δ` (for private wires). These scalars are multiplied by `G1` to produce the **per-variable CRS** points.

**Paper and pencil.**

For each wire `i`, compute:

```
combined_i = v_i(τ)·α + u_i(τ)·β + w_i(τ)
```

Then:
- If `i` is a **public** wire: `psi_scalar_i = combined_i / γ`
- If `i` is a **private** wire: `psi_scalar_i = combined_i / δ`

The point is `psi_scalar_i · G1`.

**Public wires** in our circuit: wire `0` (the constant `1`) and wire `1` (the output `a`).

**Private wires**: everything else (`x1` through `x6`).

Let us verify two examples.

**Variable 1 (output `a`, public):**
- `u_1(τ) = 0` (wire 1 never appears on the left)
- `v_1(τ) = 0` (wire 1 never appears on the right)
- `w_1(τ) = 3` (wire 1 is the output of constraint 2; `w_1(x) = L_2(x)`, so `w_1(3) = 3`)

```
combined_1 = 0·5 + 0·7 + 3 = 3
psi_scalar_1 = 3 / 11 = 3 · 11^(−1) mod q
             = 38135181945546320348689265824135247881956765454929191143711751781773513588737
```

This matches the printed value exactly. ✓

**Variable 2 (input `x1`, private):**
- `u_2(τ) = 1` (wire 2 is the left input of constraint 0; `u_2(x) = L_0(x)`, so `u_2(3) = 1`)
- `v_2(τ) = 0`
- `w_2(τ) = 0`

```
combined_2 = 0·5 + 1·7 + 0 = 7
psi_scalar_2 = 7 / 13 = 7 · 13^(−1) mod q
             = 48402346315501098904105606622940891542483586923563973374711069569174074939551
```

This also matches exactly. ✓

**Variable 0 (constant `1`, public):**
- `u_0(τ) = v_0(τ) = w_0(τ) = 0` (the constant wire never appears in any constraint matrix)
- `combined_0 = 0`, so `psi_scalar_0 = 0`
- The point is the **point at infinity** (the identity element of the curve group).

This is why the first public-input commitment term `1 · Ψ_V_G1[0]` contributes nothing — multiplying the identity by `1` still gives the identity.

**Running the code:**

```bash
cargo run --bin print_psi
```

**Actual output (excerpt):**

```
=== Step 1.9: Per-Variable CRS ===

tau = 3, alpha = 5, beta = 7, gamma = 11, delta = 13

--- Psi_V_G1 (public inputs, divided by gamma) ---
Variable 0: ... point = (point at infinity)
Variable 1: combined scalar = 3
  psi_scalar = 38135181945546320348689265824135247881956765454929191143711751781773513588737
  ...

--- Psi_P_G1 (private inputs, divided by delta) ---
Variable 2: combined scalar = 7
  psi_scalar = 48402346315501098904105606622940891542483586923563973374711069569174074939551
  ...
```

**Checking by hand:**

The two verifications above (Variable 1 and Variable 2) confirm that the per-variable scalars are computed exactly as the Groth16 specification dictates. The remaining variables follow the same pattern:

| Variable | Wire | `u(τ)` | `v(τ)` | `w(τ)` | Combined | `÷ γ` or `÷ δ` |
|----------|------|--------|--------|--------|----------|----------------|
| 0 | `1` (const) | 0 | 0 | 0 | 0 | `0` (infinity) |
| 1 | `a` (out) | 0 | 0 | 3 | 3 | `3/11` |
| 2 | `x1` | 1 | 0 | 0 | 7 | `7/13` |
| 3 | `x2` | 0 | 1 | 0 | 5 | `5/13` |
| 4 | `x3` | `L_1(3)=−3` | 0 | 0 | `−21` | `−21/13` |
| 5 | `x4` | 0 | `L_1(3)=−3` | 0 | `−15` | `−15/13` |
| 6 | `x5` | `L_2(3)=3` | 0 | `L_0(3)=1` | 22 | `22/13` |
| 7 | `x6` | 0 | `L_2(3)=3` | `L_1(3)=−3` | 12 | `12/13` |

> **Why this is the heart of the proof.** Proof element `C` is computed as `Σ a_i · Psi_P_G1[i] + h(τ)·T(τ)/δ·G1`. The per-variable CRS points are what let the prover "commit" to the witness values inside the proof, without ever revealing them. The verifier, meanwhile, recomputes the public-input commitment `V = Σ a_i · Psi_V_G1[i]` from the public wires only. Because public and private wires are divided by different denominators (`γ` vs. `δ`), the verifier can isolate the public part without learning the private part.

---

### Step 1.10: Witness polynomials

**What this step does.** The witness polynomials `l(x)`, `r(x)`, `o(x)` are formed by taking a linear combination of the QAP basis polynomials `u_i(x)`, `v_i(x)`, `w_i(x)` weighted by the witness values. If the witness is correct, then at every constraint point `j` we must have `l(j) · r(j) = o(j)`. This is the polynomial analogue of the R1CS relation `(L·a) ∘ (R·a) = O·a`.

**Paper and pencil.**

```
l(x) = Σ a_i · u_i(x)
r(x) = Σ a_i · v_i(x)
o(x) = Σ a_i · w_i(x)
```

With our witness `a = [1, 48, 2, 2, 3, 4, 4, 12]` and the QAP polynomials from Step 1.3:

**`l(x)`** — only wires `2, 4, 6` have non-zero `u_i`:

```
l(x) = 2·u_2(x) + 3·u_4(x) + 4·u_6(x)
     = 2·L_0(x) + 3·L_1(x) + 4·L_2(x)
     = 2·(½x² − ³⁄₂x + 1) + 3·(−x² + 2x) + 4·(½x² − ½x)
     = (x² − 3x + 2) + (−3x² + 6x) + (2x² − 2x)
     = x + 2
```

So `l(x) = 2 + x`, a degree-1 polynomial. The coefficients are `[2, 1]`.

**`r(x)`** — only wires `3, 5, 7` have non-zero `v_i`:

```
r(x) = 2·v_3(x) + 4·v_5(x) + 12·v_7(x)
     = 2·L_0(x) + 4·L_1(x) + 12·L_2(x)
     = 2·(½x² − ³⁄₂x + 1) + 4·(−x² + 2x) + 12·(½x² − ½x)
     = (x² − 3x + 2) + (−4x² + 8x) + (6x² − 6x)
     = 3x² − x + 2
```

In Fr, the coefficient of `x` is `−1 ≡ q−1`. The coefficients are `[2, q−1, 3]`.

**`o(x)`** — only wires `1, 6, 7` have non-zero `w_i`:

```
o(x) = 48·w_1(x) + 4·w_6(x) + 12·w_7(x)
     = 48·L_2(x) + 4·L_0(x) + 12·L_1(x)
     = 48·(½x² − ½x) + 4·(½x² − ³⁄₂x + 1) + 12·(−x² + 2x)
     = (24x² − 24x) + (2x² − 6x + 4) + (−12x² + 24x)
     = 14x² − 6x + 4
```

In Fr, the coefficient of `x` is `−6 ≡ q−6`. The coefficients are `[4, q−6, 14]`.

**Running the code:**

```bash
cargo run --bin print_witness_polys
```

**Actual output:**

```
=== Step 1.10: Witness Polynomials l(x), r(x), o(x) ===

Witness a = [1, 48, 2, 2, 3, 4, 4, 12]

l(x) degree = 1, coeffs = ["2", "1"]
r(x) degree = 2, coeffs = ["2", "52435875175126190479447740508185965837690552500527637822603658699938581184512", "3"]
o(x) degree = 2, coeffs = ["4", "52435875175126190479447740508185965837690552500527637822603658699938581184507", "14"]

Evaluation at constraint points:
  x = 0: l(x) = 2, r(x) = 2, o(x) = 4
  x = 1: l(x) = 3, r(x) = 4, o(x) = 12
  x = 2: l(x) = 4, r(x) = 12, o(x) = 48

✓ l(x)*r(x) == o(x) at all constraint points.
```

**Checking by hand:**

First, verify the coefficients match our derivations:

| Polynomial | Derived coefficients | Printed coefficients | Match? |
|------------|---------------------|---------------------|--------|
| `l(x)` | `[2, 1]` | `[2, 1]` | ✓ |
| `r(x)` | `[2, −1, 3]` → `[2, q−1, 3]` | `[2, q−1, 3]` | ✓ |
| `o(x)` | `[4, −6, 14]` → `[4, q−6, 14]` | `[4, q−6, 14]` | ✓ |

Next, verify the evaluations at constraint points:

| x | `l(x)` | `r(x)` | `l(x)·r(x)` | `o(x)` | Match? |
|---|--------|--------|-------------|--------|--------|
| 0 | `2+0=2` | `2−0+0=2` | `4` | `4−0+0=4` | ✓ |
| 1 | `2+1=3` | `2−1+3=4` | `12` | `4−6+14=12` | ✓ |
| 2 | `2+2=4` | `2−2+12=12` | `48` | `4−12+56=48` | ✓ |

At every constraint point, `l(j)·r(j) = o(j)`. This means the polynomial `l(x)·r(x) − o(x)` has roots at `0, 1, 2`, so it is divisible by `T(x) = (x−0)(x−1)(x−2)`. The next step computes this division explicitly.

---

### Step 1.11: Quotient polynomial

**What this step does.** We have established that `l(x)·r(x) − o(x)` vanishes at every constraint point, so it must be divisible by the target polynomial `T(x)`. The **quotient polynomial** `h(x)` is defined as:

```
h(x) = (l(x)·r(x) − o(x)) / T(x)
```

If the division has zero remainder, the constraints are satisfied. If there is a non-zero remainder, the witness is invalid. In Groth16, the prover computes `h(x)` explicitly and evaluates it at `τ` to build proof element `C`.

**Paper and pencil.**

First, multiply `l(x)` and `r(x)`:

```
l(x) = 2 + x
r(x) = 2 − x + 3x²

l(x)·r(x) = (2+x)(2−x+3x²)
          = 4 − 2x + 6x² + 2x − x² + 3x³
          = 4 + 5x² + 3x³
```

Subtract `o(x)`:

```
p(x) = l(x)·r(x) − o(x)
     = (4 + 5x² + 3x³) − (4 − 6x + 14x²)
     = 6x − 9x² + 3x³
     = 3x³ − 9x² + 6x
```

Factor out `T(x) = x³ − 3x² + 2x`:

```
p(x) = 3x(x² − 3x + 2)
     = 3x(x−1)(x−2)
     = 3 · T(x)
```

Therefore:

```
h(x) = p(x) / T(x) = 3
```

The quotient is a **constant** `3`. This happens because our witness values were chosen to make the arithmetic particularly clean.

**Running the code:**

```bash
cargo run --bin print_quotient
```

**Actual output:**

```
=== Step 1.11: Quotient Polynomial h(x) ===

l(x) degree = 1, coeffs = ["2", "1"]
r(x) degree = 2, coeffs = ["2", "52435875175126190479447740508185965837690552500527637822603658699938581184512", "3"]
o(x) degree = 2, coeffs = ["4", "52435875175126190479447740508185965837690552500527637822603658699938581184507", "14"]
T(x) degree = 3, coeffs = ["", "2", "52435875175126190479447740508185965837690552500527637822603658699938581184510", "1"]

p(x) = l(x)*r(x) - o(x) degree = 3, coeffs = ["", "6", "52435875175126190479447740508185965837690552500527637822603658699938581184504", "3"]
h(x) = leading_coeff(p) / leading_coeff(T) = 3 / 1 = 3
h(x) degree = 0, coeffs = ["3"]

T(x) * h(x) degree = 3, coeffs = ["", "6", "52435875175126190479447740508185965837690552500527637822603658699938581184504", "3"]

✓ p(x) == T(x) * h(x) — zero remainder confirmed.
```

**Checking by hand:**

| Polynomial | Derived coefficients | Printed coefficients | Match? |
|------------|---------------------|---------------------|--------|
| `p(x)` | `[0, 6, −9, 3]` → `[0, 6, q−9, 3]` | `[0, 6, q−9, 3]` | ✓ |
| `h(x)` | `[3]` | `[3]` | ✓ |
| `T(x)·h(x)` | `[0, 6, q−9, 3]` | `[0, 6, q−9, 3]` | ✓ |

The remainder is zero, so `h(x) = 3` is indeed the exact quotient. In the proof, the prover will evaluate `h(τ) = 3` and multiply it by `T(τ)/δ · G1` from SRS3 to produce part of proof element `C`.

> **The core Groth16 trick.** Instead of checking `l(j)·r(j) = o(j)` at every constraint point `j` (which would be `O(n)` work), the prover checks it at a single secret point `τ` by verifying that `h(τ) = (l(τ)·r(τ) − o(τ)) / T(τ)`. Because `h(x)` exists (zero remainder), this equality holds at `τ` if and only if it holds at all constraint points. The proof element `C` encodes `h(τ)` in the exponent, and the verifier checks it via the pairing equation.

---

### Step 1.12: Proof element A

**What this step does.** Proof element `A` encodes the left witness polynomial `l(x)` evaluated at `τ`, mixed with the scalar `α`. In the dense pedagogical path, the prover computes `l(τ)` directly from the coefficients and then adds `α`.

**Paper and pencil.**

```
l(x) = 2 + x
l(τ) = l(3) = 2 + 3 = 5

A = (l(τ) + α) · G1
  = (5 + 5) · G1
  = 10 · G1
```

The combined scalar is `10`.

**Running the code:**

```bash
cargo run --bin print_proof_a
```

**Actual output:**

```
=== Step 1.12: Proof Element A ===

l(x) = ["2", "1"]
l(tau) = 5  (tau = 3)
alpha = 5

A = l(tau)*G1 + alpha*G1
  combined scalar = l(tau) + alpha = 10
  x = 2386781901035473772144341182407687860118005925033428055218509614629770831545237878364312588177396809142590665502445
  y = 2721985711015193199868848835229056819857651383925471979786755635273858421658233285328399263507021600622741844499993

✓ Proof element A computed and verified.
```

**Checking by hand:** `5 + 5 = 10`. The combined scalar is correct. ✓

---

### Step 1.13: Proof element B

**What this step does.** Proof element `B` encodes the right witness polynomial `r(x)` evaluated at `τ`, mixed with the scalar `β`. It lives in G2, which is why it is larger (96 bytes compressed instead of 48).

**Paper and pencil.**

```
r(x) = 2 − x + 3x²
r(τ) = r(3) = 2 − 3 + 27 = 26

B = (r(τ) + β) · G2
  = (26 + 7) · G2
  = 33 · G2
```

The combined scalar is `33`.

**Running the code:**

```bash
cargo run --bin print_proof_b
```

**Actual output:**

```
=== Step 1.13: Proof Element B ===

r(x) = ["2", "52435875175126190479447740508185965837690552500527637822603658699938581184512", "3"]
r(tau) = 26  (tau = 3)
beta = 7

B = r(tau)*G2 + beta*G2
  combined scalar = r(tau) + beta = 33
  ... (G2 coordinates)

✓ Proof element B computed and verified.
```

**Checking by hand:** `26 + 7 = 33`. The combined scalar is correct. ✓

---

### Step 1.14: Proof element C

**What this step does.** Proof element `C` is the most complex. It has two parts:
1. A linear combination of the per-variable CRS points `Psi_P_G1`, weighted by the witness values.
2. The quotient term `h(τ)·T(τ)/δ · G1`.

Part 1 commits the prover to the private witness values; part 2 encodes the fact that the constraints are satisfied.

**Paper and pencil.**

Part 1 — private wire contributions:

```
Σ a_i · Psi_P_G1[i] = 2·(7/13) + 2·(5/13) + 3·(−21/13) + 4·(−15/13) + 4·(22/13) + 12·(12/13)
                    = (14 + 10 − 63 − 60 + 88 + 144) / 13
                    = 133/13
```

Part 2 — quotient term:

```
h(τ)·T(τ)/δ = 3 · 6 / 13 = 18/13
```

Total scalar for `C`:

```
C_scalar = 133/13 + 18/13 = 151/13
```

In Fr this is `151 · 13^(−1) mod q`, a large number that the library computes for us.

**Running the code:**

```bash
cargo run --bin print_proof_c
```

**Actual output (excerpt):**

```
=== Step 1.14: Proof Element C ===

--- Psi_P_G1 accumulation ---
Variable 2: a_i = 2, psi_scalar = 48402346315501098904105606622940891542483586923563973374711069569174074939551, contribution = 44368817455876007328763472737695817247276621346600308926818480438409568694589
...

T(tau) = 6
h(x) = 3
h_tau_G1 scalar = h * T(tau) / delta = 12100586578875274726026401655735222885620896730890993343677767392293518734889

C = sum(a_i * Psi_P_G1) + h_tau_G1
  ...

Total combined scalar = 40335288596250915753421338852450742952069655769636644478925891307645062449637
```

**Checking by hand:**

We verify that `13 · C_scalar ≡ 151 (mod q)`:

```
13 · 40335288596250915753421338852450742952069655769636644478925891307645062449637
= 524358751751261904794477405081859658376905525005276378226036586999385811845281
= 10·q + 151
```

Reducing modulo `q` gives `151`. Therefore `C_scalar ≡ 151/13 (mod q)`. ✓

---

### Step 1.15: Public-input commitment V

**What this step does.** The verifier does not know the private witness values, but it does know the public inputs (the constant `1` and the output `a = 48`). It recomputes a commitment `V` by taking a linear combination of the public-input CRS points `Psi_V_G1` weighted by the public input values. This is the only part of the proof that the verifier can reconstruct on its own.

**Paper and pencil.**

Public wires: `a_0 = 1` (constant), `a_1 = 48` (output).

```
Psi_V_G1[0] = 0 · G1   (point at infinity, contributes nothing)
Psi_V_G1[1] = 3/11 · G1

V = 1·0 + 48·(3/11)
  = 144/11
```

**Running the code:**

```bash
cargo run --bin print_public_input
```

**Actual output:**

```
=== Step 1.15: Public-Input Commitment V ===

--- Psi_V_G1 accumulation ---
Variable 0: a_i = 1, psi_scalar = , contribution scalar =
Variable 1: a_i = 48, psi_scalar = 38135181945546320348689265824135247881956765454929191143711751781773513588737, contribution = 47668977431932900435861582280169059852445956818661488929639689727216891985934

V = sum(a_i * Psi_V_G1)
  ...

Total combined scalar = 47668977431932900435861582280169059852445956818661488929639689727216891985934
```

**Checking by hand:**

We verify that `11 · V_scalar ≡ 144 (mod q)`:

```
11 · 47668977431932900435861582280169059852445956818661488929639689727216891985934
= 524358751751261904794477405081859658376905525005276378226036586999385811845274
= 10·q + 144
```

Reducing modulo `q` gives `144`. Therefore `V_scalar ≡ 144/11 (mod q)`. ✓

---

### Step 1.16: Pairing check

**What this step does.** The verifier checks a single equation involving four pairings. If the equation holds, the proof is valid. If it does not, the proof is rejected. The equation is:

```
e(A, B) == e(α·G1, β·G2) · e(C, δ·G2) · e(V, γ·G2)
```

where `e` is the bilinear pairing on BLS12-381. The bilinearity property is what makes this work: `e(s·P, t·Q) = e(P, Q)^(s·t)`. The exponents on the right-hand side multiply in exactly the right way to balance the left-hand side.

**Paper and pencil.**

We already know the scalars:

```
A = 10 · G1
B = 33 · G2
α·G1 = 5 · G1
β·G2 = 7 · G2
C = (151/13) · G1
δ·G2 = 13 · G2
V = (144/11) · G1
γ·G2 = 11 · G2
```

Check the exponents:

- Left side: `e(10·G1, 33·G2) = e(G1, G2)^(10·33) = e(G1, G2)^330`
- Right side: `e(5·G1, 7·G2) · e((151/13)·G1, 13·G2) · e((144/11)·G1, 11·G2)`
           `= e(G1, G2)^(5·7) · e(G1, G2)^((151/13)·13) · e(G1, G2)^((144/11)·11)`
           `= e(G1, G2)^35 · e(G1, G2)^151 · e(G1, G2)^144`
           `= e(G1, G2)^(35 + 151 + 144)`
           `= e(G1, G2)^330`

Both sides have the same exponent: `330`. The pairing equation balances.

**Running the code:**

```bash
cargo run --bin print_pairing
```

**Actual output (excerpt):**

```
=== Step 1.16: Pairing Check ===

A = 10 * G1
B = 33 * G2
C = 40335288596250915753421338852450742952069655769636644478925891307645062449637 * G1
V = 47668977431932900435861582280169059852445956818661488929639689727216891985934 * G1

e(A, B)              = PairingOutput(...)
e(alpha*G1, beta*G2) = PairingOutput(...)
e(C, delta*G2)       = PairingOutput(...)
e(V, gamma*G2)       = PairingOutput(...)

product RHS          = PairingOutput(...)

✓ Pairing check PASSED. The proof is valid.
```

**Checking by hand:**

The scalar arithmetic balances (`10·33 = 35 + 151 + 144 = 330`). The actual pairing values are elements of `F_q^12`, represented as nested field extensions (`QuadExtField` of `CubicExtField`). We do not verify these 12-dimensional coordinates by hand — that would require implementing the full Miller loop and final exponentiation — but the scalar identity is the mathematical core, and it is the part that can be checked with pen and paper.

> **What just happened.** We started with a simple multiplication chain (`x5 = x1*x2`, `x6 = x3*x4`, `a = x5*x6`) and ended with a proof that consists of exactly three curve points: `A = 10·G1`, `B = 33·G2`, `C = (151/13)·G1`. The verifier checks these three points against the public inputs using one pairing equation. At no point did the prover reveal `x1, x2, x3, x4`. The entire witness — the secret multipliers and the intermediate products — is hidden inside the proof, yet the verifier is mathematically certain that the constraints were satisfied.
>
> This is the essence of Groth16: a 192-byte proof that hides arbitrarily large secrets while convincing any verifier of their validity.

---

## What's next

This installment deliberately stayed at the "dense monomial" level: polynomials stored as coefficient vectors, division performed by long division, and proof assembly done one scalar multiplication at a time. It is slow, but it is *transparent*. You can open any binary, add a `println!`, and see the exact value passing through the equation.

The next installment will show how each bottleneck is removed:

| Bottleneck | First-principles fix (this article) | Production fix (next article) |
|------------|-------------------------------------|-------------------------------|
| Polynomial ops are O(n²) | Dense coefficient vectors | FFT over roots of unity |
| Proof assembly is O(n) scalar muls | One-by-one multiplication | Pippenger multi-scalar multiplication |
| Matrices explode memory | Dense `Vec<Vec<Fr>>` | Native sparse constraint representation |
| Trusted setup is single-party | Deterministic dev scalars | Multi-party MPC ceremony on PPoT |
| QAP materialises all polynomials | `build_qap()` returns every `u_i(x)` | On-the-fly witness-polynomial accumulation |

We will also survey the landscape beyond Groth16:
- **PLONK** — universal trusted setup, custom gates, better recursion
- **Bulletproofs** — no trusted setup at all, but larger proofs and slower verification
- **STARKs / JOLT** — post-quantum, transparent setup, proof size trade-offs
- **VM approaches (RISC Zero, zkVMs)** — prove arbitrary program execution without circuit design

Finally, in the third installment, we will apply the production Groth16 pipeline to **selective disclosure** — the pattern where a credential holder proves they satisfy a predicate (`age ≥ 21`, `country ∈ approved set`) without revealing any field values or their blockchain address. The proof becomes the authorization, and the on-chain script verifies nothing but the mathematics.

The code for all three installments is available in the [cardano-foundation/bls](https://github.com/cardano-foundation/bls) repository.
