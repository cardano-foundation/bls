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
