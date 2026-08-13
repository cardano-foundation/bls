# Lova Folding Design

## Overview

**Lova** — *Lattice-Based Folding Scheme from Unstructured Lattices* (Fenzi, Knabenhans, Nguyen, Pham, ASIACRYPT 2024, [eprint 2024/1964](https://eprint.iacr.org/2024/1964); official Rust implementation in [lattirust/lova](https://github.com/lattirust/lova), built on the authors' [lattirust](https://github.com/cknabs/lattirust) library) — is the first folding scheme whose security relies on the **unstructured SIS assumption**. All arithmetic runs over hardware-friendly power-of-two moduli `q = 2^64`, so **no finite-field arithmetic is needed at all**. At its core lies a new **exact Euclidean norm proof** (of independent interest), which is what lets the verifier check the witness-norm bounds that SIS commitments require.

Every step below is annotated with how it overlaps with / diverges from **Impl 10** — BLS12-381 Nova folding + sumcheck final SNARK — in [`nova-prover`](../../nova-prover/README.md#implementation-10-constant-size-nova-proofs).

> **Status:** 🔬 **Research / evaluation.** Findings for the post-quantum track (`nova-prover` **Implementation 12** / **Pending item (v)**). No code here yet.

## Exact flow

### 1. Setup — transparent

Sample a uniformly random matrix `A` over `Z_q` with `q = 2^64` (power-of-two, no field library needed) and fix norm parameters (witness chunk size `B`, decomposition/digit base `b`, bounds `β`, `m`, `k`).

- *Overlap w/ Impl 10:* both are setup-free/trustless — our Pedersen basis is already derived deterministically from a fixed seed; no ceremony in either.
- *Discrepancy:* Lova uses `A·s mod 2^64` (Ajtai commitment, integer arithmetic, no inversions); Impl 10 uses Pedersen in G1 over BLS12-381 (DLOG-based).

### 2. Arithmetization

The step function becomes relaxed R1CS over `Z_{2^64}`: `(A∘B)·Z = u·(C·Z) + E`, `Z = (W, x, u)`, with the witness `W` split into chunks of size `B` and the slack `E` written in base-`b` digits `E = Σ b^i·E_i`, each digit entry bounded by `b`.

- *Overlap:* identical relaxed-R1CS shape as Nova/Impl 10 — same `(u, E)` relaxation trick.
- *Discrepancy:* Lova additionally enforces **norm bounds** (chunked witness, digit-decomposed error) because an SIS commitment only binds *short* vectors — Nova/Impl 10 has no norm requirement, so our existing circom / 2^85-limb step circuits would need a full re-arithmetization to `Z_{2^64}` bounded-norm constraints. Impl 10 keeps the existing BLS12-381 circuits unchanged.

### 3. Per-step instances

Each step `i` produces a non-relaxed instance `(u=1, E=0)` with witness `W_i`.

- *Overlap:* same as Nova/Impl 10.

### 4. Fold (prover) — decompose-and-fold

For a public-coin **low-norm challenge vector `c ∈ {-1, 0, 1}^k`** (ternary, Fiat–Shamir from the transcript): fold the witnesses `s' = c₁·s₁ + c₂·s₂`, the instance commitment `t' = A·s'`, and the error/slack with its cross term. The prover then **re-chunks / re-decomposes** the folded witness into digits so every committed vector stays short (the decompose-and-fold paradigm). With ternary challenges `|cᵢ| = 1` and parameters set so that `2·k·b·√m ≤ β`, the norm of the folded witness **does not grow** — this is what makes unbounded folding possible, unlike a naive `r`-weighted fold whose norm would grow with each step. The norm data is added to the relation itself (decomposed-instance consistency check `D ≟ Gᵀ·D̃·G`) so it is directly checkable after all folds.

- *Overlap:* same fold algebra and Fiat–Shamir structure as Nova/Impl 10; the verifier's commitment update is O(1) per fold in both.
- *Discrepancy (the core difference):* a naive fold over `Z_{2^64}` would make the error/witness norm grow ~quadratically per fold and quickly exceed what SIS commits to — Lova's chunk/digit machinery (and the ternary challenge set) is exactly what prevents this, at the cost of larger prover work and instance data (`O(#digits)` per fold). Pedersen commitments (Impl 10) have no norm constraint, so Nova's plain `E` folding needs no decomposition.

### 5. IVC output

After `N` steps: final relaxed instance `U_final`, final witness `(W_final, E_final)`, and the transcript of all fold challenges.

- *Overlap:* same bundle shape as Impl 10's folded instance + transcript.

### 6. Verification

(a) Re-check the transcript — each challenge from `Fiat–Shamir(transcript)` — in `O(N·δ)` small ops; (b) plug the **revealed** final witness into the relaxed equation and check all norm bounds (`‖E_final‖∞ ≤ β`, each `W` chunk ≤ `B`) — `O(|C|)`. No SNARK needed for the base IVC.

- *Overlap:* final check cost `O(|circuit|)` mirrors Impl 10's native re-check of `com(Z)`/`com(E)`; both avoid per-step Groth16.
- *Discrepancy:* Lova's verifier must replay the whole `O(N)` transcript and the final **witness is public** — same "reveal-the-witness" limitation as `nova-prover` Impl 9 (with a norm-bound check instead of a Pedersen re-commit). Impl 10's sumcheck final SNARK instead proves knowledge of the witness, giving an O(1), witness-hiding proof.

### 7. Succinctness (optional)

To get `O(1)` proofs, Lova appends a transparent lattice/hash-based final SNARK ("folding the verifier") — the same role Impl 10's sumcheck + hash-PC compression plays.

- *Overlap:* this is conceptually exactly Impl 10's final argument — sumcheck family, transparent, pairing-free verifier. The Impl 10 compression design (folding-transcript handling, hash-based polynomial commitment) carries over almost unchanged.
- *Discrepancy:* Lova's final argument runs over `Z_{2^64}` with a lattice/hash PC; Impl 10's runs over `Fr`. Impl 10 reuses the existing NIFS transcript and commitments; Lova's final SNARK must additionally handle the chunk/digit commitments of the final instance.

## Is Lova trustless?

**Yes** — it is fully transparent. Concretely: the only setup is sampling a uniformly random matrix `A` from public randomness (no secret, no trapdoor, no ceremony, no SRS); folding and the final SNARK are public-coin via Fiat–Shamir; soundness rests on the unstructured SIS assumption (post-quantum). No entity ever holds secret setup material. By contrast our `nova-prover` Impl 8/9 Groth16 compression requires a (single-party) trusted ceremony; Impl 10's sumcheck swap removes that ceremony, and Lova removes both the ceremony and the DLOG/Shor vulnerability.

Caveats to keep honest: it is *transparent*, not *verified-cryptographically-forever* — trust in SIS parameters is younger than for Groth16-era curves, and `q = 2^64` SIS parameters are non-standard vs. deployed lattice schemes (Kyber/Dilithium), so they want extra scrutiny.

## Concrete-efficiency caveats (from the authors' own blog)

Lova is a *foundation*, not a practically fast scheme yet. The authors note:

- **Extractability needs many repeated runs:** knowledge soundness of the fold is argued by running a malicious prover `2k` times with the same initial message and different challenges, so the soundness error per fold is high.
- **Large security parameter:** because of the high soundness error, `t > 300` is required, which yields **concretely large proof sizes** — *dozens of megabytes* for witnesses of length `> 2^17` — and prover times **`> 10 minutes`**.
- The authors position Lova as the "algebraic folding" foundation for lattices and expect more efficient follow-ups using the same techniques with more structured assumptions (e.g. LatticeFold / ProtogaLattice / Neo).

For our evaluation: Lova is the right *conceptual* template for a trustless PQ folding layer, but a production PQ chain would likely pick a more efficient lattice folding scheme (LatticeFold-class) or a hash/STARK-based track — see the candidate-scheme table in [`nova-prover/README.md`](../../nova-prover/README.md#candidate-lattice-schemes-from-pending-item-v).

## References

1. Giacomo Fenzi, Christian Knabenhans, Ngoc Khanh Nguyen, Duc Tu Pham. *Lova: Lattice-Based Folding Scheme from Unstructured Lattices.* ASIACRYPT 2024. IACR ePrint [2024/1964](https://eprint.iacr.org/2024/1964).
2. Official Rust implementation: [lattirust/lova](https://github.com/lattirust/lova); underlying library [lattirust](https://github.com/cknabs/lattirust).
3. Christian Knabenhans. *Lova: Lattice-Based Folding Scheme from Unstructured Lattices* — [author's blog](https://cknabs.github.io/post/lova).
4. Dan Boneh, Binyi Chen. *LatticeFold: A Lattice-based Folding Scheme and its Applications to Succinct Proof Systems.* IACR ePrint [2024/257](https://eprint.iacr.org/2024/257).
