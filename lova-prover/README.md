# lova-prover

Lattice-based (post-quantum) IVC folding — research track for **Lova** (Fenzi, Knabenhans, Nguyen, Pham, ASIACRYPT 2024), the first folding scheme whose security relies on the *unstructured* SIS assumption. This crate is the post-quantum counterpart of the classical Nova stack in [`nova-prover`](../nova-prover/).

> **Status:** 🔬 **Research / evaluation.** No code yet. Lova is tracked in `nova-prover` as **Implementation 12** (post-quantum lattice folding) / **Pending item (v)** — a long-term item, not a committed path. This crate will hold the lattice IVC prover if/when that track is pursued.

## Why Lova

- **Unstructured SIS** (vs. Module-SIS for LatticeFold) — a simpler, standard lattice assumption; no ring arithmetic.
- **Power-of-two modulus `q = 2^64`** — hardware-friendly integer arithmetic only; no finite-field library, no inversions, no `Fr` big-int ops.
- **Fully transparent / trustless** — public random matrix `A`, public-coin Fiat–Shamir, no ceremony, trapdoor, or SRS.
- **Drop-in-compatible shape** — Nova folding is commitment-agnostic (any additively-homomorphic commitment); swapping Pedersen (DLOG-based, Shor-broken) for an Ajtai commitment makes the fold post-quantum with the same IVC structure.

## Findings / design

The full walkthrough — setup → folding → verification, annotated with overlap vs nova-prover's **Impl 10** (BLS12-381 Nova folding + sumcheck final SNARK) at every step, the trustless analysis, and the concrete-efficiency caveats — is in [`docs/lova-folding-design.md`](docs/lova-folding-design.md).

A source-level review of the authors' implementation (lattirust + lova), including what actually builds and passes tests, the ring/transcript/folding abstractions worth porting, and the bugs to avoid (Goldilocks prime, loose operator-norm bound), is in [`docs/lattirust-codebase-review.md`](docs/lattirust-codebase-review.md).

## Sources

- **Paper:** *Lova: Lattice-Based Folding Scheme from Unstructured Lattices.* ASIACRYPT 2024, [IACR ePrint 2024/1964](https://eprint.iacr.org/2024/1964); [author's blog](https://cknabs.github.io/post/lova).
- **Official Rust implementation:** [lattirust/lova](https://github.com/lattirust/lova), built on the authors' [lattirust](https://github.com/cknabs/lattirust) library.
- **Codebase review (this repo):** [`docs/lattirust-codebase-review.md`](docs/lattirust-codebase-review.md).

## Relationship to `nova-prover`

- Classical stack (the default): [`nova-prover`](../nova-prover/) — Impl 8 step-chain, Impl 9 NIFS + Groth16 compression, Impl 10 sumcheck final SNARK.
- PQ track (Impl 12): lattice folding (this crate) + PQ compression SNARK + hash-based on-chain verifier. Context and status: [`nova-prover/README.md`](../nova-prover/README.md#implementation-12-post-quantum-lattice-folding).

## License

Apache-2.0
