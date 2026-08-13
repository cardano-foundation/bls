# lattirust / lova — Codebase Review & Takeaways

## Scope

A source-level review of the authors' implementation behind the Lova paper ([eprint 2024/1964](https://eprint.iacr.org/2024/1964)):

- **lattirust** — the lattice algebra library ([github.com/cknabs/lattirust](https://github.com/cknabs/lattirust), commit `91ce8c01`)
- **lova** — the folding scheme itself ([github.com/lattirust/lova](https://github.com/lattirust/lova), 5 commits)

Review was done against local clones (`/tmp/opencode/{lattirust,lova}`), compiled and tested with the pinned `nightly-2025-03-10` toolchain, and cross-checked against `docs/lova-folding-design.md`.

> **Status:** 🔬 **Research / evaluation.** Findings for the post-quantum track (`nova-prover` Implementation 12 / Pending item (v)). No code from lattirust has been copied into this repo — everything below is a candidate list to port or adapt.

## Repository layout

### lattirust workspace members

| Crate | Role |
|---|---|
| `lattirust-arithmetic` | Rings (`Z2_64`, `Z2_128`, `Zq` RNS, pow-2 cyclotomic `R_q`, NTT), linear algebra (`Matrix`, `SymmetricMatrix`, `Vector`), challenge sets (Labrador, binary), decomposition, norms, nimue transcript plumbing, serialization |
| `relations` | Folding relations: `PrincipalRelation` (linear forms over `SymmetricMatrix`), R1CS/relaxed-R1CS with Labrador/binary challenge sets |
| `lattice-estimator` | Rust wrapper around the **Python (Sage)** [`malb/lattice-estimator`](https://github.com/malb/lattice-estimator) via PyO3; `build.rs` requires `SAGE_ROOT`. Only used to *choose* parameters (modulus `q`, error bounds) at build time — not at proof time |

### lova

- `src/util.rs` — `PublicParameters` (the random commitment matrix `A`, ring `Zq`, error distribution, and the full `LovaIOPattern`), `BaseRelation` (instance = witness + forms `(S, z)` + errors), `fold` / `fold_twice` / `fold_and_check` / `verify_folding`.
- `src/sis.rs` — SIS-based parameter estimation pipeline (`SISEstimator`, runs the Python estimator via `sage -python`), used by `PublicParameters::new` to pick `q`/`h` (number of commitment rows) and the error bounds.
- `src/params.rs` (generated) — concrete parameter sets (moduli, norm bounds) baked in from the Sage estimation.

## Validation results (as of this review)

Run on `nightly-2025-03-10` (the pinned toolchain — **newer nightlies fail to compile** the crate):

- **`lattirust-arithmetic`: 438 passed, 29 failed.** All 29 failures are accounted for:
  - **28 involve the Goldilocks prime** `Q4 = 2^64 − 2^32 + 1` as a ring component (`f_p::test_f4`, `f_p::test_signed_repr_4`, `z_q::test_z4`, `z_q::test_z5`). Symptom: `a · a⁻¹ = 0 ≠ 1`, i.e. broken Montgomery arithmetic for this prime. **Deterministic, reproducible bug** — avoid this modulus.
  - **1 is `labrador_challenge_set::test_operator_norm`**, which the authors' own comment marks flaky: *"this fails sometimes, but it is not clear why"*. The computed operator norm is not always an upper bound on the actual expansion ratio — **the bound is loose, not tight**.
  - Everything else passes: BabyBear NTT up to `N = 8192`, moduli `274177`, `67280421310721`, Mersenne primes, `Z2_64`/`Z2_128`, pow-2 cyclotomic rings, signed-representative round trips.
- **`relations`: 4/4 passed** — `principal_relation` satisfied/unsatisfied instance generation and R1CS instance generation are sound.
- **`lova` itself could not be compiled**: its `lattice-estimator` dependency requires a Sage install (`SAGE_ROOT`), so prover/verifier end-to-end tests were not run.

## Architecture highlights

### 1. The `Ring` trait (`lattirust-arithmetic/src/ring/mod.rs`)

A single trait for every ring used anywhere in the stack: `Copy + Clone + Debug + Display + Eq + Zero + One + Neg + UniformRand + Hash + CanonicalSerialize/Deserialize + Add/Sub/Mul (+&/&mut variants) + Sum/Product + TryFrom<u8..u128> + From<bool> + FromRandomBytes + ToBytes/FromBytes + Modulus + WithL2Norm + WithLinfNorm + inverse()`. Blanket impl for any arkworks `Field`. Ships macro test-suites (`test_field!`, `test_ring!`, `test_field_ring!`, `test_ntt_*!`) reused across every concrete ring — this is what makes the large matrix of ring tests cheap to write.

### 2. Rings

- **`Z2_64` / `Z2_128`** (`z_2_64.rs` / `z_2_128.rs`) — the two-bit field `{0,1}`, packed 32/64 elements per native word, custom serialization. Used for blinding in the transcript.
- **`Fq<Q>` = `Fp64`** (`f_p.rs`) — 64-bit prime-field elements (arkworks Montgomery). Only safe for the primes actually tested (see the Goldilocks failure above).
- **`Zq` (RNS/CRT)** (`z_q.rs`) — a "modulus = product of `L` NTT primes" ring, `Zq<Config, L>` with `Zq1..Zq5` aliases. NTT runs **per prime component** (an array-of-structs split), giving big virtual moduli with `u64` arithmetic. NTT length is limited by the smallest prime's 2-adicity (e.g. `274177` supports only `N ≤ 128`).
- **`Pow2CyclotomicPolyRing` / `Pow2CyclotomicPolyRingNTT`** (`pow2_cyclotomic_poly_ring*.rs`) — `R_q = Z_q[X]/(X^N+1)`, generic over the base ring, with a naive coefficient-multiply fallback and an NTT variant.
- **`representatives.rs`** — `SignedRepresentative` / `WithSignedRepresentative`: signed representatives (and `DecompositionFriendlySignedRepresentative` in `decomposition.rs` for digit decompositions) with explicit norm/range bounds. This is the machinery that makes norm-verification feasible.

### 3. Linear algebra (`lattirust-arithmetic/src/linear_algebra.rs`)

nalgebra-backed `Matrix`, `SymmetricMatrix` (stores one triangle), `Vector`. Folding is matrix-matrix arithmetic — the `SymmetricMatrix` choice halves the cost and matches the bilinear-form shape of the relation.

### 4. Challenge sets (`lattirust-arithmetic/src/challenge_set/`)

- **Labrador** (`labrador_challenge_set.rs`) — challenges `c` with small coefficients and bounded norm; exposes `operator_norm()` used to bound `‖c·r‖` in the error-growth analysis (loose — see caveats).
- **Binary** (`binary.rs`) — `{-1, 0, 1}` challenges for the R1CS relation.

### 5. Transcript plumbing (`lattirust-arithmetic/src/nimue/iopattern.rs`)

`SerIOPattern` (declares absorb size by serializing a "zero-like" object), `SqueezeFromRandomBytes` (`challenge_bytes` parsed into ring elements via `FromRandomBytes`), `RatchetIOPattern`. lova's `LovaIOPattern` in `src/util.rs` composes these into the per-round pattern: absorb matrix/vector → `ratchet` → squeeze challenge.

### 6. Parameter derivation (`lova/src/sis.rs`)

`PublicParameters::new` sizes the scheme: given target security and dimension, use the SIS estimator to pick `q`, `h` (commitment rows), and error bounds such that folding error growth never exceeds what the commitment and the final witness-norm check can tolerate.

## Takeaways worth borrowing

1. **Folding linear forms is the core trick** (`relations/src/principal_relation.rs`, `lova/src/util.rs`). An instance's forms are `(SymmetricMatrix S, vector z)`; a fold is `S' = α·S₀ + S₁` (and similarly for `z`), so error growth is **additive and bounded by ‖α‖**, not quadratic. Commitments are linear, so the verifier updates `com(S')` in O(1). This is the exact error-growth analysis and fold algebra we would otherwise have to derive from scratch — reuse the formulas.
2. **`Ring` trait + macro test-suites** (`ring/mod.rs`) — a uniform abstraction over `Z2_64` (blinding), `Fp64` primes, and `R_q`, with one-line-per-ring test matrices. Directly transferable to our prover crate.
3. **RNS/CRT `Zq` for big virtual moduli** — NTT over a product of NTT-friendly primes keeps all arithmetic in `u64`. Only adopt if our folding never needs a single prime field (RNS is fine for componentwise lattice arithmetic). Reuse only the tested primes (`BabyBear`, `274177`, `67280421310721`).
4. **`SymmetricMatrix`-based forms** — halves the storage/ops of the forms matrix while preserving the bilinear structure.
5. **Bounded challenge sets + operator-norm bounds** — the Labrador-style challenge (small `‖c‖`) and using `‖c‖_op` to bound error expansion per fold. Treat the bound as approximate (it is not tight).
6. **Transcript conventions** (`nimue/iopattern.rs`) — absorb-by-size-of-zero-element, `challenge_bytes` + `FromRandomBytes`, per-round `ratchet`. Clean, standard Fiat–Shamir; reusable as-is if we add commitment binding / ZK.
7. **Parameter-derivation pipeline shape** (`lova/src/sis.rs`) — derive `(q, h, error bounds)` from a target-security estimate before instantiating; replicate self-contained rather than depend on Sage/PyO3.

## Caveats / things to avoid

- **Goldilocks prime is broken** in their `Fp64` Montgomery path — do not instantiate `Zq` with a `2^64 − 2^32 + 1` component. All other tested primes are fine.
- **`operator_norm` is loose / flaky** — the author's TODO confirms it; do not rely on the bound being exact.
- **Compiles only on the pinned `nightly-2025-03-10`** — uses unstable features (`associated_type_defaults`, `int_roundings`); newer nightlies break the build. A port must either pin the toolchain or drop the unstable features.
- **Heavy const-eval** (`#![allow(long_running_const_eval)]` in `z_q.rs`, `#![allow(warnings)]` in places) — long compile times and suppressed diagnostics; clean up in a port.
- **Sage/PyO3 build dependency** (`lattice-estimator`) blocks building lova without Sage; keep parameter estimation optional / external in a port.
- **Test-suite runtime is minutes** (`~155 s` for the arithmetic lib alone).

## Sources

1. lattirust: <https://github.com/cknabs/lattirust> (workspace members `lattirust-arithmetic`, `relations`, `lattice-estimator`).
2. lova: <https://github.com/lattirust/lova> (`src/util.rs`, `src/sis.rs`, `src/params.rs`).
3. malb/lattice-estimator (Sage, submodule of lattirust): <https://github.com/malb/lattice-estimator>.
4. Design overview this review feeds into: [`lova-folding-design.md`](lova-folding-design.md).
