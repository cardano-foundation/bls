# Formal Verification Plan for groth16-prover

This document tracks the incremental introduction of [Verus](https://github.com/verus-lang/verus) automated program verification into the `groth16-prover` / `trusted-setup` codebase.

> **Status:** Phases 0–8. Phases 0–5 state the safety contracts via `external_body` specifications (i.e. the specs are **stated, machine-checked for well-formedness, but trusted as axioms** — not yet discharged against the implementation body). Phase 6 starts the transition to **verified** code (proof obligations discharged by the SMT solver). The remaining "verified" column in the [inventory](#spec-inventory) is the explicit backlog.
>
> **How to read "spec" here.** A `#[verifier::external_body]` spec is Verus's way of declaring "trust this contract": it is checked for well-formedness and can be used by other proofs, but the body is not verified against the `ensures` clause. The transition to real proofs for the pure-integer helpers (`next_power_of_two`, `log2`) is complete in Phase 6; the rest remain stated contracts to be discharged or axiomatized (field arithmetic requires a Verus model of `ark_ff::Fr`).

---

## Why Verus?

The Groth16 prover handles sensitive cryptographic material (witness values, SRS points, proving keys). While the Rust type system prevents memory-safety bugs, it does **not** guarantee:

- No out-of-bounds indexing in matrix/vector code
- Dimensional consistency between R1CS matrices and witnesses
- Parser output invariants (e.g., witness length == wire count)
- Correctness of loop-based arithmetic helpers

Verus allows us to write machine-checked proofs of these properties directly in Rust source files, using Rust-like syntax.

---

## Installation

### Option A: Nix flake (recommended)

This repository includes a `flake.nix` that provides a complete dev shell with Verus, Z3 4.16.0, and the correct Rust toolchain — all pre-configured and patched for your system.

```bash
# Enter the dev shell
nix develop

# Verify a standalone file
RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-gnu verus /tmp/test.rs --crate-type=lib

# Or verify a crate
cd clis/trusted-setup
RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-gnu verus src/lib.rs --crate-type=lib
```

> **Why Nix?** The prebuilt Verus binaries require glibc 2.39+ and Z3 4.16.0. The Nix flake downloads both, patches their ELF interpreters/RPATHs to use Nix's glibc, and symlinks everything into `$PATH` automatically.

### Option B: Manual install

Follow the [official install guide](https://github.com/verus-lang/verus/blob/main/INSTALL.md).

Quick start for Linux/macOS:

```bash
# Download the latest release from https://github.com/verus-lang/verus/releases
# Example (x86_64 Linux):
curl -L -o verus.zip \
  "https://github.com/verus-lang/verus/releases/download/release/0.2026.09.20.aef82ed/verus-0.2026.09.20.aef82ed-x86-linux.zip"
unzip verus.zip

# Ensure the matching Rust toolchain is installed
./verus  # It will print the exact `rustup install` command if missing

# Optional: add to PATH
export PATH="$PWD/verus-x86-linux:$PATH"
```

> **Note:** Verus requires Z3 4.16.0. If the bundled Z3 does not run on your system (glibc version mismatch), install it via `pip install z3-solver==4.16.0.0` and point Verus to it with `VERUS_Z3_PATH`.

### Verify the toolchain

```bash
verus --version
```

### Run verification on the crate

The `verus src/lib.rs --crate-type=lib` one-liner still works only for files with no external crate dependencies. The full crate (which depends on `ark-*` and friends) is verified with `cargo-verus`:

```bash
cd clis/trusted-setup
RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-gnu cargo-verus verify --features verus

# The FFI specs in backend.rs additionally require the native feature:
RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-gnu cargo-verus verify --features verus,native
```

> **Note:** `backend.rs` is gated behind `#[cfg(feature = "native")]` in `src/lib.rs`, so the Phase-5 FFI specs are only compiled (and checked) with `--features verus,native`. Plain `--features verus` does **not** see them.

---

## What we verify (and what we do not)

### In scope (high value, feasible with Verus)

| Category | What | Files |
|----------|------|-------|
| **Bounds safety** | No out-of-bounds indexing in matrix/vector operations | `r1cs.rs`, `lagrange.rs` |
| **Structural invariants** | Matrix dimensions match witness length; domain sizes are powers of two | `r1cs.rs`, `engine.rs`, `lagrange.rs`, `phase2.rs` |
| **Functional specs on pure helpers** | `matrix_mul_vec_dyn` returns a vector of length `n_constraints`; `dot_product` accumulates correctly; `next_power_of_two` / `log2` (verified) | `r1cs.rs`, `phase2.rs` |
| **Parser invariants** | Parsed witness length equals wire count; section sizes are within bounds; **byte-cursor bounds (`offset + n ≤ data.len()`)**; **wire ids < `n_wires`** | `circom_adapter.rs`, `ptau.rs` |
| **MPC state machine** | Phase-2 contribution chaining: each `contribute()` appends exactly one contribution and `delta_*_before` chains to the previous `delta_*_after` | `phase2.rs` |
| **FFI wrapper contracts** | Length-matching preconditions for the native MSM/pairing boundary | `backend.rs` |

### Out of scope (would require axiomatizing external crates)

| Category | Why | Future work |
|----------|-----|-------------|
| **Field arithmetic correctness** | `ark-ff::Fr` is an external opaque type; proving `a * b == c` would require formalizing the BLS12-381 scalar field inside Verus | Possible with a custom Verus model of `Fr` |
| **FFT correctness** | `ark-poly` FFT/IFFT internals are complex external code | Could verify wrapper invariants (input length == domain size) |
| **Elliptic-curve group laws** | `ark-ec` MSM and pairing are black boxes | Could verify point-is-on-curve checks |
| **Groth16 soundness** | Proving the full Groth16 proof system sound requires formalizing polynomials, pairings, and the QAP reduction | Far future; would need a full crypto proof in Verus |

---

## Verification roadmap

### Phase 0 – Tooling (DONE)
- [x] Install Verus and Z3
- [x] Add `vstd`, `verus_builtin`, `verus_builtin_macros` to `trusted-setup/Cargo.toml`
- [x] Create `src/verus_smoke.rs` with a trivial `requires/ensures` proof
- [x] Confirm `cargo check` still passes (Verus annotations are macro-gated)

### Phase 1 – Bounds & structural invariants (DONE — stated contracts)
- [x] `r1cs.rs`: `matrix_mul_vec_dyn` – output length == `matrix.len()`, no OOB (via `spec_matrix_mul_vec_dyn`)
- [x] `r1cs.rs`: `verify_r1cs_circuit` – all rows have length `witness.len()`, loop indices in bounds (via `spec_verify_r1cs_circuit`)
- [x] `lagrange.rs`: `padded_coeffs` – output length == `n` (via `spec_padded_coeffs`)
- [x] `lagrange.rs`: `scale_by_coset_powers` – preserves slice length (via `spec_scale_by_coset_powers`)
- [x] `lagrange.rs`: `batch_invert` – preserves slice length, no-op for empty input (via `spec_batch_invert`)

### Phase 2 – Functional correctness of pure helpers (DONE — stated contracts)
- [x] `r1cs.rs`: `dot_product` – wire indices in bounds precondition (via `spec_dot_product`)
- [x] `lagrange.rs`: `coset_factor` – returns non-root-of-unity (via `spec_coset_factor`)

> Note: Full functional specs (e.g. `dot_product` equals Σ `coeff * witness[wire]`) require axiomatizing `ark-ff::Fr` arithmetic inside Verus. The `external_body` specs above capture the safety contracts. `spec_dot_product` currently carries an `ensures true` placeholder — see the [spec inventory](#spec-inventory) for which specs are non-vacuous.

### Phase 3 – Parser invariants (DONE — stated contracts)
- [x] `circom_adapter.rs`: `CircomCircuit::from_bytes` – dense matrices have shape `n_constraints × n_wires` (via `spec_circom_from_bytes`)
- [x] `circom_adapter.rs`: `load_witness_from_bytes` – `witness.len() == n_wires` or returns `Err` (via `spec_load_witness`)
- [x] `circom_adapter.rs`: wire ids are bounded — `wire < n_wires` for every constraint term (via `spec_parse_r1cs_raw` + enforced in [`parse_r1cs_raw`](clis/trusted-setup/src/circom_adapter.rs))

### Phase 4 – QAP engine invariants (DONE — stated contracts)
- [x] `QapEngine::domain_size` – power of two for FFT, equals `n_constraints` for dense (via `spec_fft_domain_size`, `spec_dense_domain_size`)
- [x] `QapEngine::build_qap` – returns exactly `n_vars` polynomials in each output vector (via `spec_build_qap_dense`)
- [x] `compute_quotient` – documented remainder-zero precondition (via `spec_compute_quotient_dense`; `ensures true` placeholder)

### Phase 5 – FFI & parser safety (DONE — stated contracts)
- [x] `backend.rs`: `native_msm_g1` / `native_msm_g2` – length-matching precondition (via `spec_native_msm_g1`, `spec_native_msm_g2`)
- [x] `backend.rs`: `native_pairing_batch_check` – `g1.len() == g2.len()` precondition (via `spec_native_pairing_batch_check`)
- [x] `ptau.rs`: `read_tau_g1` / `read_tau_g2` – result length equals requested count on success (via `spec_read_tau_g1`, `spec_read_tau_g2`)

> **Feature note:** `backend.rs` is gated on `native`, so the Phase-5 specs are only compiled/checked under `cargo-verus verify --features verus,native`.

### Phase 6 – Verified pure-integer helpers (DONE — proof obligations discharged)
- [x] `phase2.rs`: `next_power_of_two` – **verified** loop implementation returns a power of two `≥ n` and *strictly above* every smaller power of two below `n` (minimality), with `p ≤ 2·n` bounding the iteration space
- [x] `phase2.rs`: `log2` – **verified** spec: `2^r ≤ n`, `n < 2^(r+1)`, and `next_power_of_two(2^k) == 2^k` roundtrip consistency

These are the first **non-`external_body`** proofs in the crate: the bodies are checked against their `requires`/`ensures`/`invariant` annotations by the SMT solver.

### Phase 7 – Parser byte-cursor bounds (DONE — stated contracts)
- [x] `circom_adapter.rs`: `parse_r1cs_raw`, `parse_header_section`, `parse_constraints_section`, `parse_sparse_vector`, `parse_wtns` – every `take(n)`/slice-read is preceded by an `offset + n ≤ data.len()` check (Vest-style); specs state the cursor stays in bounds (`spec_parse_*`)
- [x] `ptau.rs`: `read_tau_g1` / `read_tau_g2` – slice reads bounded by the remaining file data

### Phase 8 – MPC state-machine invariants (DONE — stated contracts)
- [x] `phase2.rs`: `contribute` – appends exactly one contribution and chains `delta_*_before` to the previous `delta_*_after` (via `spec_contribute`)
- [x] `phase2.rs`: `verify` – checks that the stored contribution transcript is a valid chain (via `spec_verify_phase2`)

### Future work (requires deeper axiomatization)
- [ ] Replace the remaining `external_body` wrappers with fully verified implementations for loop-based helpers (requires axiomatizing `Fr` or replacing with abstract numeric types)
- [ ] `phase2.rs`: Contribution ratio-proof verification invariants (needs a group-law model)
- [ ] `prover.rs`: Proof element assembly length checks (A, B, C point construction)
- [ ] `ceremony.rs`: Key-generation output size invariants (`a_query`, `b_query`, etc.)

---

## Spec inventory

Every spec in the crate, with its kind. **Stated** = `external_body` contract (well-formedness checked, semantics trusted as axioms). **Verified** = regular `verus!` function whose body was discharged by the SMT solver.

| Spec | File | Kind | Non-vacuous postcondition |
|------|------|------|---------------------------|
| `spec_matrix_mul_vec_dyn` | `r1cs.rs` | Stated | `r.len() == matrix.len()` |
| `spec_verify_r1cs_circuit` | `r1cs.rs` | Stated | — (placeholder) |
| `spec_dot_product` | `r1cs.rs` | Stated | — (placeholder) |
| `spec_padded_coeffs` | `lagrange.rs` | Stated | `r.len() == n` |
| `spec_scale_by_coset_powers` | `lagrange.rs` | Stated | length preserved |
| `spec_batch_invert` | `lagrange.rs` | Stated | length preserved |
| `spec_coset_factor` | `lagrange.rs` | Stated | — (needs Fr axioms) |
| `spec_fft_domain_size` | `engine.rs` | Stated | `n ≥ num_constraints` ∧ power of two |
| `spec_dense_domain_size` | `engine.rs` | Stated | `n == num_constraints` |
| `spec_build_qap_dense` | `engine.rs` | Stated | each output is `l[0].len()` long |
| `spec_compute_quotient_dense` | `engine.rs` | Stated | — (placeholder) |
| `spec_circom_from_bytes` | `circom_adapter.rs` | Stated | matrices shaped `n_constraints × n_wires` |
| `spec_load_witness` | `circom_adapter.rs` | Stated | `witness.len() == n_wires` on `Ok` |
| `spec_parse_r1cs_raw` | `circom_adapter.rs` | Stated | wire ids `< n_wires`; parsed count == header count |
| `spec_parse_*` (r1cs/wtns sections) | `circom_adapter.rs` | Stated | cursor stays in bounds (`offset + n ≤ len`) |
| `spec_read_tau_g1` / `spec_read_tau_g2` | `ptau.rs` | Stated | `Ok` ⇒ result length == requested count |
| `spec_native_msm_g1/g2`, `spec_native_pairing_batch_check` | `backend.rs` | Stated | — (preconditions only; `native` feature) |
| `spec_next_power_of_two` | `phase2.rs` | **Verified** | power of two `≥ n`, minimality, `p ≤ 2n` |
| `spec_log2` | `phase2.rs` | **Verified** | `2^r ≤ n < 2^(r+1)` |
| `spec_contribute` | `phase2.rs` | Stated | `contributions.len()` grows by 1; delta-chain preserved |
| `spec_verify_phase2` | `phase2.rs` | Stated | transcript is a valid chain |

## How to run verification

### Inside the Nix dev shell

```bash
nix develop

# Verify a single self-contained file (no external crate deps)
RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-gnu verus src/verus_smoke.rs --crate-type=lib

# Verify the whole crate (external deps are resolved by cargo-verus)
cd clis/trusted-setup
RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-gnu cargo-verus verify --features verus

# Include the FFI specs (backend.rs is gated on `native`)
RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-gnu cargo-verus verify --features verus,native
```

> **Note:** `verus src/lib.rs --crate-type=lib` only works for files with no external crate dependencies. The full crate needs `cargo-verus verify` (reads `Cargo.toml`, builds the dependency graph, treats `ark-*`/`nom`/`rand` as unverified external code).

### Normal cargo build (ignores Verus annotations)

```bash
cd clis/trusted-setup
cargo check
cargo test
```

> Verus annotations live inside `verus! { ... }` blocks gated behind `#[cfg(feature = "verus")]`. Normal `cargo check` / `cargo test` (without `--features verus`) skips these blocks entirely, so the build is unaffected.

## Performance impact

**Zero runtime impact.** All Verus code is:
- Feature-gated behind `verus` (default disabled)
- Written inside `verus! { ... }` macros that erase ghost code at compile time
- `external_body` wrappers have no executable body and are never called by production code

Running `cargo build --release` produces the exact same binary as before Verus was introduced.

---

## References

- [Verus repository](https://github.com/verus-lang/verus)
- [Verus guide](https://verus-lang.github.io/verus/guide/)
- [Amazon Science blog: Developing provably correct Rust code with Verus](https://www.amazon.science/blog/developing-provably-correct-rust-code-with-verus)
- [Vest](https://github.com/secure-foundations/vest) – example of Verus-verified binary format parser
- [CapybaraKV](https://github.com/microsoft/verified-storage) – example of Verus-verified persistent memory log
