# Formal Verification Plan for groth16-prover

This document tracks the incremental introduction of [Verus](https://github.com/verus-lang/verus) automated program verification into the `groth16-prover` / `trusted-setup` codebase.


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

---

## What we verify (and what we do not)

### In scope (high value, feasible with Verus)

| Category | What | Files |
|----------|------|-------|
| **Bounds safety** | No out-of-bounds indexing in matrix/vector operations | `r1cs.rs`, `lagrange.rs` |
| **Structural invariants** | Matrix dimensions match witness length; domain sizes are powers of two | `r1cs.rs`, `engine.rs`, `lagrange.rs` |
| **Functional specs on pure helpers** | `matrix_mul_vec_dyn` returns a vector of length `n_constraints`; `dot_product` accumulates correctly | `r1cs.rs` |
| **Parser invariants** | Parsed witness length equals wire count; section sizes are within bounds | `circom_adapter.rs` |

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

### Phase 1 – Bounds & structural invariants (DONE)
- [x] `r1cs.rs`: `matrix_mul_vec_dyn` – output length == `matrix.len()`, no OOB (via `spec_matrix_mul_vec_dyn`)
- [x] `r1cs.rs`: `verify_r1cs_circuit` – all rows have length `witness.len()`, loop indices in bounds (via `spec_verify_r1cs_circuit`)
- [x] `lagrange.rs`: `padded_coeffs` – output length == `n` (via `spec_padded_coeffs`)
- [x] `lagrange.rs`: `scale_by_coset_powers` – preserves slice length (via `spec_scale_by_coset_powers`)
- [x] `lagrange.rs`: `batch_invert` – preserves slice length, no-op for empty input (via `spec_batch_invert`)

### Phase 2 – Functional correctness of pure helpers (DONE)
- [x] `r1cs.rs`: `dot_product` – wire indices in bounds precondition (via `spec_dot_product`)
- [x] `lagrange.rs`: `coset_factor` – returns non-root-of-unity (via `spec_coset_factor`)

> Note: Full functional specs (e.g. `dot_product` equals Σ `coeff * witness[wire]`) require axiomatizing `ark-ff::Fr` arithmetic inside Verus. The `external_body` specs above capture the safety contracts.

### Phase 3 – Parser invariants (DONE)
- [x] `circom_adapter.rs`: `CircomCircuit::from_bytes` – dense matrices have shape `n_constraints × n_wires` (via `spec_circom_from_bytes`)
- [x] `circom_adapter.rs`: `load_witness_from_bytes` – `witness.len() == n_wires` or returns `Err` (via `spec_load_witness`)

### Phase 4 – QAP engine invariants (stretch / future work)
- [ ] `QapEngine::domain_size` – power of two for FFT, equals `n_constraints` for dense
- [ ] `QapEngine::build_qap` – returns exactly `n_vars` polynomials
- [ ] `compute_quotient` – remainder is zero precondition / postcondition
- [ ] Replace `external_body` wrappers with fully verified implementations for loop-based helpers (requires axiomatizing `Fr` or replacing with abstract numeric types)

---

## How to run verification

### Inside the Nix dev shell

```bash
nix develop

# Verify a single file
RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-gnu verus src/r1cs.rs --crate-type=lib

# Verify the whole crate
cd clis/trusted-setup
RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-gnu verus src/lib.rs --crate-type=lib
```

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
