# Formal Verification in `groth16-prover` / `trusted-setup`

This document records the [Verus](https://github.com/verus-lang/verus) verification
layer: what is actually machine-checked today, what is only *asserted* in a
comment-shaped contract, and what is not covered at all.

## TL;DR — read this before trusting anything below

- **Two functions are verified.** `next_power_of_two_u64` and `log2_u64` in
  `phase2.rs`, plus four small smoke-test functions in `verus_smoke.rs`.
- **Nineteen `spec_*` functions are contracts, not proofs.** Every one of them is
  marked `#[verifier::external]`, which tells Verus to trust the postcondition
  without checking the body. Four of them still carry a vacuous `ensures true`.
- **Verification was silently inert until 2026-09.** The crate compiled its
  `verus!` blocks but never invoked the verification engine. See
  [Enabling verification](#enabling-verification-read-this). A deliberately false
  assertion passed for the entire life of the feature. Any claim of the form
  "this spec was checked" made before that date was unfounded.
- **`cargo-verus verify` reports `2059 verified, 0 errors`.** That number is
  dominated by `vstd`/`ark-*` library code compiled in, **not** by this crate.
  The crate's own verified surface is the small list above.

## Why Verus?

The Groth16 code handles sensitive material (witness values, SRS points,
proving keys) and parses untrusted binary formats (`.ptau`, `.r1cs`, `.wtns`).
The Rust type system prevents memory-safety bugs but does not establish
dimensional consistency, parser cursor bounds, or loop arithmetic. Verus lets
those properties be machine-checked in the same source files.

## Enabling verification (read this)

Verification only runs if the package opts in:

```toml
# clis/trusted-setup/Cargo.toml
[package.metadata.verus]
verify = true
```

**Without this line, `cargo-verus verify` compiles the crate and does not verify
it.** No `__VERUS_DRIVER_VERIFY_*` is exported for the primary package, every
`verus!` block is type-checked and discarded, and the command exits `0`. This
was the state of the crate until 2026-09-29, which meant the feature gave a
false sense of coverage for its entire lifetime.

Because the failure is silent, treat a green run as meaningful only after
confirming it rejects a known-bad assertion. `verus_smoke.rs` is the intended
canary for this.

## Running verification

```bash
cd clis/trusted-setup

# Library + smoke tests
RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-gnu cargo-verus verify --features verus

# Additionally compiles backend.rs (the `native`-gated FFI specs)
RUSTUP_TOOLCHAIN=1.98.1-x86_64-unknown-linux-gnu cargo-verus verify --features verus,native
```

Both currently report `0 errors`. A clean run takes roughly 10 minutes.

Normal builds are unaffected — all `verus!` blocks are behind
`#[cfg(feature = "verus")]` and ghost code is erased:

```bash
cd clis/trusted-setup
cargo check
cargo test
```

> The `verus <file> --crate-type=lib` one-liner from the Nix shell banner does
> **not** work on the individual modules in this crate; it needs a crate root
> that imports `verus_builtin`. Use `cargo-verus` as above.

## What is genuinely verified

### `phase2.rs`

Both functions operate on `u64`; the production `usize` entry points in the same
file are thin wrappers that cast to `u64` and call these. The cast itself is
**not** part of any proof.

`next_power_of_two_u64` — proved from the loop body:

```rust
requires n >= 1, n <= 2^62
ensures  r >= n
         r <= 2 * n
         is_pow2(r as int)
         forall|k: u64| is_pow2(k as int) && 1 <= k < r ==> k < n   // minimality
```

`log2_u64` — proved on **powers of two only**, which is the only case callers
use it for:

```rust
requires n >= 1, n <= 2^62, is_pow2(n as int)
ensures  pow2(r as nat) == n as int
```

Note this is deliberately weaker than "`2^r <= n < 2^(r+1)`". That stronger
statement is false in general: `trailing_zeros` is only the mathematical log2
on powers of two, so `log2(12) == 2` would violate it. An earlier revision of
this document claimed the stronger contract; it was wrong.

The proof rests on `axiom_u64_trailing_zeros` from `vstd`, which is why
`reveal` cannot be used on it — it is an axiom, not a closed definition.

### `verus_smoke.rs`

`add_one` and `sum_first_n` (the latter stated as `2*s == n*(n+1)` to avoid
division), supported by two `proof fn` lemmas. These exist mainly to confirm the
toolchain is genuinely checking the crate.

## What is *not* verified

Nineteen `spec_*` functions across six files are annotated
`#[verifier::external]`: the contract is type-checked for well-formedness and is
usable by other proofs, but the body is **assumed**.

They all mention at least one type Verus has no model for — `ark_ff::Fr`,
`ark_ec` curve/affine types, `DensePolynomial`, and the crate's own
`Circuit` / `PtauFile` / `CircomCircuit` / `BackendError`. Writing
`external_type_specification` declarations for the ark type aliases was
attempted and abandoned: the aliases expand through private modules and require
exact generic/bound matching, making the declarations larger and more fragile
than the code they describe.

| Spec | File | Postcondition | Useful? |
|------|------|---------------|---------|
| `spec_matrix_mul_vec_dyn` | `r1cs.rs` | `r.len() == matrix.len()` | asserted |
| `spec_verify_r1cs_circuit` | `r1cs.rs` | `ensures true` | **vacuous** |
| `spec_dot_product` | `r1cs.rs` | `ensures true` | **vacuous** |
| `spec_padded_coeffs` | `lagrange.rs` | `r.len() == n` | asserted |
| `spec_scale_by_coset_powers` | `lagrange.rs` | length preserved | asserted |
| `spec_batch_invert` | `lagrange.rs` | length preserved | asserted |
| `spec_coset_factor` | `lagrange.rs` | `ensures true` | **vacuous** |
| `spec_fft_domain_size` | `engine.rs` | `n >= num_constraints`, power of two | asserted |
| `spec_dense_domain_size` | `engine.rs` | `n == num_constraints` | asserted |
| `spec_build_qap_dense` | `engine.rs` | each output has `l[0].len()` entries | asserted |
| `spec_compute_quotient_dense` | `engine.rs` | `ensures true` | **vacuous** |
| `spec_circom_from_bytes` | `circom_adapter.rs` | matrices shaped `n_constraints × n_wires` | asserted |
| `spec_load_witness` | `circom_adapter.rs` | `witness.len() == n_wires` on `Ok` | asserted |
| `spec_read_tau_g1` / `spec_read_tau_g2` | `ptau.rs` | result length == count on `Ok` | asserted |
| `spec_native_msm_g1` / `_g2` | `backend.rs` | length mismatch ⇒ `Err` (`native`) | asserted |
| `spec_native_pairing_batch_check` | `backend.rs` | length mismatch ⇒ `Err` (`native`) | asserted |
| `spec_native_ntt` | `backend.rs` | empty slice ⇒ `Err` (`native`) | asserted |

Four of nineteen carry no information at all. They document intent and are
harmless, but they are not evidence.

### Why the FFI specs stay unverified

The four FFI contracts are the clearest case where a proof was considered and
rejected on cost grounds. The length guards are real and are now covered by
tests (`msm_rejects_length_mismatch`, `pairing_rejects_length_mismatch`):

```rust
// bls_ffi.rs
if points.len() != scalars.len() { return Err(err(BlsStatus::MsmMismatch)); }
unsafe { msm_g1_impl(points, scalars) }
```

Verus could in principle prove `points.len() != scalars.len() ==> r.is_err()`,
but only after all of the following:

- `BlsFr` / `BlsG1` / `BlsG2` / `BlsStatus` / `BackendError` each need an
  `Ex*` mirror type plus a `View` impl, since the real types are declared
  outside the macro. `BackendError` also carries a `&'static str`.
- The function body must move *inside* `verus!`. A function declared outside it
  can only be reached through `assume_specification`, which asserts the very
  thing we would be trying to prove.
- The `extern "C"` implementations need their own `assume_specification`, and
  the `unsafe` block stays opaque regardless — so the proof would cover the
  early return and nothing about the C++ callee.

That buys a machine-checked `len` comparison in exchange for five type models
and a restructured FFI layer, all of which must be kept in sync with the ABI.
The assertion-plus-test combination conveys the same information at a fraction
of the maintenance cost.

One genuine limitation to note: `spec_native_ntt` states only the empty-slice
half of the guard, because `usize::is_power_of_two` has no Verus model. The
power-of-two half is covered by `ntt_rejects_non_power_of_two`.

## Known gaps

These are **not** covered. An earlier revision of this document claimed they
were done; the referenced spec functions do not exist in the source.

1. **Parser byte-cursor bounds are unverified.** The `.r1cs` / `.wtns` / `.ptau`
   parsers (`parse_r1cs_raw`, `parse_sparse_vector`, …) have no `verus!` block
   at all. `nom` itself is an unverified external crate, so the
   `offset + n <= data.len()` discipline those parsers rely on is unchecked.

2. ~~**Wire ids are not bounds-checked.**~~ **Fixed** in `229ea43`.
   `parse_sparse_vector` used to store a `u32` wire id straight from the file,
   and `CircomCircuit::parse_r1cs` then indexed `l[i][wire as usize]` with it,
   so a 148-byte `.r1cs` panicked instead of returning an error. Both
   representations now call `validate_wire_ids` after `parse_r1cs_raw`, which
   rejects an out-of-range id with a diagnostic naming the wire and the declared
   `n_wires`. The related unbounded `Vec::with_capacity(n_terms)` — a tiny file
   could ask for a ~200 GB allocation — was bounded by what the buffer can hold.

   This is a runtime input check, not a proof: `nom` is an external crate, so
   the parser itself remains unverified.

3. **MPC state-machine invariants are unverified.** The Phase-2 delta-chain
   (`contribute()` appending exactly one contribution, `delta_*_before` chaining
   to the previous `delta_*_after`) is described in prose only.
   `spec_contribute` and `spec_verify_phase2` do not exist.

4. **Field and curve arithmetic.** Out of reach without a Verus model of
   `ark_ff::Fr` and the BLS12-381 group laws.

## Where verification can still go

The productive direction is extracting **pure-integer** logic so Verus can
actually check it, rather than annotating ark-typed surface area:

- Bounds/offset arithmetic in the parsers, lifted out of `nom` into small
  functions over `usize` that can be proven directly.
- The `usize` → `u64` cast at the `phase2` call sites, which currently carries
  the `n <= 2^62` precondition as an unchecked obligation.
- Any further loop or index arithmetic reachable from a checked caller.

Fixing the wire-id panic in item 2 above is worth doing on correctness grounds
regardless of verification.

## References

- [Verus repository](https://github.com/verus-lang/verus)
- [Verus guide](https://verus-lang.github.io/verus/guide/)
- [Amazon Science: Developing provably correct Rust code with Verus](https://www.amazon.science/blog/developing-provably-correct-rust-code-with-verus)
- [Vest](https://github.com/secure-foundations/vest) — Verus-verified binary format parser
- [CapybaraKV](https://github.com/microsoft/verified-storage) — Verus-verified persistent memory log
