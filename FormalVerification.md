# Formal Verification in `groth16-prover` / `trusted-setup`

This document records the [Verus](https://github.com/verus-lang/verus) verification
layer: what is actually machine-checked today, what is only *asserted* in a
comment-shaped contract, and what is not covered at all.

## TL;DR — read this before trusting anything below

- **Six functions are verified.** `next_power_of_two_u64` and `log2_u64` in
  `phase2.rs`; the sparse-vector stride model `term_loop_model` and
  `sparse_capacity_is_sound` in `circom_adapter.rs`; plus four small smoke-test
  functions in `verus_smoke.rs`. The stride pair is the only proven code on an
  untrusted-input path.
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

### `circom_adapter.rs` — sparse-vector stride

`parse_sparse_vector` walks `n_terms` terms out of an attacker-controlled
buffer, and each term is a 4-byte wire id plus a 32-byte field element. Two
functions pin that arithmetic down:

- `term_loop_model` proves the loop consumes exactly `36 * k` bytes after `k`
  iterations and reports failure as soon as fewer than 36 remain, yielding
  `ok ==> n_terms * 36 <= rest_len`.
- `sparse_capacity_is_sound` derives from that
  `n_terms <= rest_len / 36`, using `vstd`'s `lemma_small_div_converse` for
  the Euclidean-division step.

This is what makes the `Vec::with_capacity(min(n_terms, rest_len / 36))` guard
provably sufficient rather than merely plausible. The invariants use `int`
arithmetic deliberately: Verus models `usize` as 32-bit, and a `u32` term count
times 36 overflows that range, so a `usize`-only invariant would be unsound to
write even though the real 64-bit target has no such limit.

It is a *model*, not the parser. `nom` does the actual reading, so this fixes
the stride and the loop bound while leaving `nom`'s own behaviour unverified.

## What is *not* verified

Nineteen `spec_*` functions across six files are annotated
`#[verifier::external]`: the contract is type-checked for well-formedness and is
usable by other proofs, but the body is **assumed**.

They all mention at least one type Verus has no model for. The wall is
`ark_bls12_381::Fr`, which expands to `Fp<MontBackend<4>, u64>` and reports:

```
error: `ark_ff::fields::models::fp::Fp` is not supported
       (note: you may be able to add a Verus specification to this type
       with the `external_type_specification` attribute)
```

This blocks even a bare `while i < vals.len()` over a `&mut [Fr]` — nothing
about the loop needs field arithmetic, and it still will not verify. Declaring
`Fr` would mean the `Ex*` + `View` pattern, which requires the type to satisfy
`ZeroablePrimitive`, a `verus_builtin` trait that cannot be implemented for a
foreign type. So the FFI and ark-facing contracts stay asserted.

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

### What *is* checked at the C++ boundary

The ABI contract in `native/include/bls_backend.h` is cross-checked against the
Rust bindings by tests in `bls_ffi.rs`. This is a different mechanism from
Verus — the header is `include_str!`'d and parsed, so these are ordinary
assertions that CI enforces, not SMT-checked proofs.

| Check | Catches |
|-------|---------|
| `c_typedefs_match_committed_header` | a renamed type or changed struct byte length |
| `byte_count_macros_match_rust_layouts` | a `BLS_BACKEND_*_BYTES` value drifting from `BlsFr/G1/G2::BYTE_LEN`; also pins the 48-byte Fp stride that the C++ decode routines assume |
| `status_codes_match_committed_header` | a renumbered `bls_backend_status` enumerator |
| `unknown_status_codes_degrade_to_internal_error` | a raw code outside `0..=7` decoding to a specific diagnosis instead of `InternalError` |

`drift_detectors_actually_reject_drift` is a negative control: it feeds the
parsers a renumbered status, a commented-out enumerator, a resized G1, and a
missing macro, and asserts each is detected. Without it the table above could
quietly degrade into tests that always pass — which is exactly what the
verification layer did before it was enabled.

The `extern "C"` *signatures* are also pinned, though not by Verus. Two
independent mechanisms in `bls_ffi.rs` close that gap: each `extern` item is
coerced at compile time to a separately written `unsafe extern "C" fn` type
(`extern_items_coerce_to_expected_signatures`), so a declaration that drifts
from the intended signature is a type error; and the committed header is parsed
and compared against the same expected table, per function and per parameter
(`extern_signatures_match_committed_header`), so argument order, arity,
pointer-ness and `const`ness are checked against the real C declaration.
Because parameter names are compared as well as types, even a swap between two
parameters of identical type is detected (as a rename). What these mechanisms
cannot see is a *C++ implementation* that internally uses its arguments in a
different order than the header declares — the declarations agree with each
other, the behaviour does not.

This is machine-checked but it is a test, not a proof: the guarantee holds only
for signatures the table enumerates, and it says nothing about the C++
implementation's behaviour. Note also that the C++ compiler already ties
`bls_backend.h` to `bls_backend.cpp`, so header-vs-implementation drift is a
build error; the gap these tests close is specifically Rust-vs-header.

Not covered on this boundary: the C++ encode/decode routines themselves. The
C++ guards against null, zero, and non-power-of-two lengths are present and
reviewed, but nothing ties the Rust slice lengths to what the C++ loop then
indexes, and the hard-coded 48/96/144-byte offsets are not checked against the
`BLS_BACKEND_*_BYTES` macros.

One genuine limitation to note: `spec_native_ntt` states only the empty-slice
half of the guard, because `usize::is_power_of_two` has no Verus model. The
power-of-two half is covered by `ntt_rejects_non_power_of_two`.

## Known gaps

These are **not** covered. An earlier revision of this document claimed they
were done; the referenced spec functions do not exist in the source.

1. **Parser byte-cursor bounds are unverified.** The `.r1cs` / `.wtns` / `.ptau`
   parsers (`parse_r1cs_raw`, `parse_sparse_vector`, …) are driven by `nom`,
   which is an unverified external crate, so the `offset + n <= data.len()`
   discipline they rely on is unchecked.

   One piece *is* proven, though: `sparse_capacity_is_sound`
   (`circom_adapter.rs`) formally derives the per-term stride (4-byte wire id +
   32-byte field element = 36 bytes) and shows that if the term loop pushes
   `n_terms` terms then `n_terms <= rest_len / 36`. That is the justification
   for the allocation guard below — it was previously a hand-written `min(...)`
   with a comment asserting it was safe, and is now a machine-checked fact.
   `term_loop_model` is a model rather than the parser itself: it tracks a
   length instead of a slice and abstracts the field decode, so it pins the
   stride arithmetic and the loop bound, not `nom`'s behaviour.

2. ~~**Wire ids are not bounds-checked.**~~ **Fixed** in `229ea43`.
   `parse_sparse_vector` used to store a `u32` wire id straight from the file,
   and `CircomCircuit::parse_r1cs` then indexed `l[i][wire as usize]` with it,
   so a 148-byte `.r1cs` panicked instead of returning an error. Both
   representations now call `validate_wire_ids` after `parse_r1cs_raw`, which
   rejects an out-of-range id with a diagnostic naming the wire and the declared
   `n_wires`. The related unbounded `Vec::with_capacity(n_terms)` — a tiny file
   could ask for a ~200 GB allocation — was bounded by what the buffer can hold.

   The bounds *check* is a runtime one; `validate_wire_ids` itself is not
   verified. Only the capacity half is proved, per item 1.

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
