//! Verus smoke test — confirms the toolchain and dependencies are wired correctly.
//!
//! This file contains small verified functions that confirm Verus is actually
//! checking this crate.  It is gated behind the `verus` feature so that normal
//! `cargo check` / `cargo test` do not need the Verus crates.
//!
//! Note that this module is only *checked* when the package declares
//! `[package.metadata.verus] verify = true`; without that Cargo/Verus only
//! compiles the crate and silently skips verification.

#![cfg(feature = "verus")]

use vstd::prelude::*;

verus! {

    /// A trivial function to confirm Verus is operational.
    pub fn add_one(x: u64) -> (y: u64)
        requires
            x < 0xffff_ffff_ffff_ffffu64,
        ensures
            y == x + 1,
    {
        x + 1
    }

    /// The induction step used by [`sum_first_n`]: doubling the accumulator
    /// value after adding `i0 + 1` gives `(i0 + 1) * (i0 + 2)`.
    proof fn lemma_sum_step(i0: u64, acc0: u64)
        requires
            2 * acc0 == i0 * (i0 + 1),
        ensures
            2 * acc0 + 2 * (i0 + 1) == (i0 + 1) * (i0 + 2),
    {
        assert(2 * acc0 + 2 * (i0 + 1) == i0 * (i0 + 1) + 2 * (i0 + 1));
        assert(i0 * (i0 + 1) + 2 * (i0 + 1) == (i0 + 1) * (i0 + 2)) by (nonlinear_arith);
    }

    /// Monotonicity of multiplication on non-negative integers.
    proof fn lemma_mul_mono(a: int, b: int, c: int, d: int)
        requires
            0 <= a,
            a <= c,
            0 <= b,
            b <= d,
        ensures
            a * b <= c * d,
    {
        assert(d - b >= 0);
        assert(c - a >= 0);
        assert(c * d - a * b == c * (d - b) + b * (c - a)) by (nonlinear_arith);
        assert(c * (d - b) >= 0) by (nonlinear_arith)
            requires
                0 <= c,
                0 <= d - b,
        ;
        assert(b * (c - a) >= 0) by (nonlinear_arith)
            requires
                0 <= b,
                0 <= c - a,
        ;
        assert(c * d - a * b >= 0);
    }

    /// A slightly more interesting proof: `s` is the sum of the first `n`
    /// natural numbers, i.e. `2 * s == n * (n + 1)`.
    pub fn sum_first_n(n: u64) -> (s: u64)
        requires
            n <= 1000,
        ensures
            2 * s == n * (n + 1),
    {
        let mut i: u64 = 0;
        let mut acc: u64 = 0;
        while i < n
            invariant
                i <= n,
                n <= 1000,
                acc <= 500_500,
                2 * acc == i * (i + 1),
            decreases n - i,
        {
            let i0 = i;
            let acc0 = acc;
            proof {
                // Reason in unbounded `int` arithmetic, where no overflow
                // obligations apply, then re-establish the `u64` facts.
                let gi: int = i0 as int;
                let ga: int = acc0 as int;
                assert(0 <= gi && gi <= 999);
                assert(0 <= ga && ga <= 500_500);
                assert(2 * ga == gi * (gi + 1));
                assert((gi + 1) * (gi + 2) - (gi * (gi + 1) + 2 * (gi + 1)) == 0) by (nonlinear_arith);
                assert(2 * ga + 2 * (gi + 1) == gi * (gi + 1) + 2 * (gi + 1));
                assert(2 * ga + 2 * (gi + 1) == (gi + 1) * (gi + 2));
                assert(2 * ga + 2 * (gi + 1) == (gi + 1) * (gi + 2));
                assert(gi + 1 <= 1000);
                assert(gi + 2 <= 1001);
                lemma_mul_mono(gi + 1, gi + 2, 1000, 1001);
            }
            i = i + 1;
            acc = acc + i;
            assert(acc <= 500_500);
        }
        assert(i == n);
        assert(2 * acc == n * (n + 1));
        acc
    }

}
