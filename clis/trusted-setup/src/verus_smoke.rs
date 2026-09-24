//! Verus smoke test — confirms the toolchain and dependencies are wired correctly.
//!
//! This file contains a trivial verified function that proves `add_one` returns
//! a value one greater than its input.  It is gated behind the `verus` feature
//! so that normal `cargo check` / `cargo test` do not need the Verus crates.

#![cfg(feature = "verus")]

use vstd::prelude::*;

verus! {

    /// A trivial function to confirm Verus is operational.
    pub fn add_one(x: u64) -> (y: u64)
        ensures y == x + 1
    {
        x + 1
    }

    /// A slightly more interesting proof: sum of first n natural numbers.
    pub fn sum_first_n(n: u64) -> (s: u64)
        requires n <= 1000
        ensures s == n * (n + 1) / 2
    {
        let mut i: u64 = 0;
        let mut acc: u64 = 0;
        while i < n
            invariant
                i <= n,
                acc == i * (i + 1) / 2,
        {
            i = i + 1;
            acc = acc + i;
        }
        acc
    }

}
