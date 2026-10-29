//! E2E examples for running VRF/KDF on OpenVM and Jolt

pub mod error;
pub mod encoder;
pub mod runner;
pub mod benchmarks;

#[cfg(feature = "verus")]
pub mod verus_specs;

#[cfg(test)]
mod tests;

pub use error::{Error, Result};
