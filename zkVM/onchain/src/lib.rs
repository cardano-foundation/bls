//! zkVM on-chain verification: BN254 → BLS12-381 Groth16 wrapping
//!
//! This crate provides utilities for wrapping zkVM proofs (OpenVM/Jolt, BN254)
//! into BLS12-381 Groth16 proofs verifiable by Cardano's Plutus builtins.

pub mod error;
pub mod proof;
pub mod wrap;
pub mod verify;

#[cfg(feature = "verus")]
pub mod verus_specs;

#[cfg(test)]
mod tests;

pub use error::{Error, Result};
pub use proof::{Bn254Proof, WrappedProof, VerificationKey, ProofSystem};
pub use wrap::wrap_proof;
pub use verify::verify_wrapped;
