// The Groth16 proof-system core (R1CS/QAP/engine, ceremony, phase2, ptau,
// circom adapter, prover) lives in the standalone `trusted_setup` library
// crate (`clis/trusted-setup`). This crate re-exports it so existing callers
// of `groth16_prover::{r1cs, qap, engine, prover, circom_adapter, ceremony,
// ptau, phase2}` keep working unchanged, and adds the Privacy-circuit witness
// helpers on top.
pub use trusted_setup::{circom_adapter, ceremony, engine, phase2, prover, ptau, qap, r1cs};

// Witness-input helpers for the Privacy / Spend circuit (BLS12-381 only)
#[cfg(feature = "privacy")]
pub mod mimc;
#[cfg(feature = "privacy")]
pub mod sparse_merkle_tree;
#[cfg(feature = "privacy")]
pub mod privacy_inputs;
#[cfg(feature = "privacy")]
pub mod ed25519;
