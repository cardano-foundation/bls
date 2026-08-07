// The Groth16 proof-system core (R1CS/QAP/engine, ceremony, phase2, ptau,
// circom adapter, prover) lives in the standalone `trusted_setup` library
// crate (`clis/trusted-setup`). This crate re-exports it so existing callers
// of `groth16_prover::{r1cs, qap, engine, prover, circom_adapter, ceremony,
// ptau, phase2}` keep working unchanged.
pub use trusted_setup::{circom_adapter, ceremony, engine, phase2, prover, ptau, qap, r1cs};
