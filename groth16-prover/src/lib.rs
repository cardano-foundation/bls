// The Groth16 proof-system core (R1CS/QAP/engine, ceremony, phase2, ptau,
// circom adapter, prover) lives in the standalone `trusted_setup` library
// crate (`clis/trusted-setup`). This crate re-exports it so existing callers
// of `groth16_prover::{r1cs, qap, engine, prover, circom_adapter, ceremony,
// ptau, phase2}` keep working unchanged.
pub use trusted_setup::{circom_adapter, ceremony, engine, phase2, prover, ptau, qap, r1cs};

/// Low-level BLS12-381 group-arithmetic backends (MSM, pairing, NTT).
///
/// The `backend` module is available when the `native` feature is enabled;
/// it exposes the vendored blst FFI primitives (`native_msm_g1`,
/// `native_msm_g2`, `native_pairing_batch_check`, `native_ntt`) alongside
/// the arkworks reference paths.
#[cfg(feature = "native")]
pub use trusted_setup::backend;
