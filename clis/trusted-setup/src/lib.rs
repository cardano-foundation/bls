//! Groth16 trusted-setup core over BLS12-381 (arkworks).
//!
//! This crate contains the Groth16 proof-system core shared by the CLI
//! binaries in this repository:
//!
//!   - `trusted-setup` (this crate's binary): `ceremony`, `ceremony-dev`,
//!     `phase2` trusted-setup commands
//!   - `groth16-prover` CLI: `prove`, `verify`, `export-vk`, `nova`
//!   - future CLIs (e.g. a dedicated `nova-prover`)
//!
//! Module layout:
//!
//!   - [`r1cs`], [`qap`], [`engine`] — R1CS / QAP / FFT machinery
//!   - [`ceremony`] — toxic waste, key types, single-party ceremony
//!   - [`phase2`] — multi-party MPC accumulator (`.zkey`)
//!   - [`ptau`] — snarkjs Powers-of-Tau parser
//!   - [`circom_adapter`] — `.r1cs` / `.wtns` loading
//!   - [`prover`] — proof generation
//!   - [`cmd`] — command runners for the CLI binary (reusable by other CLIs)

pub mod r1cs;
pub mod qap;
pub mod engine;
pub mod ceremony;
pub mod ptau;
pub mod phase2;
pub mod circom_adapter;
pub mod prover;

pub mod cmd;
