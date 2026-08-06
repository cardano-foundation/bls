pub mod r1cs;
pub mod qap;
pub mod engine;
pub mod prover;
pub mod circom_adapter;
pub mod ceremony;
pub mod ptau;
pub mod phase2;

// Witness-input helpers for the Privacy / Spend circuit (BLS12-381 only)
#[cfg(feature = "privacy")]
pub mod mimc;
#[cfg(feature = "privacy")]
pub mod sparse_merkle_tree;
#[cfg(feature = "privacy")]
pub mod privacy_inputs;
#[cfg(feature = "privacy")]
pub mod ed25519;
