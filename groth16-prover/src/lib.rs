pub mod r1cs;
pub mod qap;
pub mod engine;
pub mod prover;
pub mod circom_adapter;
pub mod ceremony;
pub mod ptau;
pub mod phase2;

// Witness-input helpers for the Privacy / Spend circuit (BLS12-381 only)
pub mod mimc;
pub mod sparse_merkle_tree;
pub mod privacy_inputs;
