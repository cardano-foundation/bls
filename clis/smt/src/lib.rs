//! Sparse Merkle Tree helpers over BLS12-381.
//!
//! Provides the MiMC(x^7) hash, the insert-only sparse Merkle tree, Ed25519
//! key handling for the CardanoKeyOwnershipSMT circuit, and the Spend(depth)
//! witness-input computation. This project is strictly focused on BLS12-381;
//! BN254 is not supported.

pub mod ed25519;
pub mod mimc;
pub mod privacy_inputs;
pub mod sparse_merkle_tree;
