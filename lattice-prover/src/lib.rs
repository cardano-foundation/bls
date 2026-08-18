//! `lattice-prover` — lattice-based (post-quantum) IVC folding, research track.
//!
//! Evaluation of **Lova** (Fenzi, Knabenhans, Nguyen, Pham — ASIACRYPT 2024), the
//! first folding scheme whose security relies on the unstructured SIS assumption.
//!
//! This crate implements the core Lova primitives using the `lattirust-arithmetic`
//! library for ring arithmetic, vector/matrix operations, and Fiat-Shamir transcripts.

pub mod bls12_381_adapter;
pub mod commitment;
pub mod decompose;
pub mod fold;
pub mod params;
pub mod rns;
pub mod transcript;
