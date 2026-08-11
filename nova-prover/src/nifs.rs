//! NIFS folding module (Implementation 9) — Relaxed-R1CS over BLS12-381.
//!
//! A Relaxed-R1CS instance `U = (x, u, W̄, Ē)` consists of a public input
//! `x`, a slack scalar `u`, and Pedersen commitments `W̄`, `Ē` to the witness
//! `W` and the error vector `E`.  The relaxed equation is
//! `(AZ)∘(BZ) = u·(CZ) + E` with `Z = (W, x, u)`.  Step instances are ordinary
//! R1CS (`u = 1`, `E = 0`); folding combines two instances into one that is
//! satisfiable exactly when both inputs were.
//!
//! Folding runs **off-circuit**, so no curve cycle is needed.  The Pedersen
//! basis is deterministic (hash-to-scalar from a fixed seed) — transparent,
//! no trusted setup.

use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, Group, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalSerialize, SerializationError};
use blake2::{Blake2b512, Digest};

/// Domain separator for the folding challenge hash (distinct from the
/// `"chain"` state-chain transcript).
pub const FOLD_PREFIX: &[u8] = b"groth16-prover-nova-fold-v1";

/// A Relaxed-R1CS instance `U = (x, u, W̄, Ē)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaxedR1csInstance {
    /// Public input (IVC state).
    pub x: Vec<Fr>,
    /// Slack scalar `u`.
    pub u: Fr,
    /// Pedersen commitment to the witness `W`.
    pub w_commit: G1Affine,
    /// Pedersen commitment to the error `E`.
    pub e_commit: G1Affine,
}

/// The witness `W' = (W, E)` of a Relaxed-R1CS instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelaxedR1csWitness {
    /// Witness assignment (full wire vector, including public inputs).
    pub w: Vec<Fr>,
    /// Error vector, length = number of constraints.
    pub e: Vec<Fr>,
}

/// Pedersen commitment parameters: the deterministic G1 bases for `W` and `E`.
#[derive(Debug, Clone)]
pub struct PedersenParams {
    /// Basis for the witness commitment, one point per wire.
    pub basis_w: Vec<G1Affine>,
    /// Basis for the error commitment, one point per constraint.
    pub basis_e: Vec<G1Affine>,
}

impl PedersenParams {
    /// Derive the bases deterministically from a seed: each basis point is
    /// `H(seed ‖ domain ‖ index)` times the G1 generator.  No trusted setup.
    pub fn from_seed(seed: &[u8], n_wires: usize, n_constraints: usize) -> Self {
        Self {
            basis_w: derive_basis(seed, b"witness", n_wires),
            basis_e: derive_basis(seed, b"error", n_constraints),
        }
    }
}

/// Hash `(seed ‖ domain ‖ index)` to a G1 point via scalar multiplication.
fn derive_basis(seed: &[u8], domain: &[u8], n: usize) -> Vec<G1Affine> {
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let mut h = Blake2b512::new();
        h.update(seed);
        h.update(domain);
        h.update(i.to_le_bytes());
        let scalar = Fr::from_le_bytes_mod_order(&h.finalize());
        out.push(G1Affine::from(G1Projective::generator() * scalar));
    }
    out
}

/// Pedersen commitment `com(v) = Σ v_i·G_i`.
pub fn commit(basis: &[G1Affine], values: &[Fr]) -> G1Affine {
    if values.is_empty() {
        return G1Affine::zero();
    }
    debug_assert_eq!(basis.len(), values.len(), "basis/values length mismatch");
    G1Affine::from(G1Projective::msm(basis, values).expect("MSM length mismatch"))
}

/// Serialize an instance to compressed bytes for the folding transcript.
pub fn instance_to_bytes(u: &RelaxedR1csInstance) -> Result<Vec<u8>, SerializationError> {
    let mut buf = Vec::new();
    for f in &u.x {
        f.serialize_compressed(&mut buf)?;
    }
    u.u.serialize_compressed(&mut buf)?;
    u.w_commit.serialize_compressed(&mut buf)?;
    u.e_commit.serialize_compressed(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basis_derivation_is_deterministic() {
        let a = PedersenParams::from_seed(b"seed", 8, 4);
        let b = PedersenParams::from_seed(b"seed", 8, 4);
        assert_eq!(a.basis_w, b.basis_w);
        assert_eq!(a.basis_e, b.basis_e);
        assert_eq!(a.basis_w.len(), 8);
        assert_eq!(a.basis_e.len(), 4);

        let c = PedersenParams::from_seed(b"other", 8, 4);
        assert_ne!(a.basis_w, c.basis_w);
    }

    #[test]
    fn commit_is_additive() {
        let params = PedersenParams::from_seed(b"seed", 4, 1);
        let a: Vec<Fr> = (1..=4).map(|i| Fr::from(i)).collect();
        let b: Vec<Fr> = (5..=8).map(|i| Fr::from(i)).collect();
        let sum: Vec<Fr> = a.iter().zip(&b).map(|(x, y)| *x + *y).collect();

        assert_eq!(
            commit(&params.basis_w, &sum),
            commit(&params.basis_w, &a) + commit(&params.basis_w, &b)
        );
    }

    #[test]
    fn commit_empty_is_zero() {
        let params = PedersenParams::from_seed(b"seed", 0, 0);
        assert!(commit(&params.basis_w, &[]).is_zero());
    }

    #[test]
    fn commit_zero_vector_is_zero() {
        let params = PedersenParams::from_seed(b"seed", 4, 1);
        let zeros = vec![Fr::zero(); 4];
        assert!(commit(&params.basis_w, &zeros).is_zero());
    }
}
