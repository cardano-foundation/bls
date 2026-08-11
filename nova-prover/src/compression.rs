//! Compression circuit for the NIFS fold (Implementation 9, work item 2).
//!
//! The compression Groth16 proof certifies that the final relaxed instance is
//! satisfiable.  The circuit is built **in Rust** (no circom needed): it
//! reuses the step circuit's sparse A/B/C matrices and checks the relaxed
//! equation `(AZ)∘(BZ) = u·(CZ) + E` row by row, with the folded witness `Z`,
//! the slack `u` and the error vector `E` all public — exactly the check
//! [`nifs::fold`] guarantees the accumulated instance satisfies.
//!
//! Size: `2 · n_constraints` constraints ("size ≈ one step").
//!
//! The Pedersen commitments `W̄`, `Ē` are **not** checked inside the circuit:
//! the circuit field is BLS12-381 `Fr` while the bases live on G1 over `Fq`,
//! so an in-circuit re-commitment would require non-native arithmetic
//! (~30K–190K constraints per wire — infeasible at step scale).  Instead the
//! verifier recomputes `com(W)`, `com(E)` with a native MSM (O(step),
//! milliseconds) and compares against the bundle instance.  Binding: the
//! circuit makes `(x, u, W, E)` public, so the Groth16 proof and the native
//! MSM check are both anchored to the same witness.

use ark_bls12_381::Fr;
use ark_ff::{One, Zero};
use groth16_prover::circom_adapter::r1cs_to_bytes_sparse;

/// The compression circuit for one step circuit.
///
/// Wire layout (all indices into the compression circuit's witness):
///
/// | index | meaning |
/// |-------|---------|
/// | `0`   | R1CS constant `1` |
/// | `1 .. 1+n_wires` | `Z` (folded step wires, `Z[0]` = folded constant) |
/// | `1+n_wires` | slack `u` |
/// | `2+n_wires .. 2+n_wires+n_constraints` | error `E` |
/// | `2+n_wires+n_constraints ..` | `t_i = u·(CZ)_i` intermediates (private) |
///
/// The first `n_public = 1 + n_wires + 1 + n_constraints` wires are public
/// (matching this prover's convention that the public-input vector is
/// `witness[..n_public]`, i.e. wire 0 = constant 1 followed by the public
/// values).
#[derive(Debug, Clone)]
pub struct CompressionCircuit {
    /// Step wire count (the `Z` vector width, including wire 0).
    pub n_wires: usize,
    /// Step constraint count.
    pub n_constraints: usize,
    /// Public wire count (`1 + n_wires + 1 + n_constraints`).
    pub n_public: usize,
    /// Total compression-circuit wires (public + the `t_i` intermediates).
    pub n_wires_total: usize,
    /// Sparse A matrix (`2 × n_constraints` rows, `(wire, coeff)`).
    pub l: Vec<Vec<(u32, Fr)>>,
    /// Sparse B matrix.
    pub r: Vec<Vec<(u32, Fr)>>,
    /// Sparse C matrix.
    pub o: Vec<Vec<(u32, Fr)>>,
}

/// Compression-circuit wire index of the step wire `j` (`Z[j]`).
#[inline]
pub fn z_wire(j: usize) -> usize {
    1 + j
}

impl CompressionCircuit {
    /// Build the compression circuit from the step circuit's sparse A/B/C
    /// matrices and wire count.
    pub fn new(
        step_l: &[Vec<(u32, Fr)>],
        step_r: &[Vec<(u32, Fr)>],
        step_o: &[Vec<(u32, Fr)>],
        n_wires: usize,
    ) -> Self {
        assert_eq!(step_l.len(), step_r.len());
        assert_eq!(step_l.len(), step_o.len());
        let n_constraints = step_l.len();
        let n_public = 1 + n_wires + 1 + n_constraints;
        let n_wires_total = n_public + n_constraints;

        let u_wire = Self::u_wire(n_wires);
        let e_wire = |i: usize| Self::e_wire(n_wires, i);
        let t_wire = |i: usize| Self::t_wire(n_wires, n_constraints, i);
        let remap = |row: &[Vec<(u32, Fr)>], i: usize| {
            row[i]
                .iter()
                .map(|&(j, c)| ((z_wire(j as usize)) as u32, c))
                .collect::<Vec<_>>()
        };

        let mut l = Vec::with_capacity(2 * n_constraints);
        let mut r = Vec::with_capacity(2 * n_constraints);
        let mut o = Vec::with_capacity(2 * n_constraints);

        for i in 0..n_constraints {
            // t_i = u · (CZ)_i
            l.push(vec![(u_wire as u32, Fr::one())]);
            r.push(remap(step_o, i));
            o.push(vec![(t_wire(i) as u32, Fr::one())]);
            // (AZ)_i · (BZ)_i = t_i + e_i
            l.push(remap(step_l, i));
            r.push(remap(step_r, i));
            o.push(vec![
                (t_wire(i) as u32, Fr::one()),
                (e_wire(i) as u32, Fr::one()),
            ]);
        }

        Self {
            n_wires,
            n_constraints,
            n_public,
            n_wires_total,
            l,
            r,
            o,
        }
    }

    /// Compression-circuit wire index of the slack `u`.
    #[inline]
    pub fn u_wire(n_wires: usize) -> usize {
        1 + n_wires
    }

    /// Compression-circuit wire index of `E[i]`.
    #[inline]
    pub fn e_wire(n_wires: usize, i: usize) -> usize {
        2 + n_wires + i
    }

    /// Compression-circuit wire index of the intermediate `t_i`.
    #[inline]
    pub fn t_wire(n_wires: usize, n_constraints: usize, i: usize) -> usize {
        2 + n_wires + n_constraints + i
    }

    /// Evaluate a sparse row against a witness: `Σ coeff·witness[wire]`.
    pub fn eval_lin(row: &[(u32, Fr)], v: &[Fr]) -> Fr {
        row.iter()
            .fold(Fr::zero(), |acc, &(w, c)| acc + c * v[w as usize])
    }

    /// Build the full compression witness from the folded instance/witness.
    ///
    /// `z` is the folded wire vector (including wire 0, which is `1 + r` after
    /// a fold), `u` the slack, `e` the error vector.  The intermediate wires
    /// `t_i = u·(CZ)_i` are computed from the circuit's own B rows.
    pub fn witness(&self, z: &[Fr], u: Fr, e: &[Fr]) -> Vec<Fr> {
        assert_eq!(z.len(), self.n_wires, "z length must equal step n_wires");
        assert_eq!(e.len(), self.n_constraints, "e length must equal n_constraints");

        let mut v = vec![Fr::zero(); self.n_wires_total];
        v[0] = Fr::one();
        for (j, &val) in z.iter().enumerate() {
            v[z_wire(j)] = val;
        }
        v[Self::u_wire(self.n_wires)] = u;
        for (i, &val) in e.iter().enumerate() {
            v[Self::e_wire(self.n_wires, i)] = val;
        }
        for i in 0..self.n_constraints {
            let cz = Self::eval_lin(&self.r[2 * i], &v);
            v[Self::t_wire(self.n_wires, self.n_constraints, i)] = u * cz;
        }
        v
    }

    /// The public-input prefix of a witness (`witness[..n_public]`).
    pub fn public_inputs<'a>(&self, v: &'a [Fr]) -> &'a [Fr] {
        assert!(v.len() >= self.n_public);
        &v[..self.n_public]
    }

    /// Serialize the circuit to a Circom-compatible sparse `.r1cs` blob.
    pub fn to_r1cs_bytes(&self) -> Vec<u8> {
        r1cs_to_bytes_sparse(
            self.n_wires_total as u32,
            (self.n_public - 1) as u32,
            0,
            (self.n_wires_total - self.n_public) as u32,
            &self.l,
            &self.r,
            &self.o,
        )
    }

    /// Check whether a witness satisfies every constraint of this circuit.
    ///
    /// Used by tests (and available to the CLI for sanity checks): for each
    /// constraint row `(A,B,C)` asserts `(A·V)·(B·V) == C·V`.
    pub fn is_satisfied(&self, v: &[Fr]) -> bool {
        assert_eq!(v.len(), self.n_wires_total);
        for (a, (b, c)) in self.l.iter().zip(self.r.iter().zip(&self.o)) {
            let lhs = Self::eval_lin(a, v) * Self::eval_lin(b, v);
            let rhs = Self::eval_lin(c, v);
            if lhs != rhs {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nifs::{self, PedersenParams};

    /// One step-constraint matrix: `A`, `B`, `C` (sparse `(wire, coeff)` rows).
    type StepR1cs = (Vec<Vec<(u32, Fr)>>, Vec<Vec<(u32, Fr)>>, Vec<Vec<(u32, Fr)>>);

    /// One-constraint multiplier step: `Z[1]·Z[2] = Z[3]`, wire 0 = constant 1.
    fn step_r1cs() -> StepR1cs {
        (
            vec![vec![(1u32, Fr::from(1u64))]],
            vec![vec![(2u32, Fr::from(1u64))]],
            vec![vec![(3u32, Fr::from(1u64))]],
        )
    }

    /// Ordinary R1CS instance/witness from a satisfying step witness.
    fn make_instance(
        params: &PedersenParams,
        w: &[Fr],
    ) -> (nifs::RelaxedR1csInstance, nifs::RelaxedR1csWitness) {
        (
            nifs::RelaxedR1csInstance {
                x: w[1..3].to_vec(),
                u: Fr::from(1u64),
                w_commit: nifs::commit(&params.basis_w, w),
                e_commit: nifs::commit(&params.basis_e, &[Fr::zero()]),
            },
            nifs::RelaxedR1csWitness {
                w: w.to_vec(),
                e: vec![Fr::zero()],
            },
        )
    }

    /// Fold two multiplier steps into a non-trivial relaxed instance.
    fn folded_instance() -> (nifs::RelaxedR1csInstance, nifs::RelaxedR1csWitness, StepR1cs) {
        let (l, r, o) = step_r1cs();
        let params = PedersenParams::from_seed(b"compression-test", 4, 1);
        let (u1, w1) = make_instance(&params, &[Fr::from(1), Fr::from(2), Fr::from(3), Fr::from(6)]);
        let (u2, w2) = make_instance(&params, &[Fr::from(1), Fr::from(5), Fr::from(7), Fr::from(35)]);
        let challenge = nifs::fold_challenge(b"acc", &u1, &u2);
        let (u3, w3) = nifs::fold(&params, &l, &r, &o, &u1, &w1, &u2, &w2, challenge);
        (u3, w3, (l, r, o))
    }

    #[test]
    fn wire_layout_maps_step_rows() {
        let (l, r, o) = step_r1cs();
        let c = CompressionCircuit::new(&l, &r, &o, 4);

        assert_eq!(c.n_wires, 4);
        assert_eq!(c.n_constraints, 1);
        // 1 (const) + 4 (Z) + 1 (u) + 1 (e) public, + 1 (t) private.
        assert_eq!(c.n_public, 7);
        assert_eq!(c.n_wires_total, 8);
        assert_eq!(c.l.len(), 2);
        assert_eq!(c.r.len(), 2);
        assert_eq!(c.o.len(), 2);

        // Constraint 0: t_0 = u · Z[3]   (u at 5, Z[3] at 4, t_0 at 7)
        assert_eq!(c.l[0], vec![(5, Fr::from(1u64))]);
        assert_eq!(c.r[0], vec![(4, Fr::from(1u64))]);
        assert_eq!(c.o[0], vec![(7, Fr::from(1u64))]);
        // Constraint 1: Z[1] · Z[2] = t_0 + e_0   (Z[1] at 2, Z[2] at 3, e_0 at 6)
        assert_eq!(c.l[1], vec![(2, Fr::from(1u64))]);
        assert_eq!(c.r[1], vec![(3, Fr::from(1u64))]);
        assert_eq!(c.o[1], vec![(7, Fr::from(1u64)), (6, Fr::from(1u64))]);
    }

    #[test]
    fn folded_witness_satisfies_generated_r1cs() {
        let (u3, w3, (l, r, o)) = folded_instance();
        let c = CompressionCircuit::new(&l, &r, &o, w3.w.len());

        assert_ne!(u3.u, Fr::from(1u64), "the folded slack must be non-trivial");
        let v = c.witness(&w3.w, u3.u, &w3.e);
        assert!(c.is_satisfied(&v), "honest folded witness must satisfy the circuit");

        // The public-input prefix is [1, Z..., u, E...].
        let pub_in = c.public_inputs(&v);
        assert_eq!(pub_in.len(), c.n_public);
        assert_eq!(pub_in[0], Fr::one());
        assert_eq!(pub_in[z_wire(0)], w3.w[0]);
        assert_eq!(pub_in[CompressionCircuit::u_wire(c.n_wires)], u3.u);
        assert_eq!(
            pub_in[CompressionCircuit::e_wire(c.n_wires, 0)],
            w3.e[0]
        );
    }

    #[test]
    fn tampered_error_is_rejected() {
        let (u3, w3, (l, r, o)) = folded_instance();
        let c = CompressionCircuit::new(&l, &r, &o, w3.w.len());

        let mut e = w3.e.clone();
        e[0] += Fr::from(1u64);
        let v = c.witness(&w3.w, u3.u, &e);
        assert!(!c.is_satisfied(&v), "tampered E must violate a constraint");

        let mut z = w3.w.clone();
        z[1] += Fr::from(1u64);
        let v = c.witness(&z, u3.u, &w3.e);
        assert!(!c.is_satisfied(&v), "tampered Z must violate a constraint");
    }

    #[test]
    fn r1cs_bytes_roundtrip() {
        let (u3, w3, (l, r, o)) = folded_instance();
        let c = CompressionCircuit::new(&l, &r, &o, w3.w.len());

        let bytes = c.to_r1cs_bytes();
        let mut parsed = groth16_prover::circom_adapter::SparseCircomCircuit::from_bytes(&bytes)
            .expect("generated .r1cs must parse");
        assert_eq!(parsed.n_wires as usize, c.n_wires_total);
        assert_eq!(parsed.n_constraints as usize, 2 * c.n_constraints);
        assert_eq!(parsed.n_pub_out as usize, c.n_public - 1);

        let v = c.witness(&w3.w, u3.u, &w3.e);
        parsed
            .load_witness_from_bytes(
                &groth16_prover::circom_adapter::wtns_to_bytes(&v),
                32,
            )
            .expect("witness must load");
        assert_eq!(parsed.witness, v);
    }
}
