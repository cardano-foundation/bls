//! `print_circom_proof` — prove with a Circom-loaded circuit and assert parity.
//!
//! This binary synthesises the exact `.r1cs` / `.wtns` bytes that Circom would
//! emit for `multiplier.circom`, parses them with the `circom_adapter`, builds
//! a `QapEngine` from the resulting matrices, and proves using the same
//! `NaiveProver` / `PippengerProver` stack.  The final proof is asserted to be
//! identical to the one produced from the hard-coded circuit.

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::Group;
use groth16_prover::{
    circom_adapter::CircomCircuit,
    engine::{DenseQapEngine, FftQapEngine},
    prover::{NaiveProver, PippengerProver, Prover},
    r1cs::{L, O, R, WITNESS},
};

fn build_synthetic_r1cs() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"r1cs");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    let field_size = 32u32;
    let n_wires = 8u32;
    let n_pub_out = 1u32;
    let n_pub_in = 0u32;
    let n_prv_in = 4u32;
    let n_labels = 8u64;
    let n_constraints = 3u32;

    let mut header = Vec::new();
    header.extend_from_slice(&field_size.to_le_bytes());
    header.extend_from_slice(&[0u8; 32]);
    header.extend_from_slice(&n_wires.to_le_bytes());
    header.extend_from_slice(&n_pub_out.to_le_bytes());
    header.extend_from_slice(&n_pub_in.to_le_bytes());
    header.extend_from_slice(&n_prv_in.to_le_bytes());
    header.extend_from_slice(&n_labels.to_le_bytes());
    header.extend_from_slice(&n_constraints.to_le_bytes());

    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(&header);

    let mut constraints = Vec::new();
    let mut write_vec = |terms: &[(u32, u64)]| {
        constraints.extend_from_slice(&(terms.len() as u32).to_le_bytes());
        for &(w, v) in terms {
            constraints.extend_from_slice(&w.to_le_bytes());
            constraints.push(v as u8);
            constraints.extend_from_slice(&vec![0u8; field_size as usize - 1]);
        }
    };

    // x1*x2 = x5
    write_vec(&[(2, 1)]);
    write_vec(&[(3, 1)]);
    write_vec(&[(6, 1)]);
    // x3*x4 = x6
    write_vec(&[(4, 1)]);
    write_vec(&[(5, 1)]);
    write_vec(&[(7, 1)]);
    // x5*x6 = a
    write_vec(&[(6, 1)]);
    write_vec(&[(7, 1)]);
    write_vec(&[(1, 1)]);

    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(constraints.len() as u64).to_le_bytes());
    out.extend_from_slice(&constraints);
    out
}

fn build_synthetic_wtns() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"wtns");
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&2u32.to_le_bytes());

    let field_size = 32u32;
    let n_wires = 8u32;
    let mut header = Vec::new();
    header.extend_from_slice(&field_size.to_le_bytes());
    header.extend_from_slice(&[0u8; 32]);
    header.extend_from_slice(&n_wires.to_le_bytes());

    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(&header);

    let witness = vec![1u64, 48, 2, 2, 3, 4, 4, 12];
    let mut data = Vec::new();
    for &v in &witness {
        data.push(v as u8);
        data.extend_from_slice(&vec![0u8; field_size as usize - 1]);
    }

    out.extend_from_slice(&2u32.to_le_bytes());
    out.extend_from_slice(&(data.len() as u64).to_le_bytes());
    out.extend_from_slice(&data);
    out
}

fn main() {
    // ------------------------------------------------------------------
    // 1. Load Circom circuit from synthetic bytes
    // ------------------------------------------------------------------
    let mut circuit = CircomCircuit::from_bytes(&build_synthetic_r1cs()).unwrap();
    circuit
        .load_witness_from_bytes(&build_synthetic_wtns(), 32)
        .unwrap();

    println!("Circom circuit loaded:");
    println!("  wires       = {}", circuit.n_wires);
    println!("  constraints = {}", circuit.n_constraints);
    println!("  witness     = {:?}", circuit.witness);

    // ------------------------------------------------------------------
    // 2. Build QAP engines from Circom matrices (dynamic Vec<Vec<u64>>)
    // ------------------------------------------------------------------
    let l_ref: Vec<&[u64]> = circuit.l.iter().map(|v| v.as_slice()).collect();
    let r_ref: Vec<&[u64]> = circuit.r.iter().map(|v| v.as_slice()).collect();
    let o_ref: Vec<&[u64]> = circuit.o.iter().map(|v| v.as_slice()).collect();

    let dense = DenseQapEngine::new();
    let fft = FftQapEngine::new();

    // ------------------------------------------------------------------
    // 3. Prove with both engines using NaiveProver
    // ------------------------------------------------------------------
    let witness_fr: Vec<Fr> = circuit.witness.iter().map(|&v| Fr::from(v)).collect();
    let tau = Fr::from(3u64);
    let alpha = Fr::from(5u64);
    let beta = Fr::from(7u64);
    let gamma = Fr::from(11u64);
    let delta = Fr::from(13u64);

    let naive = NaiveProver::new();
    let pippenger = PippengerProver::new();

    let (dense_proof, _) = naive.prove(&dense, &l_ref, &r_ref, &o_ref, &witness_fr, tau, alpha, beta, gamma, delta);
    let (fft_proof, fft_public) = naive.prove(&fft, &l_ref, &r_ref, &o_ref, &witness_fr, tau, alpha, beta, gamma, delta);

    println!("\nDense engine proof:");
    println!("  A = {:?}", dense_proof.a);
    println!("  B = {:?}", dense_proof.b);
    println!("  C = {:?}", dense_proof.c);

    println!("\nFFT engine proof:");
    println!("  A = {:?}", fft_proof.a);
    println!("  B = {:?}", fft_proof.b);
    println!("  C = {:?}", fft_proof.c);

    // ------------------------------------------------------------------
    // 4. Prove with PippengerProver for speed
    // ------------------------------------------------------------------
    let (pipp_proof, _) = pippenger.prove(&dense, &l_ref, &r_ref, &o_ref, &witness_fr, tau, alpha, beta, gamma, delta);
    println!("\nPippengerProver (dense) proof:");
    println!("  A = {:?}", pipp_proof.a);
    println!("  B = {:?}", pipp_proof.b);
    println!("  C = {:?}", pipp_proof.c);

    // ------------------------------------------------------------------
    // 5. Assert parity with hard-coded circuit
    // ------------------------------------------------------------------
    let hardcoded_witness: Vec<Fr> = WITNESS.iter().map(|&v| Fr::from(v)).collect();
    let hardcoded_dense = DenseQapEngine::new();
    let (hardcoded_proof, _) = naive.prove(&hardcoded_dense, &L, &R, &O, &hardcoded_witness, tau, alpha, beta, gamma, delta);

    assert_eq!(dense_proof, hardcoded_proof, "Dense proof must match hard-coded proof");
    assert_eq!(pipp_proof, hardcoded_proof, "Pippenger proof must match hard-coded proof");

    // FFT produces a mathematically equivalent but bit-different proof (valid
    // QAP via roots-of-unity vs dense Lagrange).  We verify it independently.
    let alpha_g1 = G1Affine::from(G1Projective::generator() * alpha);
    let beta_g2 = G2Affine::from(G2Projective::generator() * beta);
    let gamma_g2 = G2Affine::from(G2Projective::generator() * gamma);
    let delta_g2 = G2Affine::from(G2Projective::generator() * delta);

    assert!(
        groth16_prover::prover::verify_proof(&fft_proof, &fft_public, &alpha_g1, &beta_g2, &gamma_g2, &delta_g2),
        "FFT Circom proof must pass pairing check"
    );

    println!("\n✅ All Circom proofs match the hard-coded circuit proof (or pass verification)!");
}
