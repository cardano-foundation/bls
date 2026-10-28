use zkvm_onchain::{wrap_proof, verify_wrapped, Bn254Proof, ProofSystem, VerificationKey, WrappedProof};

#[test]
fn integration_wrap_openvm_then_verify() {
    let proof = Bn254Proof {
        system: ProofSystem::OpenVM,
        public_inputs: vec![vec![0x31, 0x5f, 0x5b, 0xdb]],
        proof_data: vec![0xaa; 200],
        vm_commitment: Some(vec![0xbb; 32]),
    };
    let wrapped = wrap_proof(&proof).unwrap();
    assert_eq!(wrapped.a.len(), 48);
    assert_eq!(wrapped.b.len(), 96);
    assert_eq!(wrapped.c.len(), 48);
    
    let vk = VerificationKey {
        alpha_g1: vec![0u8; 48],
        beta_g2: vec![0u8; 96],
        gamma_g2: vec![0u8; 96],
        delta_g2: vec![0u8; 96],
        ic: vec![vec![0u8; 48]],
        n_public: 1,
    };
    assert!(verify_wrapped(&wrapped, &vk).unwrap());
}

#[test]
fn integration_wrap_jolt_then_verify() {
    let proof = Bn254Proof {
        system: ProofSystem::Jolt,
        public_inputs: vec![],
        proof_data: vec![0xcc; 150],
        vm_commitment: None,
    };
    let wrapped = wrap_proof(&proof).unwrap();
    let vk = VerificationKey {
        alpha_g1: vec![1u8; 48],
        beta_g2: vec![2u8; 96],
        gamma_g2: vec![3u8; 96],
        delta_g2: vec![4u8; 96],
        ic: vec![],
        n_public: 0,
    };
    assert!(verify_wrapped(&wrapped, &vk).unwrap());
}

#[test]
fn test_proof_sizes_match_groth16() {
    let proof = Bn254Proof {
        system: ProofSystem::OpenVM,
        public_inputs: vec![],
        proof_data: vec![0u8; 100],
        vm_commitment: None,
    };
    let wrapped = wrap_proof(&proof).unwrap();
    // Groth16 proof: A (G1, 48 bytes compressed), B (G2, 96 bytes), C (G1, 48 bytes)
    assert_eq!(wrapped.a.len() + wrapped.b.len() + wrapped.c.len(), 192);
}
