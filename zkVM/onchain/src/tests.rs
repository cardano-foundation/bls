#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::proof::{Bn254Proof, ProofSystem};
    use crate::wrap::wrap_proof;
    use crate::verify::verify_wrapped;
    use crate::proof::VerificationKey;
    use crate::WrappedProof;

    #[test]
    fn test_wrap_openvm_empty_fails() {
        let proof = Bn254Proof {
            system: ProofSystem::OpenVM,
            public_inputs: vec![],
            proof_data: vec![],
            vm_commitment: None,
        };
        assert!(matches!(wrap_proof(&proof), Err(Error::WrappingFailed(_))));
    }

    #[test]
    fn test_wrap_jolt_empty_fails() {
        let proof = Bn254Proof {
            system: ProofSystem::Jolt,
            public_inputs: vec![],
            proof_data: vec![],
            vm_commitment: None,
        };
        assert!(matches!(wrap_proof(&proof), Err(Error::WrappingFailed(_))));
    }

    #[test]
    fn test_wrap_openvm_success() {
        let proof = Bn254Proof {
            system: ProofSystem::OpenVM,
            public_inputs: vec![vec![1,2,3]],
            proof_data: vec![0u8; 100],
            vm_commitment: Some(vec![4,5,6]),
        };
        let wrapped = wrap_proof(&proof).unwrap();
        assert_eq!(wrapped.a.len(), 48);
        assert_eq!(wrapped.b.len(), 96);
        assert_eq!(wrapped.c.len(), 48);
        assert_eq!(wrapped.vk_id, "openvm-wrap-v1");
    }

    #[test]
    fn test_wrap_jolt_success() {
        let proof = Bn254Proof {
            system: ProofSystem::Jolt,
            public_inputs: vec![],
            proof_data: vec![1u8; 50],
            vm_commitment: None,
        };
        let wrapped = wrap_proof(&proof).unwrap();
        assert_eq!(wrapped.vk_id, "jolt-wrap-v1");
    }

    #[test]
    fn test_verify_wrapped_success() {
        let proof = WrappedProof {
            a: vec![0u8; 48],
            b: vec![0u8; 96],
            c: vec![0u8; 48],
            public_inputs: vec!["1".to_string()],
            vk_id: "test".to_string(),
        };
        let vk = VerificationKey {
            alpha_g1: vec![0u8; 48],
            beta_g2: vec![0u8; 96],
            gamma_g2: vec![0u8; 96],
            delta_g2: vec![0u8; 96],
            ic: vec![],
            n_public: 1,
        };
        assert!(verify_wrapped(&proof, &vk).unwrap());
    }

    #[test]
    fn test_verify_wrapped_empty_proof_fails() {
        let proof = WrappedProof {
            a: vec![],
            b: vec![0u8; 96],
            c: vec![0u8; 48],
            public_inputs: vec![],
            vk_id: "test".to_string(),
        };
        let vk = VerificationKey::new();
        assert!(matches!(verify_wrapped(&proof, &vk), Err(Error::VerificationFailed(_))));
    }

    #[test]
    fn test_verify_wrapped_empty_vk_fails() {
        let proof = WrappedProof {
            a: vec![0u8; 48],
            b: vec![0u8; 96],
            c: vec![0u8; 48],
            public_inputs: vec![],
            vk_id: "test".to_string(),
        };
        let vk = VerificationKey::new();
        assert!(matches!(verify_wrapped(&proof, &vk), Err(Error::VerificationFailed(_))));
    }
}
