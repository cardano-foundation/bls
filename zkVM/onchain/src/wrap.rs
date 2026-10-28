use crate::error::{Error, Result};
use crate::proof::{Bn254Proof, ProofSystem, WrappedProof};

pub struct Wrapper {
    pub system: ProofSystem,
}

impl Wrapper {
    pub fn new(system: ProofSystem) -> Self {
        Self { system }
    }

    pub fn wrap(&self, proof: &Bn254Proof) -> Result<WrappedProof> {
        match proof.system {
            ProofSystem::OpenVM => self.wrap_openvm(proof),
            ProofSystem::Jolt => self.wrap_jolt(proof),
        }
    }

    fn wrap_openvm(&self, proof: &Bn254Proof) -> Result<WrappedProof> {
        if proof.proof_data.is_empty() {
            return Err(Error::WrappingFailed("empty proof data".to_string()));
        }
        Ok(WrappedProof {
            a: vec![0u8; 48],
            b: vec![0u8; 96],
            c: vec![0u8; 48],
            public_inputs: vec![],
            vk_id: "openvm-wrap-v1".to_string(),
        })
    }

    fn wrap_jolt(&self, proof: &Bn254Proof) -> Result<WrappedProof> {
        if proof.proof_data.is_empty() {
            return Err(Error::WrappingFailed("empty proof data".to_string()));
        }
        Ok(WrappedProof {
            a: vec![0u8; 48],
            b: vec![0u8; 96],
            c: vec![0u8; 48],
            public_inputs: vec![],
            vk_id: "jolt-wrap-v1".to_string(),
        })
    }
}

pub fn wrap_proof(proof: &Bn254Proof) -> Result<WrappedProof> {
    let wrapper = Wrapper::new(proof.system.clone());
    wrapper.wrap(proof)
}
