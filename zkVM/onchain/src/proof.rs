use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofSystem {
    OpenVM,
    Jolt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bn254Proof {
    pub system: ProofSystem,
    pub public_inputs: Vec<Vec<u8>>,
    pub proof_data: Vec<u8>,
    pub vm_commitment: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedProof {
    pub a: Vec<u8>,
    pub b: Vec<u8>,
    pub c: Vec<u8>,
    pub public_inputs: Vec<String>,
    pub vk_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationKey {
    pub alpha_g1: Vec<u8>,
    pub beta_g2: Vec<u8>,
    pub gamma_g2: Vec<u8>,
    pub delta_g2: Vec<u8>,
    pub ic: Vec<Vec<u8>>,
    pub n_public: usize,
}

impl VerificationKey {
    pub fn new() -> Self {
        Self {
            alpha_g1: vec![],
            beta_g2: vec![],
            gamma_g2: vec![],
            delta_g2: vec![],
            ic: vec![],
            n_public: 0,
        }
    }
}

impl Default for VerificationKey {
    fn default() -> Self {
        Self::new()
    }
}
