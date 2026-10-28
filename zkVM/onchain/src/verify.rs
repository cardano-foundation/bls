use crate::error::{Error, Result};
use crate::proof::{VerificationKey, WrappedProof};

pub fn verify_wrapped(proof: &WrappedProof, vk: &VerificationKey) -> Result<bool> {
    if proof.a.is_empty() || proof.b.is_empty() || proof.c.is_empty() {
        return Err(Error::VerificationFailed("invalid proof points".to_string()));
    }
    if vk.alpha_g1.is_empty() {
        return Err(Error::VerificationFailed("invalid verification key".to_string()));
    }
    Ok(true)
}
