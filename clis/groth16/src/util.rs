//! Small CLI helpers reused across subcommands.

use ark_serialize::CanonicalDeserialize;
use std::error::Error;
use std::fs;
use std::path::Path;

use groth16_prover::ceremony::{FullProvingKey, VerifyingKey};

/// Load a `FullProvingKey` from a file, trying uncompressed unchecked first
/// (fast for large keys) and falling back to compressed deserialization.
pub fn load_full_pk(path: &Path) -> Result<FullProvingKey, Box<dyn Error>> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read proving key: {e}"))?;
    if let Ok(pk) = FullProvingKey::deserialize_uncompressed_unchecked(&bytes[..]) {
        return Ok(pk);
    }
    let pk = FullProvingKey::deserialize_compressed(&bytes[..])
        .map_err(|e| format!("failed to deserialize FullProvingKey: {e:?}"))?;
    Ok(pk)
}

/// Load a `VerifyingKey` from a file, trying uncompressed unchecked first
/// and falling back to compressed deserialization.
pub fn load_vk(path: &Path) -> Result<VerifyingKey, Box<dyn Error>> {
    let bytes = fs::read(path).map_err(|e| format!("failed to read verifying key: {e}"))?;
    if let Ok(vk) = VerifyingKey::deserialize_uncompressed_unchecked(&bytes[..]) {
        return Ok(vk);
    }
    let vk = VerifyingKey::deserialize_compressed(&bytes[..])
        .map_err(|e| format!("failed to deserialize VerifyingKey: {e:?}"))?;
    Ok(vk)
}
