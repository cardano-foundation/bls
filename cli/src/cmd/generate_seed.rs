use bls12_381_aiken_cli::common::generate_crypto_secure_seed;
use std::error::Error;

/// Generate a 32-byte random hex-encoded seed
///
/// This command generates a cryptographically secure random seed that can be used
/// as input for the hkdf command to derive a private key.
/// The output is a 64-character hex string representing 32 bytes of random data.
///
/// Examples:
///   cargo run --quiet -- generate-seed
///   cargo run --quiet -- generate-seed ; echo
///   SEED=$(cargo run --quiet -- generate-seed) && echo $SEED
pub fn run() -> Result<(), Box<dyn Error>> {
    let mut seed_bytes = [0u8; 32];
    generate_crypto_secure_seed(&mut seed_bytes);
    print!("{}", hex::encode(seed_bytes));

    Ok(())
}
