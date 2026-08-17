use lattirust_arithmetic::challenge_set::ternary::{Trit, TernaryChallengeSet};
use lattirust_arithmetic::linear_algebra::Vector;
use lattirust_arithmetic::nimue::traits::ChallengeFromRandomBytes;
use lattirust_arithmetic::ring::Z2_64;
use nimue::{hash::Keccak, IOPattern, Merlin};

use crate::params::LovaParams;

/// Byte size of a single ternary challenge (1 needed + 16 security padding).
const TRIT_BYTE_SIZE: usize = 17;

/// Build the IOPattern for Lova folding.
///
/// Protocol flow:
/// 1. Absorb the commitments (com_z, com_e)
/// 2. Ratchet
/// 3. Absorb witness + error (for verification)
/// 4. Ratchet
/// 5. Squeeze ternary challenge
pub fn folding_iopattern(params: &LovaParams) -> IOPattern<Keccak> {
    IOPattern::<Keccak>::new("lattice-lova-folding-v1")
        .absorb(params.m * 8, "com_z")
        .absorb(params.m * 8, "com_e")
        .ratchet()
        .absorb(params.n * 8, "witness")
        .absorb(params.n * 8, "error")
        .ratchet()
        .squeeze(params.decompose_digits * TRIT_BYTE_SIZE, "ternary_challenge")
        .ratchet()
}

/// Create a new Merlin (prover) transcript for a folding step.
pub fn new_prover_transcript(params: &LovaParams) -> Merlin<Keccak> {
    let io = folding_iopattern(params);
    io.to_merlin()
}

/// Squeeze a deterministic ternary challenge from the transcript.
///
/// This replaces the random `sample_ternary_challenge` with a Fiat-Shamir
/// version that derives the challenge deterministically from the absorbed data.
pub fn squeeze_ternary_challenge(
    merlin: &mut Merlin<Keccak>,
    k: usize,
) -> Result<Vector<Z2_64>, nimue::IOPatternError> {
    let trits: Vec<Trit> = merlin.challenge_vec::<Trit, TernaryChallengeSet<Trit>>(k)?;
    Ok(Vector::from_vec(
        trits.into_iter()
            .map(|t| match t {
                Trit::MinusOne => Z2_64::from(-1i64),
                Trit::Zero => Z2_64::from(0i64),
                Trit::One => Z2_64::from(1i64),
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nimue::ByteWriter;

    #[test]
    fn test_transcript_deterministic_challenge() {
        let params = LovaParams::toy();
        let mut merlin1 = new_prover_transcript(&params);
        let mut merlin2 = new_prover_transcript(&params);

        // Absorb the same data
        let com_z: Vec<u8> = vec![0u8; params.m * 8];
        let com_e: Vec<u8> = vec![1u8; params.m * 8];
        merlin1.add_bytes(&com_z).unwrap();
        merlin1.add_bytes(&com_e).unwrap();
        merlin1.ratchet().unwrap();

        let witness: Vec<u8> = vec![2u8; params.n * 8];
        let error: Vec<u8> = vec![3u8; params.n * 8];
        merlin1.add_bytes(&witness).unwrap();
        merlin1.add_bytes(&error).unwrap();
        merlin1.ratchet().unwrap();

        merlin2.add_bytes(&com_z).unwrap();
        merlin2.add_bytes(&com_e).unwrap();
        merlin2.ratchet().unwrap();

        merlin2.add_bytes(&witness).unwrap();
        merlin2.add_bytes(&error).unwrap();
        merlin2.ratchet().unwrap();

        // Both should derive the same challenge
        let c1 = squeeze_ternary_challenge(&mut merlin1, params.decompose_digits).unwrap();
        let c2 = squeeze_ternary_challenge(&mut merlin2, params.decompose_digits).unwrap();
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_transcript_different_data_different_challenge() {
        let params = LovaParams::toy();
        let mut merlin1 = new_prover_transcript(&params);
        let mut merlin2 = new_prover_transcript(&params);

        // Same com_z, com_e
        merlin1.add_bytes(&vec![0u8; params.m * 8]).unwrap();
        merlin1.add_bytes(&vec![1u8; params.m * 8]).unwrap();
        merlin1.ratchet().unwrap();
        merlin1.add_bytes(&vec![2u8; params.n * 8]).unwrap();
        merlin1.add_bytes(&vec![3u8; params.n * 8]).unwrap();
        merlin1.ratchet().unwrap();

        merlin2.add_bytes(&vec![0u8; params.m * 8]).unwrap();
        merlin2.add_bytes(&vec![1u8; params.m * 8]).unwrap();
        merlin2.ratchet().unwrap();
        merlin2.add_bytes(&vec![2u8; params.n * 8]).unwrap();
        merlin2.add_bytes(&vec![4u8; params.n * 8]).unwrap(); // different error
        merlin2.ratchet().unwrap();

        let c1 = squeeze_ternary_challenge(&mut merlin1, params.decompose_digits).unwrap();
        let c2 = squeeze_ternary_challenge(&mut merlin2, params.decompose_digits).unwrap();
        assert_ne!(c1, c2);
    }

    #[test]
    fn test_challenge_values_are_ternary() {
        use lattirust_arithmetic::ring::representatives::WithSignedRepresentative;

        let params = LovaParams::toy();
        let mut merlin = new_prover_transcript(&params);
        merlin.add_bytes(&vec![0u8; params.m * 8]).unwrap();
        merlin.add_bytes(&vec![0u8; params.m * 8]).unwrap();
        merlin.ratchet().unwrap();
        merlin.add_bytes(&vec![0u8; params.n * 8]).unwrap();
        merlin.add_bytes(&vec![0u8; params.n * 8]).unwrap();
        merlin.ratchet().unwrap();

        let challenge = squeeze_ternary_challenge(&mut merlin, params.decompose_digits).unwrap();
        for j in 0..challenge.len() {
            let val = challenge[j].as_signed_representative();
            assert!(
                val >= -1 && val <= 1,
                "challenge[{}] = {} is not ternary",
                j, val
            );
        }
    }
}
