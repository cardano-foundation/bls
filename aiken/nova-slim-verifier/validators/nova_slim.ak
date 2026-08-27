use aiken/transaction.{ScriptContext}
use nova_slim_verifier/verifier.{NifsBundle, SlimProof, verify_slim}

/// On-chain validator for NovaSlim slim proofs.
///
/// Parameters (applied at compile time or via `aiken apply`):
///   - `expected_public_input`: the public input x that the proof must commit to.
///
/// Redeemer: `SlimProof` (the sumcheck proof).
/// Datum:    `NifsBundle` (the folded instance commitments).
///
/// The validator succeeds iff `verify_slim(datum, redeemer)` returns `True`.
///
/// This validator is **commitment-scheme agnostic**: it works for Pedersen,
/// SIS, and Hash folded instances because the on-chain check is only the
/// sumcheck protocol.  Off-chain, an auditor can verify the HashPC openings
/// (truth tables) against the commitment hashes in the datum.
validator(expected_public_input: ByteArray) {
  fn nova_slim_verify(
    datum: NifsBundle,
    redeemer: SlimProof,
    _context: ScriptContext,
  ) {
    let public_input_ok = redeemer.public_input == expected_public_input
    let proof_ok = verify_slim(datum, redeemer)
    public_input_ok && proof_ok
  }
}
