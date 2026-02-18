use bls/api.{PublicKey}
use bls/pairing.{aggregate_g1}

/// Aggregates multiple BLS public keys into a single public key.
/// Uses the **aggregate_g1** function to iteratively uncompress and add the public keys,
/// and then compresses the resulting aggregated public key.
/// The aggregation is in the context of G1 group.
///
/// Arguments:
/// * publickeys: List<PublicKey> - A list of BLS public keys to be aggregated.
///
/// Returns:
/// PublicKey - The compressed aggregated BLS public key.
pub fn aggregate_publickeys(publickeys: List<PublicKey>) -> PublicKey {
  aggregate_g1(publickeys)
}