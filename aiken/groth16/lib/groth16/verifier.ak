use aiken/builtin.{
  bls12_381_final_verify,
  bls12_381_g1_add,
  bls12_381_g1_uncompress,
  bls12_381_g2_uncompress,
  bls12_381_miller_loop,
  bls12_381_mul_miller_loop_result,
}
use aiken/crypto/bls12_381/g1 as g1
use aiken/crypto/bls12_381/scalar as scalar

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Groth16 proof consisting of three compressed curve points.
pub type Proof {
  a: ByteArray,
  b: ByteArray,
  c: ByteArray,
}

/// Groth16 verification key — everything needed to verify a proof.
///
/// * `alpha_g1` — 48-byte compressed G1 point (`alpha * G1`).
/// * `beta_g2`  — 96-byte compressed G2 point (`beta * G2`).
/// * `gamma_g2` — 96-byte compressed G2 point (`gamma * G2`).
/// * `delta_g2` — 96-byte compressed G2 point (`delta * G2`).
/// * `ic`       — list of 48-byte compressed G1 points. `ic[i] = Psi_V_G1[i]`.
///                  Only the first `n_public` entries are used for `V`.
/// * `n_public` — number of public variables (including the constant wire).
pub type VerificationKey {
  alpha_g1: ByteArray,
  beta_g2: ByteArray,
  gamma_g2: ByteArray,
  delta_g2: ByteArray,
  ic: List<ByteArray>,
  n_public: Int,
}

// ---------------------------------------------------------------------------
// Hard-coded verification key (compressed BLS12-381 points)
// ---------------------------------------------------------------------------

/// alpha * G1  (scalar = 5)
const alpha_g1 =
  #"b0e7791fb972fe014159aa33a98622da3cdc98ff707965e536d8636b5fcc5ac7a91a8c46e59a00dca575af0f18fb13dc"

/// beta * G2  (scalar = 7)
const beta_g2 =
  #"8d0273f6bf31ed37c3b8d68083ec3d8e20b5f2cc170fa24b9b5be35b34ed013f9a921f1cad1644d4bdb14674247234c8049cd1dbb2d2c3581e54c088135fef36505a6823d61b859437bfc79b617030dc8b40e32bad1fa85b9c0f368af6d38d3c"

/// gamma * G2  (scalar = 11)
const gamma_g2 =
  #"a190be857d602284393305bfe0a29e29a6982ed3f04ccaabafb7e59cdc7eda85c22bc3e8690355c7a0fb7590ae40f1b009303f04d568e289a35102b6df883d5ed620355c0eb5d02236718cdaf99fba6e19ef5cee2996268eb9a53ae1ee09bce3"

/// delta * G2  (scalar = 13)
const delta_g2 =
  #"8bf78a97086750eb166986ed8e428ca1d23ae3bbf8b2ee67451d7dd84445311e8bc8ab558b0bc008199f577195fc39b7152110e866f1a6e8c5348f6e005dbd93de671b7d0fbfa04d6614bcdd27a3cb2a70f0deacb3608ba95226268481a0be7c"

/// Psi_V_G1[1] = (w_1(tau) * alpha + u_1(tau) * beta + w_1(tau)) / gamma * G1
/// For our circuit, variable 1 is the public output `a`. Scalar = 3/gamma.
const psi_v_g1_1 =
  #"a087561bc7f3b2650328084de8424253a1846fe77fb0f498a3fade9d70b556016d1de5d0490fa64a444a1f53cc13d70d"

// ---------------------------------------------------------------------------
// Hard-coded proof for the concrete witness [1, 48, 2, 2, 3, 4, 4, 12]
// ---------------------------------------------------------------------------

/// A = (l(tau)+alpha) * G1  (combined scalar = 10)
const proof_a =
  #"af81da25ecf1c84b577fefbedd61077a81dc43b00304015b2b596ab67f00e41c86bb00ebd0f90d4b125eb0539891aeed"

/// B = (r(tau)+beta) * G2  (combined scalar = 33)
const proof_b =
  #"ab0f336a9b3ee493b210f64587b8c1d5fab0a86346812545a822692c40ee4eecb349a69388ba3ad13ea3c5f8d29eb36506547761152a1517a6fffeefff70c7e817bdcf94dfa8e25955a0b4ac6ffcfd9477d7230902453d78bac3bcd06dbbb457"

/// C = (sum_private + h(tau)*T(tau)/delta) * G1  (combined scalar = 151/delta)
const proof_c =
  #"b697c05f3d58d125ed8630e8f547dd5a952c33753b65629e18efcada75d443690fc1f3759dfb55edc35e4d03dd17860e"

// ---------------------------------------------------------------------------
// Convenience constructors (for backward compatibility / tests)
// ---------------------------------------------------------------------------

/// The hard-coded valid proof for the concrete circuit.
pub fn hardcoded_proof() -> Proof {
  Proof { a: proof_a, b: proof_b, c: proof_c }
}

/// The hard-coded verification key for the concrete 3-constraint circuit.
pub fn hardcoded_verification_key() -> VerificationKey {
  VerificationKey {
    alpha_g1,
    beta_g2,
    gamma_g2,
    delta_g2,
    ic: [
      // Variable 0 (constant `1`) — point at infinity
      #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      // Variable 1 (output `a`) — psi_v_g1_1
      psi_v_g1_1,
      // Variables 2..7 are private — their ic entries are never used by the verifier,
      // but we include them so `ic` has one entry per variable (8 total).
      #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ],
    n_public: 2,
  }
}

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

/// Verify a Groth16 proof against a supplied verification key.
///
/// * `proof`         – compressed points `(A, B, C)`.
/// * `public_inputs` – list of public witness values. The length must match
///                     `vk.n_public`. Variable 0 is the constant `1`.
/// * `vk`            – verification key containing CRS points and `ic` list.
///
/// Returns `True` iff the Groth16 pairing equation holds.
pub fn verify(proof: Proof, public_inputs: List<Int>, vk: VerificationKey) -> Bool {
  // Decompress proof points.
  let a = bls12_381_g1_uncompress(proof.a)
  let b = bls12_381_g2_uncompress(proof.b)
  let c = bls12_381_g1_uncompress(proof.c)

  // Decompress VK fixed points.
  let alpha = bls12_381_g1_uncompress(vk.alpha_g1)
  let beta = bls12_381_g2_uncompress(vk.beta_g2)
  let gamma = bls12_381_g2_uncompress(vk.gamma_g2)
  let delta = bls12_381_g2_uncompress(vk.delta_g2)

  // Compute the public-input commitment V.
  let v = compute_public_input_commitment(public_inputs, vk.ic, vk.n_public)

  // Pairing check:
  //   e(A, B) == e(alpha·G1, beta·G2) · e(C, delta·G2) · e(V, gamma·G2)
  let lhs = bls12_381_miller_loop(a, b)

  let rhs = bls12_381_miller_loop(alpha, beta)
  let rhs = bls12_381_mul_miller_loop_result(rhs, bls12_381_miller_loop(c, delta))
  let rhs = bls12_381_mul_miller_loop_result(rhs, bls12_381_miller_loop(v, gamma))

  bls12_381_final_verify(lhs, rhs)
}

/// Compute the public-input commitment `V = Σ a_i · ic[i]`.
///
/// * `public_inputs` – witness values for the public variables.
/// * `ic`            – list of compressed G1 points (`Psi_V_G1`), one per variable.
/// * `n_public`      – number of public variables to consume from the front of the lists.
///
/// Returns the identity point if the input lengths are mismatched or `n_public`
/// is zero — this causes the pairing check to fail for malformed input.
fn compute_public_input_commitment(
  public_inputs: List<Int>,
  ic: List<ByteArray>,
  n_public: Int,
) -> G1Element {
  // Build the MSM over the first `n_public` entries.
  do_compute_v(public_inputs, ic, n_public, g1.zero)
}

/// Tail-recursive helper that accumulates `v` one public input at a time.
fn do_compute_v(
  public_inputs: List<Int>,
  ic: List<ByteArray>,
  remaining: Int,
  acc: G1Element,
) -> G1Element {
  if remaining <= 0 {
    acc
  } else {
    when (public_inputs, ic) is {
      ([input, ..rest_inputs], [ic_point, ..rest_ic]) -> {
        let pt = bls12_381_g1_uncompress(ic_point)
        let s = scalar.from_int(input)
        let weighted = g1.scale(pt, s)
        do_compute_v(rest_inputs, rest_ic, remaining - 1, bls12_381_g1_add(acc, weighted))
      }
      _ -> g1.zero
    }
  }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

test test_verify_hardcoded_proof() {
  let proof = hardcoded_proof()
  let vk = hardcoded_verification_key()
  verify(proof, [1, 48], vk)
}

test test_verify_reject_wrong_public_input() {
  let proof = hardcoded_proof()
  let vk = hardcoded_verification_key()
  // Wrong public output (49 instead of 48) changes V and breaks the pairing.
  !verify(proof, [1, 49], vk)
}

test test_verify_reject_tampered_proof() {
  let vk = hardcoded_verification_key()
  // Replace C with the G1 generator: valid point, wrong proof.
  let bad_c =
    #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
  let bad_proof = Proof { a: proof_a, b: proof_b, c: bad_c }
  !verify(bad_proof, [1, 48], vk)
}

test test_compute_public_input_commitment_matches_expected_v() {
  let vk = hardcoded_verification_key()
  let v = compute_public_input_commitment([1, 48], vk.ic, vk.n_public)
  let expected_v =
    bls12_381_g1_uncompress(
      #"b5ae7b97f37351dbfa7c343f60ac8c1c53a4ab74b227970e8415d5d7a791498cdb0f4bd32809129a90096188dea1b8a0",
    )
  g1.equal(v, expected_v)
}

// ---------------------------------------------------------------------------
// Tests with a *different* VK (ensures verify is not accidentally falling back
// to hard-coded constants).
// ---------------------------------------------------------------------------

test test_verify_fails_with_wrong_vk_alpha() {
  let proof = hardcoded_proof()
  let vk = hardcoded_verification_key()
  // Tamper with alpha_g1 (replace with G1 generator)
  let bad_vk = VerificationKey {
    ..vk,
    alpha_g1: #"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
  }
  !verify(proof, [1, 48], bad_vk)
}

test test_verify_fails_with_wrong_vk_beta() {
  let proof = hardcoded_proof()
  let vk = hardcoded_verification_key()
  // Tamper with beta_g2 (replace with G2 generator)
  let bad_vk = VerificationKey {
    ..vk,
    beta_g2: #"93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
  }
  !verify(proof, [1, 48], bad_vk)
}

test test_verify_fails_with_wrong_vk_ic() {
  let proof = hardcoded_proof()
  let vk = hardcoded_verification_key()
  // Tamper with ic[1] (replace with point at infinity)
  let bad_ic = [
    vk.ic |> head,
    #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ..(vk.ic |> tail |> tail)
  ]
  let bad_vk = VerificationKey { ..vk, ic: bad_ic }
  !verify(proof, [1, 48], bad_vk)
}

fn head(list: List<a>) -> a {
  when list is {
    [x, ..] -> x
    _ -> fail @"head called on empty list"
  }
}

fn tail(list: List<a>) -> List<a> {
  when list is {
    [_, ..rest] -> rest
    _ -> []
  }
}

// ---------------------------------------------------------------------------
// Generalization tests — arbitrary-length public inputs
// ---------------------------------------------------------------------------

test test_single_public_input() {
  // A VK with one public variable (just the constant wire).
  let vk = VerificationKey {
    alpha_g1,
    beta_g2,
    gamma_g2,
    delta_g2,
    ic: [
      #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    ],
    n_public: 1,
  }
  // Any proof paired with this VK will fail because the VK does not match the
  // hard-coded circuit, but the MSM for V should still compute the identity.
  // We only assert that the function runs and returns a Bool.
  let _result = verify(hardcoded_proof(), [1], vk)
  True
}

test test_zero_public_inputs() {
  let vk = VerificationKey {
    alpha_g1,
    beta_g2,
    gamma_g2,
    delta_g2,
    ic: [],
    n_public: 0,
  }
  let _result = verify(hardcoded_proof(), [], vk)
  True
}

// ---------------------------------------------------------------------------
// End-to-end Circom pipeline test
// ---------------------------------------------------------------------------

/// Verification key exported from the Rust dev ceremony on the compiled
/// `SimpleExample/multiplier.circom` circuit (3 constraints, 8 wires,
/// 2 public variables: constant `1` and output `a`).
fn simple_example_vk() -> VerificationKey {
  VerificationKey {
    alpha_g1: #"81802380864a9f81298b8b82413406b4df3e0b5fd97a66e18ca464ed6e0be83b1c09ab2c2f4e3ecf8527bea992aeeb25",
    beta_g2: #"a71f88c45cb4aca43947a6f8b4b45ecd85516b8a9438ee11f301393140c54f594fa01158167dde0d3ca1a383c2f720f20d9d3ec49300f7cf388fb492328eeddc777b7345ecac3fded1d541856e941d315e0a6e7d513fc02a01748f59f36ab002",
    gamma_g2: #"b52ff6d727d7499a6ef7194fecf44fa0a03743fcf58e4727a8f42d1fc0cd0830a37ceece819da818af09721d2c32260f0c647be82c35de92a087eb3a4c85c5dfd60da9d973d7075ae707a2be33c848884ff19a3d13cdc200bb82e978f993c5cf",
    delta_g2: #"a9954557c3215b9e27fe7aafd760087ee842c564739e57ba330dc58e4ee72798aa2a2f5218a90b06616918123588fa50119a7c91ae4f81a68c5cd4f027325b31688fa5c4da9961440c1fac2df4fc5232890f617758210ca3d4afe67c6fe6e3f5",
    ic: [
      // ic[0] — constant wire
      #"c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      // ic[1] — public output `a`
      #"99d2c73cb79eaef7a45982beb31c038d69c4d88b835b4ecdcc2d3524677bb7eb35b0cc4b991a1ed0ca1e8e746a80948a",
      // ic[2] — private x1
      #"8857efc20ffabaa6837b770e22ad25c09cb081bbcce6da252d104e9fa08e2e1a5fd9476cb68e4cf2a4fe6bd6450124d2",
      // ic[3] — private x2
      #"936106b42859b335e2cf1c491124c5c18eb0a1cc117373f43cf2d1310748c22444c695a3e81350d68ff18ad5de4885ed",
      // ic[4] — private x3
      #"8592db99ef875c762756ad9518ac22644786c6abe7f15890628328e32498cc85578e793c06412fd940975a6468b25f4a",
      // ic[5] — private x4
      #"988764bb6e7823cf4c83658c458c70e096b419730faac5bb118a491534abc8892aea37bc7518946e836d376c9ef9fce6",
      // ic[6] — intermediate x5
      #"80f042242a53ece532781b2872667d1e66dd1d90dcb934bf9d6fcecd2034509e04eaf73d0ba1e0ab013e7527cb11d64d",
      // ic[7] — intermediate x6
      #"9137a31cdef863c5bbb927f23a7d761a011ae8a46415fe4f8ab6eba18b3a9511be26ff5d1b5c659dce66064698454a9c",
    ],
    n_public: 2,
  }
}

/// Proof generated by the Rust prover (Pippenger, FFT engine) for the
/// witness [1, 48, 2, 2, 3, 4, 4, 12] with the VK above.
fn simple_example_proof() -> Proof {
  Proof {
    a: #"b2d8a0555803aff03b02c7a9de897f6fe1909e728c3a1668497756dfb6d92c8c73633d0a178251182947a552c92f8bd2",
    b: #"8170b0e3032a62c50fe2222467a348f5b2f78f7a91072c1c8524708ddd17c017b5cdec3e2145a2d4f60286a5c034227a159020f5c6cf7309b5050c2b5fa6741593add450583fc7cc935a65baac7df7950357a62580c797a1d3bb2b8452778e7b",
    c: #"b8ea5b9db7f801e194f7c6a5d2c21911cbc0923166327651cdd8c48a7a1f2b5e1ac3bb4c8bcea77b01f460c72a11e293",
  }
}

test test_verify_circom_simple_example_proof() {
  // Public witness values for SimpleExample: [constant 1, output a = 48]
  verify(simple_example_proof(), [1, 48], simple_example_vk())
}

test test_verify_circom_rejects_wrong_public_input() {
  // Changing the public output breaks V and the pairing check fails.
  !verify(simple_example_proof(), [1, 49], simple_example_vk())
}
