//! Nova IVC folding library — step-chain proofs over BLS12-381 (Implementation 8).
//!
//! A long computation is decomposed into `N` identical step circuits, each
//! proving `state_{i+1} = f(step_i, state_i)`.  The [`run_fold`] operation
//! runs a chain of Groth16 proofs over the step witnesses — every step proof
//! is individually verifiable and the state chain is bound by a BLAKE2b512
//! transcript — while [`run_verify`] re-checks the whole chain.
//!
//! The step circuits must satisfy one invariant (checked by [`check_step_circuit`],
//! exposed to the CLI as the `params` operation): the number of public inputs
//! must equal the number of public outputs (`n_pub_in == n_pub_out`), so the
//! public-input block of step `i+1` must equal the public-output block of
//! step `i`.  Public inputs ARE the IVC state.
//!
//! The proof-system core (R1CS/QAP/engine, ceremony, circom adapter, prover)
//! lives in the `groth16-prover` / `trusted-setup` crates; this crate adds the
//! IVC folding layer on top.  The `nova` CLI (`clis/nova`) wraps the
//! operations in this crate.

use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{PrimeField, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2b512, Digest};
use groth16_prover::ceremony::{
    single_party_ceremony_full_from_tw_sparse, verify_with_vk, FullProvingKey, ToxicWaste,
    VerifyingKey,
};
use groth16_prover::circom_adapter::SparseCircomCircuit;
use groth16_prover::engine::FftQapEngine;
use groth16_prover::prover::{PippengerProver, Proof, Prover, PublicInput};
use serde::{Deserialize, Serialize};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

/// Domain separator for the IVC transcript.
pub const TRANSCRIPT_PREFIX: &[u8] = b"groth16-prover-nova-transcript-v1";

/// NIFS (Implementation 9) domain separators.
///
/// `NIFS_PARAMS_SEED` derives the transparent Pedersen basis; the transcript
/// prefix is distinct from the `"chain"` transcript to prevent cross-context
/// challenge reuse.
pub const NIFS_PARAMS_SEED: &[u8] = b"groth16-prover-nova-nifs-params-v1";
pub const NIFS_TRANSCRIPT_PREFIX: &[u8] = b"groth16-prover-nova-nifs-transcript-v1";

/// NIFS folding module (Implementation 9) — Relaxed-R1CS + Pedersen commitments.
pub mod nifs;

/// Compression circuit for the NIFS fold (Implementation 9, work item 2) —
/// proves the final relaxed instance satisfiable, reusing the step A/B/C.
pub mod compression;

/// JSON descriptor of a step circuit (emitted by the `params` operation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitDescriptor {
    pub n_wires: u32,
    pub n_constraints: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub n_prv_in: u32,
}

/// One folded step inside the IVC bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepProof {
    pub idx: usize,
    /// Public inputs = IVC state entering the step (decimal field strings)
    pub state_in: Vec<String>,
    /// Public outputs = IVC state leaving the step (decimal field strings)
    pub state_out: Vec<String>,
    pub proof_a: String,
    pub proof_b: String,
    pub proof_c: String,
    pub public_v: String,
    pub transcript: String,
}

/// The folded IVC bundle produced by [`run_fold`] and consumed by [`run_verify`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IvcBundle {
    pub circuit: String,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub initial_state: Vec<String>,
    pub steps: Vec<StepProof>,
    pub transcript_final: String,
}

/// Final Relaxed-R1CS instance in a NIFS bundle (public artifact).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NifsFinalInstance {
    /// Folded public input (IVC state), decimal field strings
    pub x: Vec<String>,
    /// Slack scalar `u`, decimal
    pub u: String,
    /// Pedersen commitment to the final witness (compressed G1 hex)
    pub w_commit: String,
    /// Pedersen commitment to the final error (compressed G1 hex)
    pub e_commit: String,
}

/// The NIFS bundle produced by [`run_fold_nifs`] — O(1) in the step count.
///
/// Consumed by the compression proof (Implementation 9, work item 2) and the
/// `nova verify` subcommand.  `n_wires`/`n_constraints` are included so the
/// verifier can derive the transparent Pedersen basis for the commitment
/// check without re-loading the step circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NifsBundle {
    pub circuit: String,
    pub n_wires: u32,
    pub n_constraints: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub initial_state: Vec<String>,
    pub n_steps: usize,
    pub final_instance: NifsFinalInstance,
    pub transcript_final: String,
}

/// Output of [`run_fold_nifs`]: the public bundle plus the private final
/// instance/witness (consumed by the compression proof).
#[derive(Debug, Clone)]
pub struct NifsFoldOutput {
    pub bundle: NifsBundle,
    pub final_instance: nifs::RelaxedR1csInstance,
    pub final_witness: nifs::RelaxedR1csWitness,
}

/// The compression Groth16 proof over the final relaxed instance
/// (Implementation 9, work item 2).
///
/// The circuit makes `(1, Z, u, E)` public (the full folded witness, slack and
/// error vector — only the `t_i = u·(CZ)_i` intermediates are private), so the
/// verifier recomputes the Pedersen commitments `com(Z)`, `com(E)` and the
/// public-input commitment `V` natively and cross-checks them against the
/// bundle's final instance.  `public_inputs` is `witness[..n_public]` as
/// decimal field strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompressionProof {
    pub circuit: String,
    pub n_wires: u32,
    pub n_constraints: u32,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    /// The exact final instance this proof certifies (cross-checked against
    /// the bundle by [`verify_compression`]).
    pub final_instance: NifsFinalInstance,
    pub proof_a: String,
    pub proof_b: String,
    pub proof_c: String,
    /// Compressed G1 hex of the public-input commitment `V`.
    pub public_v: String,
    /// `witness[..n_public]` = `[1, Z(1..1+n_wires), u, E(2+n_wires..)]`.
    pub public_inputs: Vec<String>,
}

/// Summary of a successful [`run_ceremony`].
#[derive(Debug, Clone)]
pub struct CeremonyOutput {
    pub pk_bytes: usize,
    pub vk_bytes: usize,
}

/// Summary of a successful [`run_verify`].
#[derive(Debug, Clone)]
pub struct VerifyOutput {
    pub steps: usize,
    pub transcript_final: String,
}

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

/// Load a step circuit from a `.r1cs` file.
pub fn load_circuit(path: &Path) -> Result<SparseCircomCircuit, Box<dyn Error>> {
    SparseCircomCircuit::from_r1cs(
        path.to_str()
            .ok_or_else(|| format!("circuit path is not valid UTF-8: {path:?}"))?,
    )
    .map_err(|e| format!("failed to load circuit {}: {e}", path.display()).into())
}

/// Enforce the step-chain invariant: the public-input block (state in)
/// must have the same width as the public-output block (state out).
pub fn check_step_circuit(c: &SparseCircomCircuit) -> Result<(), Box<dyn Error>> {
    if c.n_pub_in != c.n_pub_out {
        return Err(format!(
            "not a valid step circuit: n_pub_in ({}) != n_pub_out ({}) — \
             the public inputs must be exactly the IVC state and must have the \
             same width as the public outputs so that state_in[i+1] == state_out[i]",
            c.n_pub_in, c.n_pub_out
        )
        .into());
    }
    Ok(())
}

/// Build the JSON descriptor for a step circuit.
pub fn circuit_descriptor(c: &SparseCircomCircuit) -> CircuitDescriptor {
    CircuitDescriptor {
        n_wires: c.n_wires,
        n_constraints: c.n_constraints,
        n_pub_out: c.n_pub_out,
        n_pub_in: c.n_pub_in,
        n_prv_in: c.n_prv_in,
    }
}

/// `params` — inspect a step circuit and return its JSON descriptor.
///
/// Loads the step circuit from a `.r1cs` file and validates that it
/// satisfies the IVC invariant (`n_pub_in == n_pub_out`).
pub fn run_params(circuit: &Path) -> Result<CircuitDescriptor, Box<dyn Error>> {
    let c = load_circuit(circuit)?;
    check_step_circuit(&c)?;
    Ok(circuit_descriptor(&c))
}

/// `ceremony` — single-party ceremony for a step circuit.
///
/// Loads the step circuit from a `.r1cs` file, generates random toxic
/// waste, and writes a per-step proving key (`.pk`) and verifying key
/// (`.vk`) in binary format.
///
/// This is the **insecure, dev-only** path — use `phase2` for production
/// multi-party ceremonies.  The resulting `.pk` contains only curve points
/// (no scalars), so the prover uses pure MSM.
///
/// Use `h_scalar` for h-query scalar compression (Implementation 7) to
/// reduce proving key size.
pub fn run_ceremony(
    circuit: &Path,
    proving_key: &Path,
    verifying_key: &Path,
    h_scalar: bool,
) -> Result<CeremonyOutput, Box<dyn Error>> {
    let circuit = load_circuit(circuit)?;
    check_step_circuit(&circuit)?;

    eprintln!(
        "Loaded step circuit (sparse): {} wires, {} constraints (public: {} out + {} in, private: {})",
        circuit.n_wires,
        circuit.n_constraints,
        circuit.n_pub_out,
        circuit.n_pub_in,
        circuit.n_prv_in
    );

    let n_public = 1 + circuit.n_pub_out as usize + circuit.n_pub_in as usize;
    let mut rng = rand::thread_rng();
    let engine = FftQapEngine::new();
    let tw = ToxicWaste::random(&mut rng);

    let (full_pk, vk) = single_party_ceremony_full_from_tw_sparse(
        &engine,
        circuit.n_constraints as usize,
        circuit.n_wires as usize,
        n_public,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        tw,
        h_scalar,
    );

    let pk_bytes = write_pk_uncompressed(&full_pk, proving_key)?;
    let vk_bytes = write_vk_uncompressed(&vk, verifying_key)?;

    eprintln!(
        "Nova ceremony complete. h_scalar compression: {}.",
        if h_scalar { "enabled" } else { "disabled" }
    );
    Ok(CeremonyOutput { pk_bytes, vk_bytes })
}

fn write_pk_uncompressed(pk: &FullProvingKey, path: &Path) -> Result<usize, Box<dyn Error>> {
    let mut bytes = Vec::new();
    pk.serialize_uncompressed(&mut bytes)
        .map_err(|e| format!("failed to serialize proving key: {e:?}"))?;
    fs::write(path, &bytes)
        .map_err(|e| format!("failed to write proving key to {}: {e}", path.display()))?;
    eprintln!(
        "Full proving key ({} bytes) written to {}",
        bytes.len(),
        path.display()
    );
    Ok(bytes.len())
}

fn write_vk_uncompressed(vk: &VerifyingKey, path: &Path) -> Result<usize, Box<dyn Error>> {
    let mut bytes = Vec::new();
    vk.serialize_uncompressed(&mut bytes)
        .map_err(|e| format!("failed to serialize verifying key: {e:?}"))?;
    fs::write(path, &bytes)
        .map_err(|e| format!("failed to write verifying key to {}: {e}", path.display()))?;
    eprintln!(
        "Verifying key ({} bytes) written to {}",
        bytes.len(),
        path.display()
    );
    Ok(bytes.len())
}

/// `fold` — fold step witnesses into an IVC bundle.
///
/// Loads the step circuit, the per-step proving key, and a directory of
/// witness files (`step_0000.wtns`, `step_0001.wtns`, …), then produces a
/// Groth16 proof for each step and binds them together with a BLAKE2b
/// transcript.  Returns the [`IvcBundle`] (all step proofs, the initial
/// state, and the final transcript hash), which is consumed by [`run_verify`].
pub fn run_fold(
    circuit: &Path,
    proving_key: &Path,
    steps: &Path,
) -> Result<IvcBundle, Box<dyn Error>> {
    let circuit_path_str = circuit.to_string_lossy().into_owned();
    let mut circuit = load_circuit(circuit)?;
    check_step_circuit(&circuit)?;

    let n_pub_out = circuit.n_pub_out as usize;
    let n_pub_in = circuit.n_pub_in as usize;
    let n_constraints = circuit.n_constraints as usize;

    let full_pk = load_full_pk(proving_key).map_err(|e| format!("failed to load proving key: {e}"))?;
    let engine = FftQapEngine::new();
    let prover = PippengerProver::new();

    let mut wtns_paths: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(steps)
        .map_err(|e| format!("failed to read steps dir {}: {e}", steps.display()))?
    {
        let entry = entry.map_err(|e| format!("failed to read steps dir entry: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("wtns") {
            wtns_paths.push(path);
        }
    }
    wtns_paths.sort();

    if wtns_paths.is_empty() {
        return Err(format!(
            "no .wtns files found in steps dir {}",
            steps.display()
        )
        .into());
    }
    eprintln!(
        "Folding {} step witnesses from {}",
        wtns_paths.len(),
        steps.display()
    );

    // ------------------------------------------------------------------
    // Transcript: acc = BLAKE2b512(prefix || initial_state)
    //             acc = BLAKE2b512(acc || state_out_bytes || proof_bytes)
    // ------------------------------------------------------------------
    let mut steps_out: Vec<StepProof> = Vec::new();
    let mut prev_out: Option<Vec<String>> = None;
    let mut initial_state: Vec<String> = Vec::new();
    let mut acc_hash: Vec<u8> = {
        let mut h = Blake2b512::new();
        h.update(TRANSCRIPT_PREFIX);
        h.finalize().to_vec()
    };

    for (i, p) in wtns_paths.iter().enumerate() {
        circuit
            .load_witness(
                p.to_str()
                    .ok_or_else(|| format!("step witness path is not valid UTF-8: {p:?}"))?,
            )
            .map_err(|e| format!("failed to load witness {}: {e}", p.display()))?;
        let w = &circuit.witness;

        let out_fr = &w[1..1 + n_pub_out];
        let in_fr = &w[1 + n_pub_out..1 + n_pub_out + n_pub_in];

        let state_in: Vec<String> = in_fr.iter().map(fr_to_string).collect();
        let state_out: Vec<String> = out_fr.iter().map(fr_to_string).collect();

        // Chain check: this step's state in must equal the previous state out.
        if let Some(prev) = &prev_out {
            if state_in != *prev {
                return Err(format!(
                    "step {i} ({}): state_in does not chain to previous state_out. \
                     The step witnesses were not generated from a consistent state chain.",
                    p.display()
                )
                .into());
            }
        } else {
            initial_state = state_in.clone();
            acc_hash = transcript_step(&acc_hash, &frs_bytes(in_fr), &[]);
        }

        let (proof, public) = prover.prove_with_full_pk_sparse(
            &engine,
            &full_pk,
            n_constraints,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            w,
        );

        acc_hash = transcript_step(&acc_hash, &frs_bytes(out_fr), &proof_bytes(&proof, &public));

        let transcript = hex::encode(&acc_hash);
        steps_out.push(StepProof {
            idx: i,
            state_in,
            state_out: state_out.clone(),
            proof_a: g1_hex(&proof.a),
            proof_b: g2_hex(&proof.b),
            proof_c: g1_hex(&proof.c),
            public_v: g1_hex(&public.v),
            transcript,
        });

        prev_out = Some(state_out);
        eprintln!(
            "  step {i:>3}: {:6} gates → proof A/B/C + transcript {}",
            n_constraints,
            &steps_out.last().unwrap().transcript[..16]
        );
    }

    let transcript_final = hex::encode(&acc_hash);
    Ok(IvcBundle {
        circuit: circuit_path_str,
        n_pub_out: circuit.n_pub_out,
        n_pub_in: circuit.n_pub_in,
        initial_state,
        steps: steps_out,
        transcript_final,
    })
}

/// `fold --nifs` — fold step witnesses into a single Relaxed-R1CS instance.
///
/// Loads the step circuit and a directory of witness files, derives the
/// transparent Pedersen parameters, and folds every step instance into one
/// running accumulator via the NIFS.  Folding is linear-time and needs no
/// proving key.  Returns the O(1) [`NifsBundle`] (final instance + transcript)
/// plus the private final instance/witness for the compression proof.
pub fn run_fold_nifs(circuit: &Path, steps: &Path) -> Result<NifsFoldOutput, Box<dyn Error>> {
    fold_nifs(circuit, steps)
}

/// Core folding routine shared by [`run_fold_nifs`] and [`run_compress`]
/// (which re-folds deterministically to recover the private final witness).
fn fold_nifs(circuit: &Path, steps: &Path) -> Result<NifsFoldOutput, Box<dyn Error>> {
    let circuit_path_str = circuit.to_string_lossy().into_owned();
    let mut circuit = load_circuit(circuit)?;
    check_step_circuit(&circuit)?;

    let n_pub_out = circuit.n_pub_out as usize;
    let n_pub_in = circuit.n_pub_in as usize;
    let n_wires = circuit.n_wires as usize;
    let n_constraints = circuit.n_constraints as usize;

    let params = nifs::PedersenParams::from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints);
    let zero_e = vec![Fr::zero(); n_constraints];

    let mut wtns_paths: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(steps)
        .map_err(|e| format!("failed to read steps dir {}: {e}", steps.display()))?
    {
        let entry = entry.map_err(|e| format!("failed to read steps dir entry: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("wtns") {
            wtns_paths.push(path);
        }
    }
    wtns_paths.sort();

    if wtns_paths.is_empty() {
        return Err(format!(
            "no .wtns files found in steps dir {}",
            steps.display()
        )
        .into());
    }
    eprintln!(
        "Folding {} step witnesses (NIFS) from {}",
        wtns_paths.len(),
        steps.display()
    );

    let mut acc_hash: Option<Vec<u8>> = None;
    let mut prev_out: Option<Vec<String>> = None;
    let mut initial_state: Vec<String> = Vec::new();
    let mut acc_u: Option<nifs::RelaxedR1csInstance> = None;
    let mut acc_w: Option<nifs::RelaxedR1csWitness> = None;

    for (i, p) in wtns_paths.iter().enumerate() {
        circuit
            .load_witness(
                p.to_str()
                    .ok_or_else(|| format!("step witness path is not valid UTF-8: {p:?}"))?,
            )
            .map_err(|e| format!("failed to load witness {}: {e}", p.display()))?;
        let w = &circuit.witness;

        let out_fr = &w[1..1 + n_pub_out];
        let in_fr = &w[1 + n_pub_out..1 + n_pub_out + n_pub_in];
        let state_in: Vec<String> = in_fr.iter().map(fr_to_string).collect();
        let state_out: Vec<String> = out_fr.iter().map(fr_to_string).collect();

        if let Some(prev) = &prev_out {
            if state_in != *prev {
                return Err(format!(
                    "step {i} ({}): state_in does not chain to previous state_out. \
                     The step witnesses were not generated from a consistent state chain.",
                    p.display()
                )
                .into());
            }
        } else {
            initial_state = state_in.clone();
            acc_hash = Some(transcript_nifs_init(in_fr));
        }

        let x: Vec<Fr> = w[1..1 + n_pub_out + n_pub_in].to_vec();
        let step_u = nifs::RelaxedR1csInstance {
            x,
            u: Fr::from(1u64),
            w_commit: nifs::commit(&params.basis_w, w),
            e_commit: G1Affine::zero(),
        };
        let step_w = nifs::RelaxedR1csWitness {
            w: w.to_vec(),
            e: zero_e.clone(),
        };

        match acc_u.take() {
            None => {
                acc_u = Some(step_u);
                acc_w = Some(step_w);
            }
            Some(u_acc) => {
                let w_acc = acc_w.take().expect("running witness must exist");
                let acc = acc_hash.as_ref().expect("transcript initialized");
                let challenge = nifs::fold_challenge(acc, &u_acc, &step_u);
                let (u3, w3) = nifs::fold(
                    &params,
                    &circuit.l,
                    &circuit.r,
                    &circuit.o,
                    &u_acc,
                    &w_acc,
                    &step_u,
                    &step_w,
                    challenge,
                );
                acc_u = Some(u3);
                acc_w = Some(w3);
            }
        }

        acc_hash = Some(transcript_nifs_step(
            acc_hash.as_ref().expect("transcript initialized"),
            acc_u.as_ref().expect("running instance"),
        ));
        prev_out = Some(state_out);
        eprintln!(
            "  step {i:>3}: folded (u = {})",
            fr_to_string(&acc_u.as_ref().expect("running instance").u)
        );
    }

    let final_u = acc_u.ok_or("no step witnesses folded")?;
    let final_w = acc_w.expect("final witness present");
    let transcript_final = hex::encode(acc_hash.as_ref().expect("transcript finalized"));

    let bundle = NifsBundle {
        circuit: circuit_path_str,
        n_wires: circuit.n_wires,
        n_constraints: circuit.n_constraints,
        n_pub_out: circuit.n_pub_out,
        n_pub_in: circuit.n_pub_in,
        initial_state,
        n_steps: wtns_paths.len(),
        final_instance: NifsFinalInstance {
            x: final_u.x.iter().map(fr_to_string).collect(),
            u: fr_to_string(&final_u.u),
            w_commit: g1_hex(&final_u.w_commit),
            e_commit: g1_hex(&final_u.e_commit),
        },
        transcript_final,
    };

    Ok(NifsFoldOutput {
        bundle,
        final_instance: final_u,
        final_witness: final_w,
    })
}

/// `compress` — Groth16-compress the final NIFS instance (Implementation 9,
/// work item 2).
///
/// Re-folds the step witnesses deterministically to recover the private final
/// instance `(u, W, E)`, builds the [`compression::CompressionCircuit`]
/// (relaxed-equation check, `2·n_constraints` constraints), and proves it with
/// the compression `FullProvingKey` (from `trusted-setup ceremony-dev
/// --sparse` on the `.r1cs` emitted by `fold --nifs --compression-r1cs`).
/// Writes a [`CompressionProof`] JSON to `out`.
///
/// Proof size is O(1) — a single Groth16 proof — regardless of the step count.
pub fn run_compress(
    circuit: &Path,
    steps: &Path,
    proving_key: &Path,
    out: &Path,
) -> Result<CompressOutput, Box<dyn Error>> {
    let c = load_circuit(circuit)?;
    check_step_circuit(&c)?;

    let folded = fold_nifs(circuit, steps)?;

    let cc = compression::CompressionCircuit::new(&c.l, &c.r, &c.o, c.n_wires as usize);
    let v = cc.witness(
        &folded.final_witness.w,
        folded.final_instance.u,
        &folded.final_witness.e,
    );
    if !cc.is_satisfied(&v) {
        return Err("internal error: compression witness does not satisfy the circuit".into());
    }

    let full_pk = load_full_pk(proving_key).map_err(|e| format!("failed to load proving key: {e}"))?;
    if full_pk.vk.n_public != cc.n_public || full_pk.a_query.len() != cc.n_wires_total {
        return Err(
            "proving key does not match the compression circuit (wrong ceremony output?)".into(),
        );
    }

    let engine = FftQapEngine::new();
    let prover = PippengerProver::new();
    let (proof, public) =
        prover.prove_with_full_pk_sparse(&engine, &full_pk, cc.l.len(), &cc.l, &cc.r, &cc.o, &v);

    let cproof = CompressionProof {
        circuit: circuit.to_string_lossy().into_owned(),
        n_wires: c.n_wires,
        n_constraints: c.n_constraints,
        n_pub_out: c.n_pub_out,
        n_pub_in: c.n_pub_in,
        final_instance: folded.bundle.final_instance.clone(),
        proof_a: g1_hex(&proof.a),
        proof_b: g2_hex(&proof.b),
        proof_c: g1_hex(&proof.c),
        public_v: g1_hex(&public.v),
        public_inputs: cc.public_inputs(&v).iter().map(fr_to_string).collect(),
    };

    let json = serde_json::to_string_pretty(&cproof)
        .map_err(|e| format!("failed to serialize compression proof: {e}"))?;
    fs::write(out, &json)
        .map_err(|e| format!("failed to write compression proof to {}: {e}", out.display()))?;
    eprintln!(
        "Compression proof written to {} ({} bytes, u = {})",
        out.display(),
        json.len(),
        fr_to_string(&folded.final_instance.u)
    );
    Ok(CompressOutput {
        bytes: json.len(),
        bundle: folded.bundle,
    })
}

/// Output of [`run_compress`].
#[derive(Debug, Clone)]
pub struct CompressOutput {
    pub bytes: usize,
    pub bundle: NifsBundle,
}

/// Verify a compression proof against a NIFS bundle (in-memory).
///
/// Checks, in order:
///   1. the proof's public inputs match the bundle's final instance
///      (`x`, `u`, and the Pedersen commitments `com(Z)`, `com(E)` recomputed
///      natively with the transparent basis);
///   2. the Groth16 pairing check `e(A,B) = e(α,β)·e(C,δ)·e(V,γ)`, where `V`
///      is recomputed from the public inputs and the VK's `ic` points.
///
/// This is the O(1) end of Implementation 9: constant-size proof and
/// verification regardless of the step count.
pub fn verify_compression(
    bundle: &NifsBundle,
    proof: &CompressionProof,
    vk: &VerifyingKey,
) -> Result<VerifyOutput, Box<dyn Error>> {
    if proof.final_instance != bundle.final_instance {
        return Err("compression proof was not created for this NIFS bundle".into());
    }
    if proof.n_wires != bundle.n_wires
        || proof.n_constraints != bundle.n_constraints
        || proof.n_pub_out != bundle.n_pub_out
        || proof.n_pub_in != bundle.n_pub_in
    {
        return Err("compression proof does not match the NIFS bundle parameters".into());
    }

    let n_wires = bundle.n_wires as usize;
    let n_constraints = bundle.n_constraints as usize;
    let n_pub_out = bundle.n_pub_out as usize;
    let n_pub_in = bundle.n_pub_in as usize;
    let n_public = 1 + n_wires + 1 + n_constraints;

    let pub_frs = frs_from_strings(&proof.public_inputs)?;
    if pub_frs.len() != n_public {
        return Err(format!(
            "compression proof public-input vector has {} entries, expected {n_public} \
             (1 + {n_wires} step wires + u + {n_constraints} error entries)",
            pub_frs.len()
        )
        .into());
    }

    // [1, Z(1..1+n_wires), u, E(2+n_wires..2+n_wires+n_constraints)]
    let z = &pub_frs[1..1 + n_wires];
    let u = pub_frs[1 + n_wires];
    let e = &pub_frs[2 + n_wires..2 + n_wires + n_constraints];

    // 1a. state chain
    let x = z[1..1 + n_pub_out + n_pub_in].to_vec();
    if x != frs_from_strings(&bundle.final_instance.x)? {
        return Err("compression proof public x does not match the NIFS bundle".into());
    }
    if u != bundle
        .final_instance
        .u
        .parse::<Fr>()
        .map_err(|e| format!("bundle final_instance.u is not a valid field element: {e:?}"))?
    {
        return Err("compression proof slack u does not match the NIFS bundle".into());
    }

    // 1b. commitments: recompute com(Z), com(E) with the transparent basis.
    let params = nifs::PedersenParams::from_seed(NIFS_PARAMS_SEED, n_wires, n_constraints);
    if nifs::commit(&params.basis_w, z) != deserialize_g1(&bundle.final_instance.w_commit)? {
        return Err("W commitment recomputation does not match the NIFS bundle".into());
    }
    if nifs::commit(&params.basis_e, e) != deserialize_g1(&bundle.final_instance.e_commit)? {
        return Err("E commitment recomputation does not match the NIFS bundle".into());
    }

    // 2. Groth16 pairing check with V recomputed from the public inputs.
    // The VK's `ic` holds one point per variable; only the first `n_public`
    // (the constant + public wires) contribute to `V`.
    let proof = deserialize_proof(&proof.proof_a, &proof.proof_b, &proof.proof_c)?;
    if vk.ic.len() < n_public {
        return Err("compression verifying key has too few ic points".into());
    }
    let v = G1Affine::from(
        G1Projective::msm(&vk.ic[..n_public], &pub_frs)
            .map_err(|e| format!("MSM for V failed: {e:?}"))?,
    );
    if !verify_with_vk(&proof, &PublicInput { v }, vk) {
        return Err("compression proof Groth16 pairing check failed".into());
    }

    Ok(VerifyOutput {
        steps: bundle.n_steps,
        transcript_final: bundle.transcript_final.clone(),
    })
}

/// Emit the compression circuit `.r1cs` for a step circuit (Implementation 9,
/// work item 2).
///
/// The compression circuit reuses the step circuit's sparse A/B/C matrices and
/// checks the relaxed equation `(AZ)∘(BZ) = u·(CZ) + E` row by row — the exact
/// invariant [`nifs::fold`] guarantees the accumulated instance satisfies.  The
/// resulting `.r1cs` is Circom-compatible and can be fed to
/// `trusted-setup ceremony-dev --sparse` to derive the compression proving /
/// verifying keys.  Returns the number of bytes written.
pub fn emit_compression_r1cs(circuit: &Path, out: &Path) -> Result<usize, Box<dyn Error>> {
    let c = load_circuit(circuit)?;
    check_step_circuit(&c)?;

    let cc = compression::CompressionCircuit::new(&c.l, &c.r, &c.o, c.n_wires as usize);
    let bytes = cc.to_r1cs_bytes();
    fs::write(out, &bytes)
        .map_err(|e| format!("failed to write compression .r1cs to {}: {e}", out.display()))?;
    eprintln!(
        "Compression circuit (from {} step constraints): {} wires, {} constraints, {} public",
        c.n_constraints,
        cc.n_wires_total,
        cc.l.len(),
        cc.n_public
    );
    eprintln!(
        "Compression circuit .r1cs ({} bytes) written to {}",
        bytes.len(),
        out.display()
    );
    Ok(bytes.len())
}

/// `verify` — verify a folded IVC bundle.
///
/// Loads an IVC bundle (`.ivc.json`) and the step verifying key, then
/// checks:
///   1. Each step's Groth16 pairing verification passes
///   2. The state chain is consistent (step[i].state_out == step[i+1].state_in)
///   3. The BLAKE2b transcript hashes match at every step
///
/// For a NIFS bundle (Implementation 9) the step verifying key is ignored:
/// verification requires the compression proof (`compression_proof`) and the
/// compression verifying key (`compression_vk`) and runs [`verify_compression`].
pub fn run_verify(
    ivc: &Path,
    verifying_key: &Path,
    compression_proof: Option<&Path>,
    compression_vk: Option<&Path>,
) -> Result<VerifyOutput, Box<dyn Error>> {
    let bytes = fs::read(ivc)
        .map_err(|e| format!("failed to read IVC bundle {}: {e}", ivc.display()))?;
    let bundle: IvcBundle = match serde_json::from_slice(&bytes) {
        Ok(b) => b,
        Err(_) => {
            let nifs: NifsBundle = serde_json::from_slice(&bytes).map_err(|_| {
                "failed to parse IVC bundle: not a step-chain bundle and not a NIFS bundle"
            })?;
            return verify_nifs_bundle(&nifs, compression_proof, compression_vk);
        }
    };

    let vk = load_vk(verifying_key).map_err(|e| format!("failed to load verifying key: {e}"))?;

    if bundle.steps.is_empty() {
        return Err("IVC bundle contains no steps".into());
    }
    if bundle.initial_state != bundle.steps[0].state_in {
        return Err("IVC bundle initial_state does not match step 0 state_in".into());
    }

    let mut acc_hash: Vec<u8> = {
        let mut h = Blake2b512::new();
        h.update(TRANSCRIPT_PREFIX);
        h.finalize().to_vec()
    };
    acc_hash = transcript_step(&acc_hash, &frs_bytes(&frs_from_strings(&bundle.initial_state)?), &[]);

    let mut prev: Option<&Vec<String>> = None;
    for step in &bundle.steps {
        // 1. Chain check
        if let Some(prev) = prev {
            if step.state_in != *prev {
                return Err(format!(
                    "step {}: state_in does not chain to previous state_out",
                    step.idx
                )
                .into());
            }
        }

        // 2. Groth16 pairing check for this step's proof
        let proof = deserialize_proof(&step.proof_a, &step.proof_b, &step.proof_c)?;
        let public = deserialize_public(&step.public_v)?;
        if !verify_with_vk(&proof, &public, &vk) {
            return Err(format!("step {}: Groth16 pairing check failed", step.idx).into());
        }

        // 3. Transcript check
        acc_hash = transcript_step(
            &acc_hash,
            &frs_bytes(&frs_from_strings(&step.state_out)?),
            &proof_bytes(&proof, &public),
        );
        if hex::encode(&acc_hash) != step.transcript {
            return Err(format!(
                "step {}: transcript mismatch (IVC chain was tampered with)",
                step.idx
            )
            .into());
        }

        prev = Some(&step.state_out);
    }

    if hex::encode(&acc_hash) != bundle.transcript_final {
        return Err("final transcript mismatch".into());
    }

    Ok(VerifyOutput {
        steps: bundle.steps.len(),
        transcript_final: bundle.transcript_final,
    })
}

/// Load the compression proof + VK for a NIFS bundle and run
/// [`verify_compression`].
fn verify_nifs_bundle(
    nifs: &NifsBundle,
    compression_proof: Option<&Path>,
    compression_vk: Option<&Path>,
) -> Result<VerifyOutput, Box<dyn Error>> {
    let proof_path = compression_proof.ok_or(
        "this is a NIFS bundle (Implementation 9) — verifying it requires the compression \
         proof (--compression-proof) and the compression verifying key (--compression-vk)",
    )?;
    let vk_path = compression_vk.ok_or(
        "this is a NIFS bundle (Implementation 9) — verifying it requires the compression \
         proof (--compression-proof) and the compression verifying key (--compression-vk)",
    )?;

    let proof_bytes = fs::read(proof_path)
        .map_err(|e| format!("failed to read compression proof {}: {e}", proof_path.display()))?;
    let cproof: CompressionProof = serde_json::from_slice(&proof_bytes)
        .map_err(|e| format!("failed to parse compression proof: {e}"))?;
    let vk = load_vk(vk_path).map_err(|e| format!("failed to load compression verifying key: {e}"))?;

    verify_compression(nifs, &cproof, &vk)
}

/// Serialize a field element to its compressed bytes.
fn fr_bytes(f: &Fr) -> Vec<u8> {
    let mut buf = Vec::new();
    f.serialize_compressed(&mut buf).expect("Fr serialize");
    buf
}

/// Serialize a slice of field elements to concatenated compressed bytes.
fn frs_bytes(frs: &[Fr]) -> Vec<u8> {
    frs.iter().flat_map(fr_bytes).collect()
}

/// Serialize a proof + public input to compressed bytes.
fn proof_bytes(proof: &Proof, public: &PublicInput) -> Vec<u8> {
    let mut buf = Vec::new();
    proof
        .a
        .serialize_compressed(&mut buf)
        .expect("proof.a serialize");
    proof
        .b
        .serialize_compressed(&mut buf)
        .expect("proof.b serialize");
    proof
        .c
        .serialize_compressed(&mut buf)
        .expect("proof.c serialize");
    public
        .v
        .serialize_compressed(&mut buf)
        .expect("public.v serialize");
    buf
}

/// Hex of a compressed G1 point.
fn g1_hex(p: &G1Affine) -> String {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).expect("G1 serialize");
    hex::encode(buf)
}

/// Hex of a compressed G2 point.
fn g2_hex(p: &G2Affine) -> String {
    let mut buf = Vec::new();
    p.serialize_compressed(&mut buf).expect("G2 serialize");
    hex::encode(buf)
}

/// Next transcript digest: `H(acc || state_out || proof)`.
pub fn transcript_step(acc_hash: &[u8], out_bytes: &[u8], proof_bytes: &[u8]) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(acc_hash);
    h.update(out_bytes);
    h.update(proof_bytes);
    h.finalize().to_vec()
}

/// Initialize the NIFS transcript: `H(NIFS_TRANSCRIPT_PREFIX ‖ initial_state)`.
fn transcript_nifs_init(initial_state: &[Fr]) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(frs_bytes(initial_state));
    h.finalize().to_vec()
}

/// Extend the NIFS transcript with the running instance after a fold:
/// `H(acc ‖ instance_bytes)`.  The folding challenge (`nifs::fold_challenge`)
/// is domain-separated via `FOLD_PREFIX`.
fn transcript_nifs_step(acc_hash: &[u8], u: &nifs::RelaxedR1csInstance) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(NIFS_TRANSCRIPT_PREFIX);
    h.update(acc_hash);
    h.update(nifs::instance_to_bytes(u).expect("serialize instance"));
    h.finalize().to_vec()
}

fn deserialize_g1(hex: &str) -> Result<G1Affine, Box<dyn Error>> {
    let bytes = hex::decode(hex).map_err(|e| format!("invalid G1 hex: {e}"))?;
    G1Affine::deserialize_compressed(&bytes[..])
        .map_err(|e| format!("failed to deserialize G1 point: {e:?}").into())
}

fn deserialize_g2(hex: &str) -> Result<G2Affine, Box<dyn Error>> {
    let bytes = hex::decode(hex).map_err(|e| format!("invalid G2 hex: {e}"))?;
    G2Affine::deserialize_compressed(&bytes[..])
        .map_err(|e| format!("failed to deserialize G2 point: {e:?}").into())
}

fn deserialize_proof(a: &str, b: &str, c: &str) -> Result<Proof, Box<dyn Error>> {
    Ok(Proof {
        a: deserialize_g1(a)?,
        b: deserialize_g2(b)?,
        c: deserialize_g1(c)?,
    })
}

fn deserialize_public(v: &str) -> Result<PublicInput, Box<dyn Error>> {
    Ok(PublicInput {
        v: deserialize_g1(v)?,
    })
}

/// Canonical decimal string for a field element.
///
/// arkworks' `Display` for BLS12-381 `Fr` emits an empty string for the
/// zero element, so serialize via the canonical bigint instead.
pub fn fr_to_string(f: &Fr) -> String {
    f.into_bigint().to_string()
}

/// Parse decimal field-element strings back into `Fr`.
pub fn frs_from_strings(strs: &[String]) -> Result<Vec<Fr>, Box<dyn Error>> {
    strs.iter()
        .map(|s| {
            s.parse::<Fr>()
                .map_err(|e| format!("invalid field element '{s}': {e:?}").into())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use groth16_prover::circom_adapter::{r1cs_to_bytes_sparse, wtns_to_bytes};

    /// One-constraint step circuit `out = in · x` (wires `[1, out, in, x]`).
    fn step_r1cs_bytes() -> Vec<u8> {
        r1cs_to_bytes_sparse(
            4,
            1,
            1,
            1,
            &[vec![(2u32, Fr::from(1u64))]],
            &[vec![(3u32, Fr::from(1u64))]],
            &[vec![(1u32, Fr::from(1u64))]],
        )
    }

    fn write_step_wtns(dir: &Path, idx: usize, st_in: u64, x: u64) -> u64 {
        let st_out = st_in * x;
        fs::write(
            dir.join(format!("step_{idx:04}.wtns")),
            wtns_to_bytes(&[
                Fr::from(1u64),
                Fr::from(st_out),
                Fr::from(st_in),
                Fr::from(x),
            ]),
        )
        .unwrap();
        st_out
    }

    /// Fold 3 steps, run a dev ceremony on the compression circuit, compress,
    /// and verify the O(1) compression proof.
    #[test]
    fn nifs_compression_end_to_end() {
        let tmp = tempfile::tempdir().unwrap();
        let r1cs_path = tmp.path().join("step.r1cs");
        let steps_dir = tmp.path().join("steps");
        let pk_path = tmp.path().join("compression.pk");
        let proof_path = tmp.path().join("compression.proof.json");
        fs::write(&r1cs_path, step_r1cs_bytes()).unwrap();
        fs::create_dir(&steps_dir).unwrap();

        let mut state = 2u64;
        for (i, x) in [3u64, 5, 7].iter().enumerate() {
            state = write_step_wtns(&steps_dir, i, state, *x);
        }
        assert_eq!(state, 210);

        // 1. fold -> bundle + private final instance/witness
        let fold_out = run_fold_nifs(&r1cs_path, &steps_dir).unwrap();
        assert_eq!(fold_out.bundle.n_steps, 3);
        assert_ne!(fold_out.final_instance.u, Fr::from(1u64));

        // 2. ceremony on the compression circuit (dev path, group elements only)
        let c = load_circuit(&r1cs_path).unwrap();
        let cc = compression::CompressionCircuit::new(&c.l, &c.r, &c.o, c.n_wires as usize);
        let mut rng = rand::thread_rng();
        let engine = FftQapEngine::new();
        let tw = ToxicWaste::random(&mut rng);
        let (full_pk, vk) = single_party_ceremony_full_from_tw_sparse(
            &engine,
            cc.l.len(),
            cc.n_wires_total,
            cc.n_public,
            &cc.l,
            &cc.r,
            &cc.o,
            tw,
            false,
        );
        let mut pk_bytes = Vec::new();
        full_pk.serialize_uncompressed(&mut pk_bytes).unwrap();
        fs::write(&pk_path, &pk_bytes).unwrap();

        // 3. compress -> one Groth16 proof, O(1) in the step count
        let compress_out = run_compress(&r1cs_path, &steps_dir, &pk_path, &proof_path).unwrap();
        assert_eq!(compress_out.bundle.final_instance, fold_out.bundle.final_instance);
        let proof: CompressionProof =
            serde_json::from_slice(&fs::read(&proof_path).unwrap()).unwrap();
        assert_eq!(proof.public_inputs.len(), cc.n_public);

        // 4. verify: pairing + recomputed commitments + state/u
        let vout = verify_compression(&compress_out.bundle, &proof, &vk).unwrap();
        assert_eq!(vout.steps, 3);

        // 5. tamper resistance: a flipped public input fails the commitment check
        let mut bad = proof.clone();
        bad.public_inputs[1 + c.n_wires as usize] = fr_to_string(&(fold_out.final_instance.u + Fr::from(1u64)));
        assert!(
            verify_compression(&compress_out.bundle, &bad, &vk).is_err(),
            "tampered u must fail verification"
        );

        // 6. tamper resistance: a corrupted proof point fails the pairing check
        let mut bad2 = proof.clone();
        bad2.proof_a = g1_hex(&G1Affine::generator());
        assert!(
            verify_compression(&compress_out.bundle, &bad2, &vk).is_err(),
            "tampered proof must fail the pairing check"
        );
    }

    #[test]
    fn fr_to_string_roundtrip() {
        let f = Fr::from(123456789u64);
        let s = fr_to_string(&f);
        let back = frs_from_strings(&[s]).unwrap();
        assert_eq!(back, vec![f]);
    }
}
