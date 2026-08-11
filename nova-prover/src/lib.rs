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

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ec::AffineRepr;
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
/// `nova verify` subcommand.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NifsBundle {
    pub circuit: String,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub initial_state: Vec<String>,
    pub n_steps: usize,
    pub final_instance: NifsFinalInstance,
    pub transcript_final: String,
}

/// Output of [`run_fold_nifs`]: the public bundle plus the private final
/// witness (consumed by the compression proof).
#[derive(Debug, Clone)]
pub struct NifsFoldOutput {
    pub bundle: NifsBundle,
    pub final_witness: nifs::RelaxedR1csWitness,
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
/// plus the private final witness for the compression proof.
pub fn run_fold_nifs(circuit: &Path, steps: &Path) -> Result<NifsFoldOutput, Box<dyn Error>> {
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
        final_witness: final_w,
    })
}

/// `verify` — verify a folded IVC bundle.
///
/// Loads an IVC bundle (`.ivc.json`) and the step verifying key, then
/// checks:
///   1. Each step's Groth16 pairing verification passes
///   2. The state chain is consistent (step[i].state_out == step[i+1].state_in)
///   3. The BLAKE2b transcript hashes match at every step
pub fn run_verify(ivc: &Path, verifying_key: &Path) -> Result<VerifyOutput, Box<dyn Error>> {
    let bytes = fs::read(ivc)
        .map_err(|e| format!("failed to read IVC bundle {}: {e}", ivc.display()))?;
    let bundle: IvcBundle =
        serde_json::from_slice(&bytes).map_err(|e| format!("failed to parse IVC bundle: {e}"))?;

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

    #[test]
    fn fr_to_string_roundtrip() {
        let f = Fr::from(123456789u64);
        let s = fr_to_string(&f);
        let back = frs_from_strings(&[s]).unwrap();
        assert_eq!(back, vec![f]);
    }
}
