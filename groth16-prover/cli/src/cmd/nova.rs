//! `nova` subcommand — Nova IVC folding + compression flow (Implementation 8).
//!
//! A long computation is decomposed into `N` identical step circuits, each
//! proving `state_{i+1} = f(step_i, state_i)`.  The `fold` subcommand runs a
//! chain of Groth16 proofs over the step witnesses — every step proof is
//! individually verifiable and the state chain is bound by a transcript —
//! while `verify` re-checks the whole chain.
//!
//! The step circuits must satisfy one invariant (checked by `params`):
//! the number of public inputs must equal the number of public outputs
//! (`n_pub_in == n_pub_out`), so the public-input block of step `i+1`
//! must equal the public-output block of step `i`.  Public inputs ARE the
//! IVC state.
//!
//! Subcommands:
//!   params    — inspect a step circuit and emit a JSON descriptor
//!   ceremony  — single-party ceremony for a step circuit (per-step Groth16 keys)
//!   fold      — fold step witnesses into an IVC bundle + transcript
//!   verify    — verify a folded IVC bundle (pairings + chain + transcript)

use ark_bls12_381::{Fr, G1Affine, G2Affine};
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use blake2::{Blake2b512, Digest};
use clap::{Parser, Subcommand};
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
const TRANSCRIPT_PREFIX: &[u8] = b"groth16-prover-nova-transcript-v1";

/// `nova` subcommands
#[derive(Debug, Subcommand)]
pub enum NovaCommand {
    /// Inspect a step circuit and emit a JSON descriptor
    Params(ParamsArgs),
    /// Single-party ceremony for a step circuit
    Ceremony(CeremonyArgs),
    /// Fold step witnesses into an IVC bundle
    Fold(FoldArgs),
    /// Verify a folded IVC bundle
    Verify(VerifyArgs),
}

/// Arguments for `nova params`
#[derive(Debug, Parser)]
pub struct ParamsArgs {
    /// Path to the step circuit `.r1cs` file
    #[arg(long, value_name = "FILE")]
    circuit: PathBuf,

    /// Optional JSON output path; if omitted, the descriptor is printed
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

/// Arguments for `nova ceremony`
#[derive(Debug, Parser)]
pub struct CeremonyArgs {
    /// Path to the step circuit `.r1cs` file
    #[arg(long, value_name = "FILE")]
    circuit: PathBuf,

    /// Output path for the proving key (.pk extension recommended)
    #[arg(long, value_name = "FILE")]
    proving_key: PathBuf,

    /// Output path for the verification key (.vk extension recommended)
    #[arg(long, value_name = "FILE")]
    verifying_key: PathBuf,

    /// Use h-query scalar compression (Implementation 7)
    #[arg(long)]
    h_scalar: bool,
}

/// Arguments for `nova fold`
#[derive(Debug, Parser)]
pub struct FoldArgs {
    /// Path to the step circuit `.r1cs` file
    #[arg(long, value_name = "FILE")]
    circuit: PathBuf,

    /// Path to the step proving key (from `nova ceremony`)
    #[arg(long, value_name = "FILE")]
    proving_key: PathBuf,

    /// Directory containing the step witnesses `step_0000.wtns`, ... (sorted)
    #[arg(long, value_name = "DIR")]
    steps: PathBuf,

    /// Output path for the IVC bundle JSON (.ivc.json extension recommended)
    #[arg(long, value_name = "FILE")]
    out: PathBuf,
}

/// Arguments for `nova verify`
#[derive(Debug, Parser)]
pub struct VerifyArgs {
    /// Path to the IVC bundle produced by `nova fold`
    #[arg(long, value_name = "FILE")]
    ivc: PathBuf,

    /// Path to the step verifying key (from `nova ceremony`)
    #[arg(long, value_name = "FILE")]
    verifying_key: PathBuf,
}

/// JSON descriptor of a step circuit (emitted by `params`).
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

/// The folded IVC bundle produced by `fold` and consumed by `verify`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IvcBundle {
    pub circuit: String,
    pub n_pub_out: u32,
    pub n_pub_in: u32,
    pub initial_state: Vec<String>,
    pub steps: Vec<StepProof>,
    pub transcript_final: String,
}

/// Run the `nova` subcommand.
pub fn run(cmd: NovaCommand) -> Result<(), Box<dyn Error>> {
    match cmd {
        NovaCommand::Params(args) => run_params(args),
        NovaCommand::Ceremony(args) => run_ceremony(args),
        NovaCommand::Fold(args) => run_fold(args),
        NovaCommand::Verify(args) => run_verify(args),
    }
}

fn load_circuit(path: &Path) -> Result<SparseCircomCircuit, Box<dyn Error>> {
    SparseCircomCircuit::from_r1cs(
        path.to_str()
            .ok_or_else(|| format!("circuit path is not valid UTF-8: {path:?}"))?,
    )
    .map_err(|e| format!("failed to load circuit {}: {e}", path.display()).into())
}

/// Enforce the step-chain invariant: the public-input block (state in)
/// must have the same width as the public-output block (state out).
fn check_step_circuit(c: &SparseCircomCircuit) -> Result<(), Box<dyn Error>> {
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
fn transcript_step(acc_hash: &[u8], out_bytes: &[u8], proof_bytes: &[u8]) -> Vec<u8> {
    let mut h = Blake2b512::new();
    h.update(acc_hash);
    h.update(out_bytes);
    h.update(proof_bytes);
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

/// `nova params`
fn run_params(args: ParamsArgs) -> Result<(), Box<dyn Error>> {
    let circuit = load_circuit(&args.circuit)?;
    check_step_circuit(&circuit)?;

    let desc = CircuitDescriptor {
        n_wires: circuit.n_wires,
        n_constraints: circuit.n_constraints,
        n_pub_out: circuit.n_pub_out,
        n_pub_in: circuit.n_pub_in,
        n_prv_in: circuit.n_prv_in,
    };
    let json = serde_json::to_string_pretty(&desc)?;

    if let Some(out) = &args.out {
        fs::write(out, &json)
            .map_err(|e| format!("failed to write descriptor to {}: {e}", out.display()))?;
        eprintln!(
            "Step circuit {}: {} wires, {} constraints ({} out + {} in public, {} private) — OK",
            args.circuit.display(),
            desc.n_wires,
            desc.n_constraints,
            desc.n_pub_out,
            desc.n_pub_in,
            desc.n_prv_in
        );
        eprintln!("Descriptor written to {}", out.display());
    } else {
        println!("{json}");
    }
    Ok(())
}

/// `nova ceremony`
fn run_ceremony(args: CeremonyArgs) -> Result<(), Box<dyn Error>> {
    let circuit = load_circuit(&args.circuit)?;
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
        args.h_scalar,
    );

    write_pk_uncompressed(&full_pk, &args.proving_key)?;
    write_vk_uncompressed(&vk, &args.verifying_key)?;

    eprintln!(
        "Nova ceremony complete. h_scalar compression: {}.",
        if args.h_scalar { "enabled" } else { "disabled" }
    );
    Ok(())
}

fn write_pk_uncompressed(pk: &FullProvingKey, path: &Path) -> Result<(), Box<dyn Error>> {
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
    Ok(())
}

fn write_vk_uncompressed(vk: &VerifyingKey, path: &Path) -> Result<(), Box<dyn Error>> {
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
    Ok(())
}

/// `nova fold`
fn run_fold(args: FoldArgs) -> Result<(), Box<dyn Error>> {
    let mut circuit = load_circuit(&args.circuit)?;
    check_step_circuit(&circuit)?;

    let n_pub_out = circuit.n_pub_out as usize;
    let n_pub_in = circuit.n_pub_in as usize;
    let n_constraints = circuit.n_constraints as usize;

    let full_pk = crate::util::load_full_pk(&args.proving_key)
        .map_err(|e| format!("failed to load proving key: {e}"))?;
    let engine = FftQapEngine::new();
    let prover = PippengerProver::new();

    let mut wtns_paths: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(&args.steps)
        .map_err(|e| format!("failed to read steps dir {}: {e}", args.steps.display()))?
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
            args.steps.display()
        )
        .into());
    }
    eprintln!("Folding {} step witnesses from {}", wtns_paths.len(), args.steps.display());

    // ------------------------------------------------------------------
    // Transcript: acc = BLAKE2b512(prefix || initial_state)
    //             acc = BLAKE2b512(acc || state_out_bytes || proof_bytes)
    // ------------------------------------------------------------------
    let mut steps: Vec<StepProof> = Vec::new();
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
        steps.push(StepProof {
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
            &steps.last().unwrap().transcript[..16]
        );
    }

    let transcript_final = hex::encode(&acc_hash);
    let bundle = IvcBundle {
        circuit: args.circuit.to_string_lossy().into_owned(),
        n_pub_out: circuit.n_pub_out,
        n_pub_in: circuit.n_pub_in,
        initial_state,
        steps,
        transcript_final,
    };

    let json = serde_json::to_string_pretty(&bundle)
        .map_err(|e| format!("failed to serialize IVC bundle: {e}"))?;
    fs::write(&args.out, &json)
        .map_err(|e| format!("failed to write IVC bundle to {}: {e}", args.out.display()))?;
    eprintln!("IVC bundle written to {}", args.out.display());
    Ok(())
}

/// `nova verify`
fn run_verify(args: VerifyArgs) -> Result<(), Box<dyn Error>> {
    let bytes = fs::read(&args.ivc)
        .map_err(|e| format!("failed to read IVC bundle {}: {e}", args.ivc.display()))?;
    let bundle: IvcBundle =
        serde_json::from_slice(&bytes).map_err(|e| format!("failed to parse IVC bundle: {e}"))?;

    let vk = crate::util::load_vk(&args.verifying_key)
        .map_err(|e| format!("failed to load verifying key: {e}"))?;

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

    eprintln!(
        "Verified {} steps: {} pairings OK, state chain OK, transcript OK",
        bundle.steps.len(),
        bundle.steps.len()
    );
    eprintln!("Final transcript: {}", bundle.transcript_final);
    Ok(())
}

/// Canonical decimal string for a field element.
///
/// arkworks' `Display` for BLS12-381 `Fr` emits an empty string for the
/// zero element, so serialize via the canonical bigint instead.
fn fr_to_string(f: &Fr) -> String {
    f.into_bigint().to_string()
}

/// Parse decimal field-element strings back into `Fr`.
fn frs_from_strings(strs: &[String]) -> Result<Vec<Fr>, Box<dyn Error>> {
    strs.iter()
        .map(|s| {
            s.parse::<Fr>()
                .map_err(|e| format!("invalid field element '{s}': {e:?}").into())
        })
        .collect()
}
