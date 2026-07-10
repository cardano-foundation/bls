use ark_bls12_381::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::{Parser, ValueEnum};
use groth16_prover::ceremony::ProvingKey;
use groth16_prover::circom_adapter::CircomCircuit;
use groth16_prover::engine::{DenseQapEngine, FftQapEngine};
use groth16_prover::prover::{NaiveProver, PippengerProver, Prover};
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// QAP engine selection
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum EngineArg {
    /// Classical dense Lagrange interpolation (pedagogical, O(n²))
    Dense,
    /// FFT over roots of unity (production, O(N log N))
    Fft,
}

/// Prover MSM strategy selection
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ProverArg {
    /// Scalar-by-scalar accumulation (pedagogical)
    Naive,
    /// Batched multi-scalar multiplication via Pippenger (production)
    Pippenger,
}

/// Arguments for the `prove` subcommand
#[derive(Debug, Parser)]
pub struct Args {
    /// Path to the `.r1cs` circuit file
    #[arg(long, value_name = "FILE")]
    circuit: PathBuf,

    /// Path to the `.wtns` witness file
    #[arg(long, value_name = "FILE")]
    witness: PathBuf,

    /// Path to the proving key file (from the ceremony step).
    /// If omitted, the deterministic test values are used (dev only).
    #[arg(long, value_name = "FILE")]
    proving_key: Option<PathBuf>,

    /// QAP engine: dense (classical) or fft (roots of unity)
    #[arg(long, value_enum, default_value = "fft")]
    engine: EngineArg,

    /// Prover strategy: naive (scalar-by-scalar) or pippenger (batched MSM)
    #[arg(long, value_enum, default_value = "pippenger")]
    prover: ProverArg,

    /// Optional output file for the proof (raw binary).
    /// If omitted, the proof is printed as hex to stdout.
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

/// Run the prove command
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    // ------------------------------------------------------------------
    // 1. Load circuit and witness
    // ------------------------------------------------------------------
    let mut circuit = CircomCircuit::from_r1cs(
        args.circuit
            .to_str()
            .ok_or("circuit path is not valid UTF-8")?,
    )
    .map_err(|e| format!("failed to load circuit: {e}"))?;

    circuit
        .load_witness(
            args.witness
                .to_str()
                .ok_or("witness path is not valid UTF-8")?,
        )
        .map_err(|e| format!("failed to load witness: {e}"))?;

    eprintln!(
        "Loaded circuit: {} wires, {} constraints",
        circuit.n_wires, circuit.n_constraints
    );

    // ------------------------------------------------------------------
    // 2. Build engine inputs
    // ------------------------------------------------------------------
    let l_ref: Vec<&[u64]> = circuit.l.iter().map(|v| v.as_slice()).collect();
    let r_ref: Vec<&[u64]> = circuit.r.iter().map(|v| v.as_slice()).collect();
    let o_ref: Vec<&[u64]> = circuit.o.iter().map(|v| v.as_slice()).collect();

    let witness_fr: Vec<Fr> = circuit.witness.iter().map(|&v| Fr::from(v)).collect();

    // ------------------------------------------------------------------
    // 3. Load proving key (or fall back to deterministic test values)
    // ------------------------------------------------------------------
    let (tau, alpha, beta, gamma, delta) = if let Some(pk_path) = &args.proving_key {
        let pk_bytes = fs::read(pk_path)
            .map_err(|e| format!("failed to read proving key: {e}"))?;
        let pk = ProvingKey::deserialize_compressed(&pk_bytes[..])
            .map_err(|e| format!("failed to deserialize proving key: {e:?}"))?;
        eprintln!("Loaded proving key from {}", pk_path.display());
        (
            pk.toxic_waste.tau,
            pk.toxic_waste.alpha,
            pk.toxic_waste.beta,
            pk.toxic_waste.gamma,
            pk.toxic_waste.delta,
        )
    } else {
        eprintln!("Warning: no proving key provided; using deterministic test toxic waste (dev only)");
        (
            Fr::from(3u64),
            Fr::from(5u64),
            Fr::from(7u64),
            Fr::from(11u64),
            Fr::from(13u64),
        )
    };

    // ------------------------------------------------------------------
    // 4. Select engine and prover based on CLI flags
    // ------------------------------------------------------------------
    let (proof, public_input) = match (args.engine, args.prover) {
        (EngineArg::Dense, ProverArg::Naive) => {
            let engine = DenseQapEngine::new();
            let prover = NaiveProver::new();
            prover.prove(&engine, &l_ref, &r_ref, &o_ref, &witness_fr, tau, alpha, beta, gamma, delta)
        }
        (EngineArg::Dense, ProverArg::Pippenger) => {
            let engine = DenseQapEngine::new();
            let prover = PippengerProver::new();
            prover.prove(&engine, &l_ref, &r_ref, &o_ref, &witness_fr, tau, alpha, beta, gamma, delta)
        }
        (EngineArg::Fft, ProverArg::Naive) => {
            let engine = FftQapEngine::new();
            let prover = NaiveProver::new();
            prover.prove(&engine, &l_ref, &r_ref, &o_ref, &witness_fr, tau, alpha, beta, gamma, delta)
        }
        (EngineArg::Fft, ProverArg::Pippenger) => {
            let engine = FftQapEngine::new();
            let prover = PippengerProver::new();
            prover.prove(&engine, &l_ref, &r_ref, &o_ref, &witness_fr, tau, alpha, beta, gamma, delta)
        }
    };

    eprintln!("Proof generated successfully.");

    // ------------------------------------------------------------------
    // 4. Serialize proof
    // ------------------------------------------------------------------
    let mut proof_bytes = Vec::new();
    proof.a.serialize_compressed(&mut proof_bytes)
        .map_err(|e| format!("failed to serialize proof.a: {e:?}"))?;
    proof.b.serialize_compressed(&mut proof_bytes)
        .map_err(|e| format!("failed to serialize proof.b: {e:?}"))?;
    proof.c.serialize_compressed(&mut proof_bytes)
        .map_err(|e| format!("failed to serialize proof.c: {e:?}"))?;

    // Also serialize public input V
    let mut public_bytes = Vec::new();
    public_input.v.serialize_compressed(&mut public_bytes)
        .map_err(|e| format!("failed to serialize public_input.v: {e:?}"))?;

    // ------------------------------------------------------------------
    // 5. Output
    // ------------------------------------------------------------------
    if let Some(out_path) = args.out {
        // Write raw binary proof
        fs::write(&out_path, &proof_bytes)
            .map_err(|e| format!("failed to write proof to {}: {e}", out_path.display()))?;
        eprintln!("Proof written to {}", out_path.display());

        // Also write public input alongside (same stem + ".pub")
        let pub_path = out_path.with_extension("pub");
        fs::write(&pub_path, &public_bytes)
            .map_err(|e| format!("failed to write public input to {}: {e}", pub_path.display()))?;
        eprintln!("Public input written to {}", pub_path.display());
    } else {
        // Hex-encode to stdout
        let hex_proof = hex::encode(&proof_bytes);
        println!("{}", hex_proof);
    }

    Ok(())
}
