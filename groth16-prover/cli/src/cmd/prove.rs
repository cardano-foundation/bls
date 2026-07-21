use ark_bls12_381::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::{Parser, ValueEnum};
use groth16_prover::ceremony::{
    single_party_ceremony_full_from_tw, FullProvingKey, ProvingKey, ToxicWaste,
};
use groth16_prover::circom_adapter::{CircomCircuit, SparseCircomCircuit};
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

    /// Build the witness polynomials on-the-fly using the group-element-only
    /// FullProvingKey path (Implementation 5). This avoids materialising the
    /// full `n_vars × domain_size` QAP matrix and is the default behaviour.
    #[arg(long, group = "qap_mode")]
    qap_on_fly: bool,

    /// Use the legacy scalar-based QAP path (Implementation 4). The prover
    /// re-evaluates the full QAP at `tau` on every proof instead of using the
    /// pre-computed group elements from the proving key.
    #[arg(long, group = "qap_mode")]
    qap_not_on_fly: bool,

    /// Use sparse constraint representation (Implementation 6).
    /// Avoids expanding the `.r1cs` into dense matrices, saving memory
    /// for large circuits.  Implies `--qap-on-fly`.
    #[arg(long)]
    sparse: bool,

    /// Optional output file for the proof (raw binary).
    /// If omitted, the proof is printed as hex to stdout.
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
}

/// Run the prove command
pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    // ------------------------------------------------------------------
    // Sparse path (Implementation 6)
    // ------------------------------------------------------------------
    if args.sparse {
        return run_sparse(args);
    }

    // ------------------------------------------------------------------
    // 1. Load circuit and witness (dense path)
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
    let witness_fr = &circuit.witness;

    // ------------------------------------------------------------------
    // 3. Decide which QAP construction mode to use
    // ------------------------------------------------------------------
    // Default is on-the-fly (Implementation 5).  --qap-not-on-fly selects the
    // legacy scalar-based path (Implementation 4).
    let use_on_fly = !args.qap_not_on_fly;
    if use_on_fly {
        eprintln!("Using on-the-fly QAP construction (Implementation 5)");
    } else {
        eprintln!("Using legacy scalar-based QAP construction (Implementation 4)");
    }

    // ------------------------------------------------------------------
    // 4. Load or build the right proving artifact
    // ------------------------------------------------------------------
    let n_public = (1 + circuit.n_pub_out + circuit.n_pub_in) as usize;
    let dummy_scalars = (
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
        Fr::from(0u64),
    );
    let (full_pk_opt, scalars) = if use_on_fly {
        // On-the-fly path: FullProvingKey (group elements only).  If the user
        // supplied a .pk, load it; otherwise generate one from the deterministic
        // test values (dev-only fallback), using the same engine as the proof.
        let full_pk = if let Some(pk_path) = &args.proving_key {
            let pk_bytes =
                fs::read(pk_path).map_err(|e| format!("failed to read proving key: {e}"))?;
            let full_pk = FullProvingKey::deserialize_compressed(&pk_bytes[..]).map_err(|e| {
                format!(
                    "failed to deserialize FullProvingKey: {e:?}. \
If your proving key is a legacy scalar-based key, use --qap-not-on-fly."
                )
            })?;
            eprintln!(
                "Loaded FullProvingKey from {} (group elements only, no scalars)",
                pk_path.display()
            );
            full_pk
        } else {
            eprintln!("Warning: no proving key provided; generating deterministic FullProvingKey (dev only)");
            let tw = ToxicWaste::deterministic();
            match args.engine {
                EngineArg::Dense => {
                    let engine = DenseQapEngine::new();
                    single_party_ceremony_full_from_tw(
                        &engine, &circuit.l, &circuit.r, &circuit.o, n_public, tw,
                    )
                    .0
                }
                EngineArg::Fft => {
                    let engine = FftQapEngine::new();
                    single_party_ceremony_full_from_tw(
                        &engine, &circuit.l, &circuit.r, &circuit.o, n_public, tw,
                    )
                    .0
                }
            }
        };
        (Some(full_pk), dummy_scalars)
    } else {
        // Legacy scalar-based path (Implementation 4): need toxic-waste scalars.
        let scalars = if let Some(pk_path) = &args.proving_key {
            let pk_bytes =
                fs::read(pk_path).map_err(|e| format!("failed to read proving key: {e}"))?;
            let pk = ProvingKey::deserialize_compressed(&pk_bytes[..]).map_err(|e| {
                format!(
                    "failed to deserialize legacy ProvingKey: {e:?}. \
If your proving key is a FullProvingKey, use --qap-on-fly (or omit the flag)."
                )
            })?;
            eprintln!("Loaded legacy proving key from {}", pk_path.display());
            (
                pk.toxic_waste.tau,
                pk.toxic_waste.alpha,
                pk.toxic_waste.beta,
                pk.toxic_waste.gamma,
                pk.toxic_waste.delta,
            )
        } else {
            eprintln!(
                "Warning: no proving key provided; using deterministic test toxic waste (dev only)"
            );
            (
                Fr::from(3u64),
                Fr::from(5u64),
                Fr::from(7u64),
                Fr::from(11u64),
                Fr::from(13u64),
            )
        };
        (None, scalars)
    };

    // ------------------------------------------------------------------
    // 5. Select engine and prover based on CLI flags
    // ------------------------------------------------------------------
    let (tau, alpha, beta, gamma, delta) = scalars;
    let (proof, public_input) = match (args.engine, args.prover, full_pk_opt) {
        // --- FullProvingKey path (on-the-fly, Implementation 5) ---
        (EngineArg::Dense, ProverArg::Naive, Some(full_pk)) => {
            let engine = DenseQapEngine::new();
            let prover = NaiveProver::new();
            prover.prove_with_full_pk(
                &engine, &full_pk, &circuit.l, &circuit.r, &circuit.o, witness_fr,
            )
        }
        (EngineArg::Dense, ProverArg::Pippenger, Some(full_pk)) => {
            let engine = DenseQapEngine::new();
            let prover = PippengerProver::new();
            prover.prove_with_full_pk(
                &engine, &full_pk, &circuit.l, &circuit.r, &circuit.o, witness_fr,
            )
        }
        (EngineArg::Fft, ProverArg::Naive, Some(full_pk)) => {
            let engine = FftQapEngine::new();
            let prover = NaiveProver::new();
            prover.prove_with_full_pk(
                &engine, &full_pk, &circuit.l, &circuit.r, &circuit.o, witness_fr,
            )
        }
        (EngineArg::Fft, ProverArg::Pippenger, Some(full_pk)) => {
            let engine = FftQapEngine::new();
            let prover = PippengerProver::new();
            prover.prove_with_full_pk(
                &engine, &full_pk, &circuit.l, &circuit.r, &circuit.o, witness_fr,
            )
        }

        // --- Legacy scalar-based path (Implementation 4) ---
        (EngineArg::Dense, ProverArg::Naive, None) => {
            let engine = DenseQapEngine::new();
            let prover = NaiveProver::new();
            prover.prove(
                &engine, &circuit.l, &circuit.r, &circuit.o, witness_fr, tau, alpha, beta, gamma,
                delta,
            )
        }
        (EngineArg::Dense, ProverArg::Pippenger, None) => {
            let engine = DenseQapEngine::new();
            let prover = PippengerProver::new();
            prover.prove(
                &engine, &circuit.l, &circuit.r, &circuit.o, witness_fr, tau, alpha, beta, gamma,
                delta,
            )
        }
        (EngineArg::Fft, ProverArg::Naive, None) => {
            let engine = FftQapEngine::new();
            let prover = NaiveProver::new();
            prover.prove(
                &engine, &circuit.l, &circuit.r, &circuit.o, witness_fr, tau, alpha, beta, gamma,
                delta,
            )
        }
        (EngineArg::Fft, ProverArg::Pippenger, None) => {
            let engine = FftQapEngine::new();
            let prover = PippengerProver::new();
            prover.prove(
                &engine, &circuit.l, &circuit.r, &circuit.o, witness_fr, tau, alpha, beta, gamma,
                delta,
            )
        }
    };

    eprintln!("Proof generated successfully.");

    // ------------------------------------------------------------------
    // 4. Serialize proof
    // ------------------------------------------------------------------
    let mut proof_bytes = Vec::new();
    proof
        .a
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| format!("failed to serialize proof.a: {e:?}"))?;
    proof
        .b
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| format!("failed to serialize proof.b: {e:?}"))?;
    proof
        .c
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| format!("failed to serialize proof.c: {e:?}"))?;

    // Also serialize public input V
    let mut public_bytes = Vec::new();
    public_input
        .v
        .serialize_compressed(&mut public_bytes)
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
        fs::write(&pub_path, &public_bytes).map_err(|e| {
            format!(
                "failed to write public input to {}: {e}",
                pub_path.display()
            )
        })?;
        eprintln!("Public input written to {}", pub_path.display());
    } else {
        // Hex-encode to stdout
        let hex_proof = hex::encode(&proof_bytes);
        println!("{}", hex_proof);
    }

    Ok(())
}

/// Sparse proving path (Implementation 6).
///
/// Loads the circuit in sparse format, builds witness polynomials directly
/// from the sparse constraint representation, and assembles the proof via
/// the FullProvingKey MSM path.
fn run_sparse(args: Args) -> Result<(), Box<dyn Error>> {
    use groth16_prover::ceremony::single_party_ceremony_full_from_tw_sparse;

    // ------------------------------------------------------------------
    // 1. Load circuit and witness (sparse)
    // ------------------------------------------------------------------
    let mut circuit = SparseCircomCircuit::from_r1cs(
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
        "Loaded circuit (sparse): {} wires, {} constraints",
        circuit.n_wires, circuit.n_constraints
    );

    if args.qap_not_on_fly {
        return Err(
            "--qap-not-on-fly is incompatible with --sparse. Sparse mode requires the on-the-fly FullProvingKey path."
                .into(),
        );
    }
    eprintln!("Using sparse on-the-fly QAP construction (Implementation 6)");

    // ------------------------------------------------------------------
    // 2. Load or generate FullProvingKey
    // ------------------------------------------------------------------
    let n_public = (1 + circuit.n_pub_out + circuit.n_pub_in) as usize;
    let engine = FftQapEngine::new();

    let full_pk = if let Some(pk_path) = &args.proving_key {
        let pk_bytes =
            fs::read(pk_path).map_err(|e| format!("failed to read proving key: {e}"))?;
        let full_pk = FullProvingKey::deserialize_compressed(&pk_bytes[..]).map_err(|e| {
            format!(
                "failed to deserialize FullProvingKey: {e:?}. \
If your proving key is a legacy scalar-based key, use --qap-not-on-fly."
            )
        })?;
        eprintln!(
            "Loaded FullProvingKey from {} (group elements only, no scalars)",
            pk_path.display()
        );
        full_pk
    } else {
        eprintln!("Warning: no proving key provided; generating deterministic FullProvingKey (dev only)");
        let tw = ToxicWaste::deterministic();
        single_party_ceremony_full_from_tw_sparse(
            &engine,
            circuit.n_constraints as usize,
            circuit.n_wires as usize,
            n_public,
            &circuit.l,
            &circuit.r,
            &circuit.o,
            tw,
        )
        .0
    };

    // ------------------------------------------------------------------
    // 3. Select prover and generate proof
    // ------------------------------------------------------------------
    let witness_fr = &circuit.witness;
    let n_constraints = circuit.n_constraints as usize;

    let (proof, public_input) = match args.prover {
        ProverArg::Naive => {
            let prover = NaiveProver::new();
            prover.prove_with_full_pk_sparse(
                &engine,
                &full_pk,
                n_constraints,
                &circuit.l,
                &circuit.r,
                &circuit.o,
                witness_fr,
            )
        }
        ProverArg::Pippenger => {
            let prover = PippengerProver::new();
            prover.prove_with_full_pk_sparse(
                &engine,
                &full_pk,
                n_constraints,
                &circuit.l,
                &circuit.r,
                &circuit.o,
                witness_fr,
            )
        }
    };

    eprintln!("Proof generated successfully (sparse path).");

    // ------------------------------------------------------------------
    // 4. Serialize and output
    // ------------------------------------------------------------------
    let mut proof_bytes = Vec::new();
    proof
        .a
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| format!("failed to serialize proof.a: {e:?}"))?;
    proof
        .b
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| format!("failed to serialize proof.b: {e:?}"))?;
    proof
        .c
        .serialize_compressed(&mut proof_bytes)
        .map_err(|e| format!("failed to serialize proof.c: {e:?}"))?;

    let mut public_bytes = Vec::new();
    public_input
        .v
        .serialize_compressed(&mut public_bytes)
        .map_err(|e| format!("failed to serialize public_input.v: {e:?}"))?;

    if let Some(out_path) = args.out {
        fs::write(&out_path, &proof_bytes)
            .map_err(|e| format!("failed to write proof to {}: {e}", out_path.display()))?;
        eprintln!("Proof written to {}", out_path.display());

        let pub_path = out_path.with_extension("pub");
        fs::write(&pub_path, &public_bytes).map_err(|e| {
            format!(
                "failed to write public input to {}: {e}",
                pub_path.display()
            )
        })?;
        eprintln!("Public input written to {}", pub_path.display());
    } else {
        let hex_proof = hex::encode(&proof_bytes);
        println!("{}", hex_proof);
    }

    Ok(())
}
