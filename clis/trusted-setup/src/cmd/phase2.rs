//! Phase-2 MPC ceremony CLI subcommands.
//!
//! These commands implement the circuit-specific phase of a Groth16 trusted-setup
//! ceremony, producing the same `.pk` / `.vk` binary format as `ceremony-dev`.
//!
//! # Workflow
//!
//! ```text
//! 1. trusted-setup phase2 new \
//!       --circuit c.r1cs --srs universal.ptau --zkey c_0000.zkey
//!
//! 2. trusted-setup phase2 contribute \
//!       --zkey-in c_0000.zkey --zkey-out c_0001.zkey
//!
//! 3. trusted-setup phase2 verify \
//!       --zkey c_0001.zkey --circuit c.r1cs --srs universal.ptau
//!
//! 4. trusted-setup phase2 finalize \
//!       --zkey c_final.zkey --proving-key c.pk --verifying-key c.vk
//! ```
//!
//! # Examples
//!
//! Full workflow from SRS to proving key:
//!
//!   $ trusted-setup phase2 new --circuit circuit.r1cs --srs universal.ptau --zkey circuit_0000.zkey
//!   $ trusted-setup phase2 contribute --zkey-in circuit_0000.zkey --zkey-out circuit_0001.zkey --name "Contributor 1"
//!   $ trusted-setup phase2 verify --zkey circuit_0001.zkey
//!   $ trusted-setup phase2 finalize --zkey circuit_0001.zkey --proving-key circuit.pk --verifying-key circuit.vk

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use clap::{Parser, Subcommand};
use crate::circom_adapter::CircomCircuit;
use crate::engine::FftQapEngine;
use crate::phase2::Phase2Accumulator;
use crate::ptau::PtauFile;
use std::error::Error;
use std::fs;
use std::path::PathBuf;

/// Phase-2 ceremony subcommands
#[derive(Debug, Subcommand)]
pub enum Phase2Command {
    /// Create an initial Phase-2 accumulator from a `.ptau` SRS and a circuit
    ///
    /// Loads the circuit from a `.r1cs` file and the Phase-1 SRS from a
    /// `.ptau` file, then runs the Phase-2 initialization protocol to
    /// produce a circuit-specific accumulator (`.zkey`).
    ///
    /// The accumulator contains the toxic waste encrypted under the
    /// circuit-specific trapdoor.  Keep the `.zkey` file secret — anyone
    /// with access to it can produce fake proofs.
    ///
    /// Example:
    ///
    ///   $ trusted-setup phase2 new --circuit circuit.r1cs --srs universal.ptau --zkey circuit_0000.zkey
    New(NewArgs),

    /// Contribute randomness to an existing accumulator
    ///
    /// Loads an existing accumulator (`.zkey`), applies a fresh
    /// contribution of random toxic waste, and writes the updated
    /// accumulator to a new file.  Each contribution binds the
    /// accumulator to a new secret value, so the ceremony remains
    /// secure as long as at least one participant honestly discards
    /// their contribution.
    ///
    /// Optionally tag the contribution with a `--name` for audit trails.
    ///
    /// Example:
    ///
    ///   $ trusted-setup phase2 contribute --zkey-in circuit_0000.zkey --zkey-out circuit_0001.zkey --name "Alice"
    Contribute(ContributeArgs),

    /// Verify an accumulator's integrity
    ///
    /// Loads an accumulator (`.zkey`) and checks that all contributions
    /// are valid — i.e. that the accumulated verification key matches
    /// the expected public parameters.  This ensures no participant
    /// introduced a malicious trapdoor.
    ///
    /// Example:
    ///
    ///   $ trusted-setup phase2 verify --zkey circuit_0001.zkey
    Verify(VerifyArgs),

    /// Convert a finalized accumulator into `.pk` + `.vk`
    ///
    /// Loads a finalized accumulator (`.zkey`) and extracts the
    /// proving key (`.pk`) and verifying key (`.vk`) in binary format.
    /// The `.pk` is used by `prove` and the `.vk` is used by `verify`.
    ///
    /// After this step the accumulator is consumed and should no longer
    /// be used directly.
    ///
    /// Example:
    ///
    ///   $ trusted-setup phase2 finalize --zkey circuit_final.zkey --proving-key circuit.pk --verifying-key circuit.vk
    Finalize(FinalizeArgs),
}

/// Arguments for `phase2 new`
#[derive(Debug, Parser)]
pub struct NewArgs {
    /// Path to the `.r1cs` circuit file
    #[arg(long, value_name = "FILE")]
    circuit: PathBuf,

    /// Path to the Phase-1 `.ptau` SRS file
    #[arg(long, value_name = "FILE")]
    srs: PathBuf,

    /// Output path for the initial accumulator (`.zkey`)
    #[arg(long, value_name = "FILE")]
    zkey: PathBuf,
}

/// Arguments for `phase2 contribute`
#[derive(Debug, Parser)]
pub struct ContributeArgs {
    /// Input accumulator (`.zkey`) to contribute to
    #[arg(long, value_name = "FILE")]
    zkey_in: PathBuf,

    /// Output accumulator (`.zkey`) with the new contribution applied
    #[arg(long, value_name = "FILE")]
    zkey_out: PathBuf,

    /// Optional participant name for audit trail
    #[arg(long, value_name = "NAME")]
    name: Option<String>,
}

/// Arguments for `phase2 verify`
#[derive(Debug, Parser)]
pub struct VerifyArgs {
    /// Accumulator (`.zkey`) to verify
    #[arg(long, value_name = "FILE")]
    zkey: PathBuf,
}

/// Arguments for `phase2 finalize`
#[derive(Debug, Parser)]
pub struct FinalizeArgs {
    /// Final accumulator (`.zkey`) to extract keys from
    #[arg(long, value_name = "FILE")]
    zkey: PathBuf,

    /// Output path for the proving key (`.pk`)
    #[arg(long, value_name = "FILE")]
    proving_key: PathBuf,

    /// Output path for the verifying key (`.vk`)
    #[arg(long, value_name = "FILE")]
    verifying_key: PathBuf,
}

/// Run a Phase-2 subcommand
pub fn run(cmd: Phase2Command) -> Result<(), Box<dyn Error>> {
    match cmd {
        Phase2Command::New(args) => run_new(args),
        Phase2Command::Contribute(args) => run_contribute(args),
        Phase2Command::Verify(args) => run_verify(args),
        Phase2Command::Finalize(args) => run_finalize(args),
    }
}

// ------------------------------------------------------------------
// `phase2 new`
// ------------------------------------------------------------------

fn run_new(args: NewArgs) -> Result<(), Box<dyn Error>> {
    // 1. Load circuit
    let circuit = CircomCircuit::from_r1cs(
        args.circuit
            .to_str()
            .ok_or("circuit path is not valid UTF-8")?,
    )
    .map_err(|e| format!("failed to load circuit: {e}"))?;

    eprintln!(
        "Loaded circuit: {} wires, {} constraints (public: {} out + {} in, private: {})",
        circuit.n_wires,
        circuit.n_constraints,
        circuit.n_pub_out,
        circuit.n_pub_in,
        circuit.n_prv_in
    );

    // 2. Load .ptau
    let mut ptau = PtauFile::open(
        args.srs.to_str().ok_or("SRS path is not valid UTF-8")?,
    )
    .map_err(|e| format!("failed to open .ptau: {e}"))?;

    eprintln!(
        "Loaded SRS: power {} (max {} G1 points, {} G2 points)",
        ptau.power(),
        ptau.max_g1_points(),
        ptau.max_g2_points()
    );

    // 3. Determine public variable count
    let n_public = 1 + circuit.n_pub_out as usize + circuit.n_pub_in as usize;

    // 4. Initialize Phase-2 accumulator
    let mut rng = rand::thread_rng();
    let engine = FftQapEngine::new();

    eprintln!("Initializing Phase-2 accumulator (this may take a while)...");
    let accumulator = Phase2Accumulator::initialize(
        &mut ptau,
        &engine,
        &circuit.l,
        &circuit.r,
        &circuit.o,
        n_public,
        &mut rng,
    )
    .map_err(|e| format!("initialization failed: {e:?}"))?;

    eprintln!("Accumulator initialized.");
    eprintln!(
        "  Variables: {} (public: {}), Constraints: {}",
        accumulator.a_query.len(),
        n_public,
        accumulator.h_query.len()
    );

    // 6. Serialize accumulator
    let mut buf = Vec::new();
    accumulator
        .serialize_compressed(&mut buf)
        .map_err(|e| format!("failed to serialize accumulator: {e:?}"))?;

    fs::write(&args.zkey, &buf)
        .map_err(|e| format!("failed to write accumulator: {e}"))?;

    eprintln!(
        "Initial accumulator written to {} ({} bytes)",
        args.zkey.display(),
        buf.len()
    );

    Ok(())
}

// ------------------------------------------------------------------
// `phase2 contribute`
// ------------------------------------------------------------------

fn run_contribute(args: ContributeArgs) -> Result<(), Box<dyn Error>> {
    // 1. Load accumulator
    let data = fs::read(&args.zkey_in)
        .map_err(|e| format!("failed to read accumulator: {e}"))?;

    let mut accumulator = Phase2Accumulator::deserialize_compressed(&data[..])
        .map_err(|e| format!("failed to deserialize accumulator: {e:?}"))?;

    eprintln!(
        "Loaded accumulator with {} existing contribution(s).",
        accumulator.contributions.len()
    );

    // 2. Apply contribution
    let mut rng = rand::thread_rng();
    accumulator
        .contribute(&mut rng)
        .map_err(|e| format!("contribution failed: {e:?}"))?;

    if let Some(name) = &args.name {
        let last = accumulator.contributions.len() - 1;
        accumulator.contributions[last].name = Some(name.clone());
        eprintln!("Contribution applied by '{}'.", name);
    } else {
        eprintln!("Contribution {} applied.", accumulator.contributions.len());
    }

    // 3. Serialize and write
    let mut buf = Vec::new();
    accumulator
        .serialize_compressed(&mut buf)
        .map_err(|e| format!("failed to serialize accumulator: {e:?}"))?;

    fs::write(&args.zkey_out, &buf)
        .map_err(|e| format!("failed to write accumulator: {e}"))?;

    eprintln!(
        "Accumulator written to {} ({} bytes)",
        args.zkey_out.display(),
        buf.len()
    );

    Ok(())
}

// ------------------------------------------------------------------
// `phase2 verify`
// ------------------------------------------------------------------

fn run_verify(args: VerifyArgs) -> Result<(), Box<dyn Error>> {
    // 1. Load accumulator
    let data = fs::read(&args.zkey)
        .map_err(|e| format!("failed to read accumulator: {e}"))?;

    let accumulator = Phase2Accumulator::deserialize_compressed(&data[..])
        .map_err(|e| format!("failed to deserialize accumulator: {e:?}"))?;

    eprintln!(
        "Loaded accumulator with {} contribution(s).",
        accumulator.contributions.len()
    );

    // 2. Verify
    accumulator
        .verify()
        .map_err(|e| format!("verification failed: {e:?}"))?;

    eprintln!("Accumulator is valid. All {} contribution(s) passed verification.",
        accumulator.contributions.len()
    );

    Ok(())
}

// ------------------------------------------------------------------
// `phase2 finalize`
// ------------------------------------------------------------------

fn run_finalize(args: FinalizeArgs) -> Result<(), Box<dyn Error>> {
    // 1. Load accumulator
    let data = fs::read(&args.zkey)
        .map_err(|e| format!("failed to read accumulator: {e}"))?;

    let accumulator = Phase2Accumulator::deserialize_compressed(&data[..])
        .map_err(|e| format!("failed to deserialize accumulator: {e:?}"))?;

    eprintln!(
        "Loaded accumulator with {} contribution(s).",
        accumulator.contributions.len()
    );

    // 2. Finalize
    let (full_pk, vk) = accumulator.finalize();

    eprintln!("Accumulator finalized.");
    eprintln!(
        "  Proving key:  {}  ({} bytes)",
        args.proving_key.display(),
        {
            let mut buf = Vec::new();
            full_pk.serialize_compressed(&mut buf).unwrap();
            buf.len()
        }
    );
    eprintln!(
        "  Verifying key: {}  ({} bytes)",
        args.verifying_key.display(),
        {
            let mut buf = Vec::new();
            vk.serialize_compressed(&mut buf).unwrap();
            buf.len()
        }
    );

    // 3. Write keys
    let mut pk_bytes = Vec::new();
    full_pk
        .serialize_compressed(&mut pk_bytes)
        .map_err(|e| format!("failed to serialize proving key: {e:?}"))?;
    fs::write(&args.proving_key, &pk_bytes)
        .map_err(|e| format!("failed to write proving key: {e}"))?;

    let mut vk_bytes = Vec::new();
    vk.serialize_compressed(&mut vk_bytes)
        .map_err(|e| format!("failed to serialize verifying key: {e:?}"))?;
    fs::write(&args.verifying_key, &vk_bytes)
        .map_err(|e| format!("failed to write verifying key: {e}"))?;

    eprintln!("Proving key written to {}", args.proving_key.display());
    eprintln!("Verifying key written to {}", args.verifying_key.display());

    Ok(())
}
