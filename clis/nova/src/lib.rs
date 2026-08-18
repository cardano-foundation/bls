//! Library exports for the nova CLI

/// Re-export common types from nova-prover for downstream use
pub use nova_prover::{
    run_ceremony, run_fold, run_params, run_verify, CeremonyOutput, CircuitDescriptor, IvcBundle,
    StepProof, VerifyOutput,
};
