use std::env;
use std::fs;
use zkvm_onchain::{wrap_proof, Bn254Proof, ProofSystem, Result};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!("usage: wrap-openvm --proof <path> --out <path>");
        std::process::exit(2);
    }
    let mut proof_path = String::new();
    let mut out_path = String::new();
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--proof" && i + 1 < args.len() {
            proof_path = args[i+1].clone();
            i += 2;
        } else if args[i] == "--out" && i + 1 < args.len() {
            out_path = args[i+1].clone();
            i += 2;
        } else {
            i += 1;
        }
    }
    
    let proof_data = fs::read(&proof_path)?;
    let proof = Bn254Proof {
        system: ProofSystem::OpenVM,
        public_inputs: vec![],
        proof_data,
        vm_commitment: None,
    };
    let wrapped = wrap_proof(&proof)?;
    let json = serde_json::to_string_pretty(&wrapped)?;
    fs::write(&out_path, json)?;
    println!("wrapped proof written to {}", out_path);
    Ok(())
}
