use crate::error::{Error, Result};
use std::process::Command;

#[derive(Debug, Clone)]
pub enum VmTarget {
    OpenVM,
    Jolt,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub vm: VmTarget,
    pub flat_path: String,
    pub args_hex: Vec<String>,
    pub release: bool,
}

#[derive(Debug, Clone)]
pub struct RunResult {
    pub success: bool,
    pub output: String,
    pub duration_ms: u64,
}

impl RunConfig {
    pub fn new(vm: VmTarget, flat_path: String) -> Self {
        Self {
            vm,
            flat_path,
            args_hex: vec![],
            release: true,
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args_hex = args;
        self
    }
}

pub fn run_uplc(config: &RunConfig) -> Result<RunResult> {
    let start = std::time::Instant::now();
    let mut cmd = match config.vm {
        VmTarget::OpenVM => {
            let mut c = Command::new("cargo");
            c.arg("run");
            if config.release { c.arg("--release"); }
            c.args(["--bin", "uplc", "--"]);
            c.args([&config.flat_path]);
            for arg in &config.args_hex {
                c.args(["--data-bytes", arg]);
            }
            c.current_dir("../../zkVM/openvm/hello-aiken");
            c
        }
        VmTarget::Jolt => {
            let mut c = Command::new("cargo");
            c.arg("run");
            if config.release { c.arg("--release"); }
            c.args(["--bin", "uplc", "--"]);
            c.args([&config.flat_path]);
            for arg in &config.args_hex {
                c.args(["--data-bytes", arg]);
            }
            c.current_dir("../../zkVM/jolt/hello-aiken");
            c
        }
    };
    
    let output = cmd.output().map_err(|e| Error::Runner(e.to_string()))?;
    let duration_ms = start.elapsed().as_millis() as u64;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    
    Ok(RunResult {
        success: output.status.success(),
        output: if stdout.is_empty() { stderr } else { stdout },
        duration_ms,
    })
}
