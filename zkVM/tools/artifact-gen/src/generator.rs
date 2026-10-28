use crate::error::{Error, Result};
use crate::parser::{extract_compiled_code, parse_export_json};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone)]
pub struct GeneratorConfig {
    pub project_dir: String,
    pub module: String,
    pub name: String,
    pub output_path: String,
}

pub struct ArtifactGenerator {
    pub config: GeneratorConfig,
}

impl ArtifactGenerator {
    pub fn new(config: GeneratorConfig) -> Self {
        Self { config }
    }

    pub fn generate(&self) -> Result<()> {
        let output = Command::new("aiken")
            .arg("export")
            .arg("-m")
            .arg(&self.config.module)
            .arg("-n")
            .arg(&self.config.name)
            .current_dir(&self.config.project_dir)
            .output()?;
        
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::ExportFailed(stderr.to_string()));
        }
        
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json = parse_export_json(&stdout)?;
        let bytes = extract_compiled_code(&json)?;
        
        std::fs::write(&self.config.output_path, bytes)?;
        Ok(())
    }
}
