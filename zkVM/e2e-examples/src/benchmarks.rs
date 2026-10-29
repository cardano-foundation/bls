use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub program: String,
    pub vm: String,
    pub host_time_ms: u64,
    pub prove_time_ms: Option<u64>,
    pub verify_time_ms: Option<u64>,
    pub proof_size_bytes: Option<u64>,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub results: Vec<BenchmarkResult>,
    pub timestamp: String,
}

impl BenchmarkReport {
    pub fn new() -> Self {
        Self {
            results: vec![],
            timestamp: chrono_string(),
        }
    }
    
    pub fn add(&mut self, result: BenchmarkResult) {
        self.results.push(result);
    }
    
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

impl Default for BenchmarkReport {
    fn default() -> Self {
        Self::new()
    }
}

fn chrono_string() -> String {
    "2026-01-01T00:00:00Z".to_string()
}
