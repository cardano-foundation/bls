//! Aiken artifact generator
//! 
//! Automates aiken export -> extract compiledCode -> write .flat

pub mod error;
pub mod generator;
pub mod parser;

#[cfg(feature = "verus")]
pub mod verus_specs;

#[cfg(test)]
mod tests;

pub use error::{Error, Result};
pub use generator::{ArtifactGenerator, GeneratorConfig};
pub use parser::{extract_compiled_code, parse_export_json};
