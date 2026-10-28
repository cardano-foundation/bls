use crate::error::{Error, Result};
use serde_json::Value;

pub fn parse_export_json(output: &str) -> Result<Value> {
    let json_start = output.find('{').ok_or_else(|| Error::ParseFailed("no JSON found in output".to_string()))?;
    let json_str = &output[json_start..];
    let value: Value = serde_json::from_str(json_str)?;
    Ok(value)
}

pub fn extract_compiled_code(value: &Value) -> Result<Vec<u8>> {
    let compiled_code = value
        .get("compiledCode")
        .and_then(|v| v.as_str())
        .ok_or(Error::NoCompiledCode)?;
    let bytes = hex::decode(compiled_code)
        .map_err(|e| Error::InvalidHex(e.to_string()))?;
    Ok(bytes)
}
