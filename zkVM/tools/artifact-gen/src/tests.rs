#[cfg(test)]
mod tests {
    use crate::parser::{extract_compiled_code, parse_export_json};
    use crate::error::Error;

    #[test]
    fn test_parse_export_json() {
        let output = "Compiling...\n{\"name\":\"test\",\"compiledCode\":\"deadbeef\"}";
        let json = parse_export_json(output).unwrap();
        assert_eq!(json["name"], "test");
    }

    #[test]
    fn test_extract_compiled_code() {
        let output = "{\"compiledCode\":\"010203\"}";
        let json = parse_export_json(output).unwrap();
        let bytes = extract_compiled_code(&json).unwrap();
        assert_eq!(bytes, vec![1, 2, 3]);
    }

    #[test]
    fn test_no_compiled_code() {
        let output = "{\"name\":\"test\"}";
        let json = parse_export_json(output).unwrap();
        assert!(matches!(extract_compiled_code(&json), Err(Error::NoCompiledCode)));
    }

    #[test]
    fn test_invalid_hex() {
        let output = "{\"compiledCode\":\"zz\"}";
        let json = parse_export_json(output).unwrap();
        assert!(matches!(extract_compiled_code(&json), Err(Error::InvalidHex(_))));
    }
}
