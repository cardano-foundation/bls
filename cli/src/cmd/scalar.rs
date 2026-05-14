use hex::decode;
use num_bigint::BigUint;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Path to private key file (optional, reads from stdin if not provided)
    #[arg(short, long = "prv")]
    prv: Option<String>,
}

fn parse_scalar_input(input: &str) -> Result<Vec<u8>, String> {
    let mut bytes = if let Some(hex) = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix("0X"))
    {
        decode(hex).map_err(|_| "invalid hex scalar")?
    } else {
        let val = BigUint::parse_bytes(input.as_bytes(), 10).ok_or("invalid decimal scalar")?;
        val.to_bytes_le()
    };

    if bytes.len() > 32 {
        return Err("scalar value exceeds 32 bytes".to_string());
    }
    bytes.resize(32, 0u8);
    Ok(bytes)
}

pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let input = if let Some(path) = args.prv {
        let f = File::open(&path)?;
        let mut reader = BufReader::new(f);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        line.trim().to_string()
    } else {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line.trim().to_string()
    };

    let scalar_bytes = parse_scalar_input(&input)?;

    let scalar = bls12_381_aiken_cli::sk_to_scalar(&scalar_bytes).map_err(|e| e)?;

    let scalar_bytes = scalar.to_bytes_le();
    let big_uint = BigUint::from_bytes_le(&scalar_bytes);
    print!("{}", big_uint);

    Ok(())
}
