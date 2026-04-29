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

pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let private_key_hex = if let Some(path) = args.prv {
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

    let private_key_bytes = decode(&private_key_hex).map_err(|_| "invalid hex private key")?;

    let scalar = bls12_381_aiken_cli::sk_to_scalar(&private_key_bytes).map_err(|e| e)?;

    let scalar_bytes = scalar.to_bytes_le();
    let big_uint = BigUint::from_bytes_le(&scalar_bytes);
    print!("{}", big_uint);

    Ok(())
}
