use hex::decode;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Signature (from stdin or file)
    #[arg(short, long)]
    sig: Option<String>,

    /// Message that was signed
    #[arg(short, long)]
    msg: String,

    /// Public key (from stdin or file)
    #[arg(short, long)]
    pk: Option<String>,

    /// Domain separation tag (optional, defaults to empty)
    #[arg(short, long, default_value = "")]
    dst: String,

    /// Augmentation data (optional, defaults to empty)
    #[arg(short, long, default_value = "")]
    aug: String,
}

pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    // Read signature
    let signature_hex = if let Some(path) = args.sig {
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

    // Read public key
    let public_key_hex = if let Some(path) = args.pk {
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

    let signature_bytes = decode(&signature_hex).map_err(|_| "invalid hex signature")?;
    let public_key_bytes = decode(&public_key_hex).map_err(|_| "invalid hex public key")?;

    let is_valid = bls12_381_aiken_cli::verify(
        args.msg.as_bytes(),
        &signature_bytes,
        &public_key_bytes,
        args.dst.as_bytes(),
        args.aug.as_bytes(),
    )
    .map_err(|e| e)?;

    if is_valid {
        println!("Verified");
    } else {
        println!("Not Verified");
    }

    Ok(())
}
