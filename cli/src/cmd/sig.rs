use hex::decode;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Path to private key file (optional, reads from stdin if not provided)
    #[arg(short, long = "prv")]
    prv: Option<String>,

    /// Message to sign
    #[arg(short, long)]
    msg: String,

    /// Domain separation tag (optional)
    #[arg(short, long, default_value = "")]
    dst: String,

    /// Augmentation data (optional)
    #[arg(short, long, default_value = "")]
    aug: String,
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

    let signature = bls12_381_aiken_cli::hash_to_group(
        &private_key_bytes,
        args.msg.as_bytes(),
        args.dst.as_bytes(),
        args.aug.as_bytes(),
    )
    .map_err(|e| e)?;

    print!("{}", hex::encode(signature));

    Ok(())
}
