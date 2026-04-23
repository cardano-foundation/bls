use hex::decode;
use hkdf::Hkdf;
use sha2::Sha256;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Path to seed file (optional, reads from stdin if not provided)
    #[arg(short, long)]
    file: Option<String>,
}

pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let seed = if let Some(path) = args.file {
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

    let seed_bytes = decode(&seed).map_err(|_| "invalid hex seed")?;

    let hk = Hkdf::<Sha256>::new(None, &seed_bytes);
    let mut private_key = [0u8; 32];
    hk.expand(b"", &mut private_key)
        .map_err(|_| "hkdf expand failed")?;

    print!("{}", hex::encode(private_key));

    Ok(())
}
