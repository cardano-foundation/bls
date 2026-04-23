use hex::decode;
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

    let mut private_key = vec![0u8; 32];
    for i in 0..32 {
        private_key[i] = seed_bytes[i % seed_bytes.len()];
    }

    print!("{}", hex::encode(&private_key));

    Ok(())
}
