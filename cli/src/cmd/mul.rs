use clap::ArgGroup;
use hex::decode;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

#[derive(Debug, clap::Args)]
#[command(group = ArgGroup::new("group").required(true).args(["g1", "g2"]))]
pub struct Args {
    /// Use G1 group (48-byte compressed points)
    #[arg(long = "g1", group = "group")]
    g1: bool,

    /// Use G2 group (96-byte compressed points)
    #[arg(long = "g2", group = "group")]
    g2: bool,

    /// Path to point file (optional, reads from stdin if not provided)
    #[arg(long)]
    point: Option<String>,

    /// Scalar (hex, 32 bytes, required)
    #[arg(long)]
    scalar: String,
}

pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let point_hex = if let Some(path) = args.point {
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

    let point_bytes = decode(&point_hex).map_err(|_| "invalid hex point")?;
    let scalar_bytes = decode(&args.scalar).map_err(|_| "invalid hex scalar")?;

    let group = if args.g1 {
        bls12_381_aiken_cli::CurveGroup::G1
    } else {
        bls12_381_aiken_cli::CurveGroup::G2
    };

    let result =
        bls12_381_aiken_cli::scalar_mul(&group, &point_bytes, &scalar_bytes).map_err(|e| e)?;

    print!("{}", hex::encode(result));

    Ok(())
}
