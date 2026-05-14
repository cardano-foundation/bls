use super::strip_0x;
use clap::ArgGroup;
use hex::decode;
use num_bigint::BigUint;
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

    /// Point to multiply (from stdin or file, as hex). Use "identity" for the point at infinity, or "generator" for the group generator.
    #[arg(long)]
    point: Option<String>,

    /// Scalar value (hex with 0x prefix, or decimal without prefix)
    #[arg(long)]
    scalar: String,
}

const G1_GENERATOR: &str = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
const G2_GENERATOR: &str = "93e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

fn resolve_point(value: &str, group: &bls12_381_aiken_cli::CurveGroup) -> Result<Vec<u8>, String> {
    if value == "identity" {
        return Ok(match group {
            bls12_381_aiken_cli::CurveGroup::G1 => {
                let mut bytes = vec![0xc0u8];
                bytes.extend(std::iter::repeat(0u8).take(47));
                bytes
            }
            bls12_381_aiken_cli::CurveGroup::G2 => {
                let mut bytes = vec![0xc0u8];
                bytes.extend(std::iter::repeat(0u8).take(95));
                bytes
            }
        });
    }
    if value == "generator" {
        return Ok(match group {
            bls12_381_aiken_cli::CurveGroup::G1 => decode(G1_GENERATOR).unwrap(),
            bls12_381_aiken_cli::CurveGroup::G2 => decode(G2_GENERATOR).unwrap(),
        });
    }
    decode(strip_0x(value)).map_err(|_| "invalid hex point".to_string())
}

fn parse_scalar(s: &str) -> Result<Vec<u8>, String> {
    let mut bytes = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        decode(hex).map_err(|_| "invalid hex scalar")?
    } else if let Some(val) = BigUint::parse_bytes(s.as_bytes(), 10) {
        val.to_bytes_le()
    } else {
        return Err("invalid scalar".to_string());
    };

    if bytes.len() > 32 {
        return Err("scalar value exceeds 32 bytes".to_string());
    }
    bytes.resize(32, 0u8);
    Ok(bytes)
}

pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let group = if args.g1 {
        bls12_381_aiken_cli::CurveGroup::G1
    } else {
        bls12_381_aiken_cli::CurveGroup::G2
    };

    let point_bytes = if let Some(val) = args.point {
        if val == "identity" || val == "generator" {
            resolve_point(&val, &group)?
        } else {
            let f = File::open(&val)?;
            let mut reader = BufReader::new(f);
            let mut line = String::new();
            reader.read_line(&mut line)?;
            resolve_point(line.trim(), &group)?
        }
    } else {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        resolve_point(line.trim(), &group)?
    };

    let scalar_bytes = parse_scalar(&args.scalar)?;

    let result =
        bls12_381_aiken_cli::scalar_mul(&group, &point_bytes, &scalar_bytes).map_err(|e| e)?;

    print!("0x{}", hex::encode(result));

    Ok(())
}
