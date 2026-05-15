use super::strip_0x;
use blst::{
    blst_p1_affine, blst_p1_deserialize, blst_p1_uncompress, blst_p2_affine, blst_p2_deserialize,
    blst_p2_uncompress, BLST_ERROR,
};
use clap::ArgGroup;
use hex::decode;
use midnight_curves::bls12_381::{G1Affine, G2Affine};
use midnight_curves::pairing::group::GroupEncoding;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::mem;
use std::ops::Neg;

#[derive(Debug, clap::Args)]
#[command(group = ArgGroup::new("group").required(true).args(["g1", "g2"]))]
pub struct Args {
    /// Use G1 group (48-byte compressed points)
    #[arg(long = "g1", group = "group")]
    g1: bool,

    /// Use G2 group (96-byte compressed points)
    #[arg(long = "g2", group = "group")]
    g2: bool,

    /// Point to invert (from stdin or file, as hex). Use "identity" for the point at infinity, or "generator" for the group generator.
    #[arg(long = "point")]
    point: Option<String>,
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

fn is_compressed_identity(bytes: &[u8]) -> bool {
    bytes.len() > 0 && bytes[0] == 0xc0 && bytes[1..].iter().all(|&b| b == 0)
}

fn invert_g1(point: &[u8]) -> Result<Vec<u8>, String> {
    if is_compressed_identity(point) || (point.len() == 96 && point.iter().all(|&b| b == 0)) {
        let mut identity = vec![0xc0u8];
        identity.extend(std::iter::repeat(0u8).take(47));
        return Ok(identity);
    }
    let affine = match point.len() {
        48 => {
            let mut raw = blst_p1_affine::default();
            let result = unsafe { blst_p1_uncompress(&mut raw, point.as_ptr()) };
            if result != BLST_ERROR::BLST_SUCCESS {
                return Err("invalid G1 compressed point".to_string());
            }
            unsafe { mem::transmute::<blst_p1_affine, G1Affine>(raw) }
        }
        96 => {
            let mut raw = blst_p1_affine::default();
            let result = unsafe { blst_p1_deserialize(&mut raw, point.as_ptr()) };
            if result != BLST_ERROR::BLST_SUCCESS {
                return Err("invalid G1 uncompressed point".to_string());
            }
            unsafe { mem::transmute::<blst_p1_affine, G1Affine>(raw) }
        }
        _ => return Err("invalid G1 point length (expected 48 or 96 bytes)".to_string()),
    };
    let negated = affine.neg();
    Ok(negated.to_bytes().as_ref().to_vec())
}

fn invert_g2(point: &[u8]) -> Result<Vec<u8>, String> {
    if is_compressed_identity(point) || (point.len() == 192 && point.iter().all(|&b| b == 0)) {
        let mut identity = vec![0xc0u8];
        identity.extend(std::iter::repeat(0u8).take(95));
        return Ok(identity);
    }
    let affine = match point.len() {
        96 => {
            let mut raw = blst_p2_affine::default();
            let result = unsafe { blst_p2_uncompress(&mut raw, point.as_ptr()) };
            if result != BLST_ERROR::BLST_SUCCESS {
                return Err("invalid G2 compressed point".to_string());
            }
            unsafe { mem::transmute::<blst_p2_affine, G2Affine>(raw) }
        }
        192 => {
            let mut raw = blst_p2_affine::default();
            let result = unsafe { blst_p2_deserialize(&mut raw, point.as_ptr()) };
            if result != BLST_ERROR::BLST_SUCCESS {
                return Err("invalid G2 uncompressed point".to_string());
            }
            unsafe { mem::transmute::<blst_p2_affine, G2Affine>(raw) }
        }
        _ => return Err("invalid G2 point length (expected 96 or 192 bytes)".to_string()),
    };
    let negated = affine.neg();
    Ok(negated.to_bytes().as_ref().to_vec())
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
        } else if let Ok(bytes) = resolve_point(&val, &group) {
            bytes
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

    let result = match group {
        bls12_381_aiken_cli::CurveGroup::G1 => invert_g1(&point_bytes)?,
        bls12_381_aiken_cli::CurveGroup::G2 => invert_g2(&point_bytes)?,
    };

    print!("0x{}", hex::encode(result));

    Ok(())
}
