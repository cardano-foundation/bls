use super::strip_0x;
use blst::{
    blst_fp12, blst_p1_affine, blst_p1_deserialize, blst_p2_affine, blst_p2_deserialize, BLST_ERROR,
};
use hex::decode;
use midnight_curves::bls12_381::{G1Affine, G2Affine};
use midnight_curves::pairing::group::prime::PrimeCurveAffine;
use std::error::Error;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::mem;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// G1 point as hex (uncompressed, 192 hex chars)
    #[arg(long)]
    g1: Option<String>,

    /// G2 point as hex (uncompressed, 384 hex chars)
    #[arg(long)]
    g2: Option<String>,

    /// G1 point file path
    #[arg(long = "g1-file")]
    g1_file: Option<String>,

    /// G2 point file path
    #[arg(long = "g2-file")]
    g2_file: Option<String>,
}

fn read_input(arg: &Option<String>, file: &Option<String>) -> Result<String, Box<dyn Error>> {
    if let Some(val) = arg {
        return Ok(val.clone());
    }
    if let Some(path) = file {
        let f = File::open(path)?;
        let mut reader = BufReader::new(f);
        let mut line = String::new();
        reader.read_line(&mut line)?;
        return Ok(line.trim().to_string());
    }
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn is_all_zeros(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

pub fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let g1_hex = read_input(&args.g1, &args.g1_file)?;
    let g2_hex = read_input(&args.g2, &args.g2_file)?;

    let g1_bytes = decode(strip_0x(&g1_hex)).map_err(|_| "invalid hex G1 point")?;
    let g2_bytes = decode(strip_0x(&g2_hex)).map_err(|_| "invalid hex G2 point")?;

    if g1_bytes.len() != 96 {
        return Err("G1 point must be 96 bytes (uncompressed)".into());
    }
    if g2_bytes.len() != 192 {
        return Err("G2 point must be 192 bytes (uncompressed)".into());
    }

    let g1_affine = if is_all_zeros(&g1_bytes) {
        G1Affine::identity()
    } else {
        let mut raw = blst_p1_affine::default();
        let result = unsafe { blst_p1_deserialize(&mut raw, g1_bytes.as_ptr()) };
        if result != BLST_ERROR::BLST_SUCCESS {
            return Err("invalid G1 uncompressed point".into());
        }
        unsafe { mem::transmute::<blst_p1_affine, G1Affine>(raw) }
    };

    let g2_affine = if is_all_zeros(&g2_bytes) {
        G2Affine::identity()
    } else {
        let mut raw = blst_p2_affine::default();
        let result = unsafe { blst_p2_deserialize(&mut raw, g2_bytes.as_ptr()) };
        if result != BLST_ERROR::BLST_SUCCESS {
            return Err("invalid G2 uncompressed point".into());
        }
        unsafe { mem::transmute::<blst_p2_affine, G2Affine>(raw) }
    };

    let gt = midnight_curves::bls12_381::pairing(&g1_affine, &g2_affine);
    let fp12: blst_fp12 = unsafe { mem::transmute(gt) };
    let bytes = unsafe {
        std::slice::from_raw_parts(&fp12 as *const _ as *const u8, mem::size_of::<blst_fp12>())
    };

    print!("0x{}", hex::encode(bytes));

    Ok(())
}
