#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_main)]
#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

use uplc_guest::{eval_flat, Data};

openvm::entry!(main);

pub fn main() {
    let (flat, args) = read_input();

    let value = eval_flat(&flat, &args).expect("UPLC evaluation failed");
    let digest = value.as_bytes().expect("result is not a bytestring");

    let mut output = [0u8; 32];
    output.copy_from_slice(digest);

    println(format!("UPLC output sha256 = {}", hex(&output)));

    #[cfg(target_os = "zkvm")]
    openvm::io::reveal_bytes32(output);
}

#[cfg(target_os = "zkvm")]
fn read_input() -> (Vec<u8>, Vec<Data>) {
    let bytes = openvm::io::read_vec();
    decode_input_blob(&bytes).expect("invalid input blob")
}

#[cfg(not(target_os = "zkvm"))]
fn read_input() -> (Vec<u8>, Vec<Data>) {
    use std::{env, fs, process};

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: uplc <program.flat> [--data-bytes HEX]... [--write-input PATH]");
        process::exit(2);
    }

    let flat = fs::read(&args[1]).unwrap_or_else(|error| {
        eprintln!("failed to read {}: {error}", args[1]);
        process::exit(2);
    });

    let mut data_args = Vec::new();
    let mut index = 2;
    let mut write_input_path: Option<String> = None;
    while index < args.len() {
        match args[index].as_str() {
            "--data-bytes" => {
                let value = args.get(index + 1).unwrap_or_else(|| {
                    eprintln!("--data-bytes requires a hex value");
                    process::exit(2);
                });
                let bytes = uplc_guest::hex_decode(value).unwrap_or_else(|| {
                    eprintln!("invalid hex value: {value}");
                    process::exit(2);
                });
                data_args.push(Data::B(bytes));
                index += 2;
            }
            "--write-input" => {
                write_input_path = Some(args.get(index + 1).unwrap_or_else(|| {
                    eprintln!("--write-input requires a path");
                    process::exit(2);
                }).clone());
                index += 2;
            }
            other => {
                eprintln!("unknown argument: {other}");
                process::exit(2);
            }
        }
    }

    if let Some(path) = write_input_path {
        let json = encode_openvm_input_json(&flat, &data_args);
        fs::write(&path, json.as_bytes()).unwrap_or_else(|error| {
            eprintln!("failed to write {path}: {error}");
            process::exit(2);
        });
        std::println!("wrote {path}");
        process::exit(0);
    }

    (flat, data_args)
}

#[cfg(not(target_os = "zkvm"))]
fn encode_openvm_input_json(flat: &[u8], args: &[Data]) -> String {
    let blob = encode_input_blob(flat, args);
    let hex = blob.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    format!("{{\"input\":[\"0x01{}\"]}}", hex)
}

#[cfg(not(target_os = "zkvm"))]
fn encode_input_blob(flat: &[u8], args: &[Data]) -> Vec<u8> {
    let mut out = Vec::new();
    push_u32(&mut out, flat.len() as u32);
    out.extend_from_slice(flat);
    push_u32(&mut out, args.len() as u32);
    for arg in args {
        let Data::B(bytes) = arg else {
            panic!("only Data::B arguments are supported in the zkVM input format");
        };
        push_u32(&mut out, bytes.len() as u32);
        out.extend_from_slice(bytes);
    }
    out
}

#[cfg(target_os = "zkvm")]
fn decode_input_blob(bytes: &[u8]) -> Option<(Vec<u8>, Vec<Data>)> {
    let mut pos = 0;
    let flat_len = read_u32(bytes, &mut pos)? as usize;
    let flat = read_bytes(bytes, &mut pos, flat_len)?;
    let num_args = read_u32(bytes, &mut pos)? as usize;
    let mut args = Vec::with_capacity(num_args);
    for _ in 0..num_args {
        let arg_len = read_u32(bytes, &mut pos)? as usize;
        let arg_bytes = read_bytes(bytes, &mut pos, arg_len)?;
        args.push(Data::B(arg_bytes));
    }
    Some((flat, args))
}

#[cfg(not(target_os = "zkvm"))]
fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(target_os = "zkvm")]
fn read_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos + 4 > bytes.len() {
        return None;
    }
    let value = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Some(value)
}

#[cfg(target_os = "zkvm")]
fn read_bytes(bytes: &[u8], pos: &mut usize, len: usize) -> Option<Vec<u8>> {
    if *pos + len > bytes.len() {
        return None;
    }
    let value = bytes[*pos..*pos + len].to_vec();
    *pos += len;
    Some(value)
}

fn println(s: String) {
    #[cfg(target_os = "zkvm")]
    openvm::io::println(s);
    #[cfg(not(target_os = "zkvm"))]
    std::println!("{}", s);
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::new();
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
