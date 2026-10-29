#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_main)]
#![cfg_attr(all(target_os = "zkvm", not(feature = "std")), no_std)]

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

use uplc_guest::{eval_flat, Data};
#[cfg(target_os = "zkvm")]
use num_bigint;
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
        encode_data(&mut out, arg);
    }
    out
}

#[cfg(not(target_os = "zkvm"))]
fn encode_data(out: &mut Vec<u8>, data: &Data) {
    match data {
        Data::B(bytes) => {
            out.push(0);
            push_u32(out, bytes.len() as u32);
            out.extend_from_slice(bytes);
        }
        Data::I(i) => {
            out.push(1);
            let bytes = i.to_signed_bytes_le();
            push_u32(out, bytes.len() as u32);
            out.extend_from_slice(&bytes);
        }
        Data::List(items) => {
            out.push(2);
            push_u32(out, items.len() as u32);
            for item in items {
                encode_data(out, item);
            }
        }
        Data::Map(entries) => {
            out.push(3);
            push_u32(out, entries.len() as u32);
            for (k, v) in entries {
                encode_data(out, k);
                encode_data(out, v);
            }
        }
        Data::Constr(tag, fields) => {
            out.push(4);
            push_u64(out, *tag);
            push_u32(out, fields.len() as u32);
            for field in fields {
                encode_data(out, field);
            }
        }
    }
}

#[cfg(not(target_os = "zkvm"))]
fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(target_os = "zkvm")]
fn decode_input_blob(bytes: &[u8]) -> Option<(Vec<u8>, Vec<Data>)> {
    let mut pos = 0;
    let flat_len = read_u32(bytes, &mut pos)? as usize;
    let flat = read_bytes(bytes, &mut pos, flat_len)?;
    let num_args = read_u32(bytes, &mut pos)? as usize;
    let mut args = Vec::with_capacity(num_args);
    for _ in 0..num_args {
        args.push(decode_data(bytes, &mut pos)?);
    }
    Some((flat, args))
}

#[cfg(target_os = "zkvm")]
fn decode_data(bytes: &[u8], pos: &mut usize) -> Option<Data> {
    let tag = read_u8(bytes, pos)?;
    match tag {
        0 => {
            let len = read_u32(bytes, pos)? as usize;
            let b = read_bytes(bytes, pos, len)?;
            Some(Data::B(b))
        }
        1 => {
            let len = read_u32(bytes, pos)? as usize;
            let b = read_bytes(bytes, pos, len)?;
            let mut sign = 1i128;
            if !b.is_empty() && b[len-1] & 0x80 != 0 {
                sign = -1;
            }
            let mut val: i128 = 0;
            for &byte in b.iter().rev() {
                val = val * 256 + (byte as i128);
            }
            if sign == -1 {
                val = -val;
            }
            Some(Data::I(num_bigint::BigInt::from(val)))
        }
        2 => {
            let len = read_u32(bytes, pos)? as usize;
            let mut items = alloc::vec::Vec::with_capacity(len);
            for _ in 0..len {
                items.push(decode_data(bytes, pos)?);
            }
            Some(Data::List(items))
        }
        3 => {
            let len = read_u32(bytes, pos)? as usize;
            let mut items = alloc::vec::Vec::with_capacity(len);
            for _ in 0..len {
                let k = decode_data(bytes, pos)?;
                let v = decode_data(bytes, pos)?;
                items.push((k, v));
            }
            Some(Data::Map(items))
        }
        4 => {
            let tag = read_u64(bytes, pos)?;
            let len = read_u32(bytes, pos)? as usize;
            let mut fields = alloc::vec::Vec::with_capacity(len);
            for _ in 0..len {
                fields.push(decode_data(bytes, pos)?);
            }
            Some(Data::Constr(tag, fields))
        }
        _ => None,
    }
}

#[cfg(target_os = "zkvm")]
fn read_u8(bytes: &[u8], pos: &mut usize) -> Option<u8> {
    if *pos >= bytes.len() { return None; }
    let v = bytes[*pos]; *pos += 1; Some(v)
}

#[cfg(target_os = "zkvm")]
fn read_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos + 8 > bytes.len() { return None; }
    let v = u64::from_le_bytes(bytes[*pos..*pos+8].try_into().unwrap());
    *pos += 8; Some(v)
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
