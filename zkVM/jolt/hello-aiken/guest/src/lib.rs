#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use alloc::vec::Vec;
use uplc_guest::{eval_flat, Data};
#[cfg(feature = "guest")]
use num_bigint;
#[jolt::provable(heap_size = 32768, max_trace_length = 65536)]
fn uplc_eval(flat_with_args: &[u8]) -> [u8; 32] {
    let (flat, args) = decode_input_blob(&flat_with_args).expect("invalid input blob");
    let value = eval_flat(&flat, &args).expect("UPLC evaluation failed");
    let digest = value.as_bytes().expect("result is not a bytestring");
    let mut output = [0u8; 32];
    output.copy_from_slice(digest);
    output
}

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
            let mut val: i128 = 0;
            for &byte in b.iter().rev() {
                val = val * 256 + (byte as i128);
            }
            Some(Data::I(num_bigint::BigInt::from(val)))
        }
        2 => {
            let len = read_u32(bytes, pos)? as usize;
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                items.push(decode_data(bytes, pos)?);
            }
            Some(Data::List(items))
        }
        3 => {
            let len = read_u32(bytes, pos)? as usize;
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                let k = decode_data(bytes, pos)?;
                let v = decode_data(bytes, pos)?;
                items.push((k, v));
            }
            Some(Data::Map(items))
        }
        4 => {
            let tagv = read_u64(bytes, pos)?;
            let len = read_u32(bytes, pos)? as usize;
            let mut fields = Vec::with_capacity(len);
            for _ in 0..len {
                fields.push(decode_data(bytes, pos)?);
            }
            Some(Data::Constr(tagv, fields))
        }
        _ => None,
    }
}

fn read_u8(bytes: &[u8], pos: &mut usize) -> Option<u8> {
    if *pos >= bytes.len() { return None; }
    let v = bytes[*pos]; *pos += 1; Some(v)
}

fn read_u64(bytes: &[u8], pos: &mut usize) -> Option<u64> {
    if *pos + 8 > bytes.len() { return None; }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes[*pos..*pos+8]);
    *pos += 8;
    Some(u64::from_le_bytes(arr))
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos + 4 > bytes.len() {
        return None;
    }
    let value = u32::from_le_bytes(bytes[*pos..*pos + 4].try_into().unwrap());
    *pos += 4;
    Some(value)
}

fn read_bytes(bytes: &[u8], pos: &mut usize, len: usize) -> Option<Vec<u8>> {
    if *pos + len > bytes.len() {
        return None;
    }
    let value = bytes[*pos..*pos + len].to_vec();
    *pos += len;
    Some(value)
}
