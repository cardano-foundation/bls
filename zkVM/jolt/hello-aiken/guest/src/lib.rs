#![cfg_attr(feature = "guest", no_std)]

extern crate alloc;

use alloc::vec::Vec;
use uplc_guest::{eval_flat, Data};

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
        let arg_len = read_u32(bytes, &mut pos)? as usize;
        let arg_bytes = read_bytes(bytes, &mut pos, arg_len)?;
        args.push(Data::B(arg_bytes));
    }
    Some((flat, args))
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
