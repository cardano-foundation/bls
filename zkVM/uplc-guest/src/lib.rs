#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

mod data;
mod flat;
mod machine;
mod term;

pub use data::{decode_cbor, decode_cbor_with_length, encode_cbor, Data, DataError};
pub use flat::{decode, DecodeError};
pub use machine::{eval, eval_flat, EvalError, Value};
pub use term::{hex_decode, hex_encode, Builtin, Constant, ConstantType, Program, Term, Version};
