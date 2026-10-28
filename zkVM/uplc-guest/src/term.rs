use alloc::{boxed::Box, rc::Rc, string::String, vec::Vec};
use bls12_381::{G1Affine, G2Affine, Gt};
use num_bigint::BigInt;

use crate::data::Data;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Builtin(pub u8);

impl Builtin {
    pub const ADD_INTEGER: Self = Self(0);
    pub const SUBTRACT_INTEGER: Self = Self(1);
    pub const MULTIPLY_INTEGER: Self = Self(2);
    pub const DIVIDE_INTEGER: Self = Self(3);
    pub const QUOTIENT_INTEGER: Self = Self(4);
    pub const REMAINDER_INTEGER: Self = Self(5);
    pub const MOD_INTEGER: Self = Self(6);
    pub const EQUALS_INTEGER: Self = Self(7);
    pub const LESS_THAN_INTEGER: Self = Self(8);
    pub const LESS_THAN_EQUALS_INTEGER: Self = Self(9);
    pub const APPEND_BYTE_STRING: Self = Self(10);
    pub const CONS_BYTE_STRING: Self = Self(11);
    pub const SLICE_BYTE_STRING: Self = Self(12);
    pub const LENGTH_OF_BYTE_STRING: Self = Self(13);
    pub const INDEX_BYTE_STRING: Self = Self(14);
    pub const EQUALS_BYTE_STRING: Self = Self(15);
    pub const LESS_THAN_BYTE_STRING: Self = Self(16);
    pub const LESS_THAN_EQUALS_BYTE_STRING: Self = Self(17);
    pub const SHA2_256: Self = Self(18);
    pub const SHA3_256: Self = Self(19);
    pub const BLAKE2B_256: Self = Self(20);
    pub const KECCAK_256: Self = Self(71);
    pub const BLAKE2B_224: Self = Self(72);
    pub const INTEGER_TO_BYTE_STRING: Self = Self(73);
    pub const XOR_BYTE_STRING: Self = Self(77);
    pub const REPLICATE_BYTE: Self = Self(81);
    pub const BLS12_381_G1_ADD: Self = Self(54);
    pub const BLS12_381_G1_NEG: Self = Self(55);
    pub const BLS12_381_G1_SCALAR_MUL: Self = Self(56);
    pub const BLS12_381_G1_EQUAL: Self = Self(57);
    pub const BLS12_381_G1_COMPRESS: Self = Self(58);
    pub const BLS12_381_G1_UNCOMPRESS: Self = Self(59);
    pub const BLS12_381_G1_HASH_TO_GROUP: Self = Self(60);
    pub const BLS12_381_G2_ADD: Self = Self(61);
    pub const BLS12_381_G2_NEG: Self = Self(62);
    pub const BLS12_381_G2_SCALAR_MUL: Self = Self(63);
    pub const BLS12_381_G2_EQUAL: Self = Self(64);
    pub const BLS12_381_G2_COMPRESS: Self = Self(65);
    pub const BLS12_381_G2_UNCOMPRESS: Self = Self(66);
    pub const BLS12_381_G2_HASH_TO_GROUP: Self = Self(67);
    pub const BLS12_381_MILLER_LOOP: Self = Self(68);
    pub const BLS12_381_MUL_ML_RESULT: Self = Self(69);
    pub const BLS12_381_FINAL_VERIFY: Self = Self(70);
    pub const BLS12_381_G1_MULTI_SCALAR_MUL: Self = Self(92);
    pub const BLS12_381_G2_MULTI_SCALAR_MUL: Self = Self(93);
    pub const APPEND_STRING: Self = Self(22);
    pub const EQUALS_STRING: Self = Self(23);
    pub const ENCODE_UTF8: Self = Self(24);
    pub const DECODE_UTF8: Self = Self(25);
    pub const IF_THEN_ELSE: Self = Self(26);
    pub const CHOOSE_UNIT: Self = Self(27);
    pub const TRACE: Self = Self(28);
    pub const FST_PAIR: Self = Self(29);
    pub const SND_PAIR: Self = Self(30);
    pub const CHOOSE_LIST: Self = Self(31);
    pub const MK_CONS: Self = Self(32);
    pub const HEAD_LIST: Self = Self(33);
    pub const TAIL_LIST: Self = Self(34);
    pub const NULL_LIST: Self = Self(35);
    pub const CHOOSE_DATA: Self = Self(36);
    pub const CONSTR_DATA: Self = Self(37);
    pub const MAP_DATA: Self = Self(38);
    pub const LIST_DATA: Self = Self(39);
    pub const I_DATA: Self = Self(40);
    pub const B_DATA: Self = Self(41);
    pub const UN_CONSTR_DATA: Self = Self(42);
    pub const UN_MAP_DATA: Self = Self(43);
    pub const UN_LIST_DATA: Self = Self(44);
    pub const UN_I_DATA: Self = Self(45);
    pub const UN_B_DATA: Self = Self(46);
    pub const EQUALS_DATA: Self = Self(47);
    pub const SERIALISE_DATA: Self = Self(51);
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConstantType {
    Integer,
    ByteString,
    String,
    Unit,
    Bool,
    Data,
    Bls12_381G1Element,
    Bls12_381G2Element,
    Bls12_381MlResult,
    List(Box<ConstantType>),
    Array(Box<ConstantType>),
    Pair(Box<ConstantType>, Box<ConstantType>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Constant {
    Integer(BigInt),
    ByteString(Vec<u8>),
    String(String),
    Unit,
    Bool(bool),
    Data(Data),
    Bls12_381G1Element(G1Affine),
    Bls12_381G2Element(G2Affine),
    Bls12_381MlResult(Gt),
    List(Vec<Constant>),
    Array(Vec<Constant>),
    Pair(Box<Constant>, Box<Constant>),
}

impl Constant {
    pub fn as_integer(&self) -> Option<&BigInt> {
        match self {
            Self::Integer(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::ByteString(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&Data> {
        match self {
            Self::Data(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&Vec<Constant>> {
        match self {
            Self::List(values) => Some(values),
            _ => None,
        }
    }

    pub fn as_pair(&self) -> Option<(&Constant, &Constant)> {
        match self {
            Self::Pair(first, second) => Some((first, second)),
            _ => None,
        }
    }

    pub fn as_bls12_381_g1_element(&self) -> Option<&G1Affine> {
        match self {
            Self::Bls12_381G1Element(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_bls12_381_g2_element(&self) -> Option<&G2Affine> {
        match self {
            Self::Bls12_381G2Element(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_bls12_381_ml_result(&self) -> Option<&Gt> {
        match self {
            Self::Bls12_381MlResult(value) => Some(value),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Term {
    Var(usize),
    Lam(Rc<Term>),
    Apply(Rc<Term>, Rc<Term>),
    Delay(Rc<Term>),
    Force(Rc<Term>),
    Constant(Constant),
    Builtin(Builtin),
    Error,
    Constr(u64, Vec<Rc<Term>>),
    Case(Rc<Term>, Vec<Rc<Term>>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Program {
    pub version: Version,
    pub term: Rc<Term>,
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn hex_decode(input: &str) -> Option<Vec<u8>> {
    let trimmed = input
        .strip_prefix("0x")
        .or_else(|| input.strip_prefix('#'))
        .unwrap_or(input);
    if !trimmed.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    let bytes = trimmed.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let hi = hex_value(bytes[index])?;
        let lo = hex_value(bytes[index + 1])?;
        out.push((hi << 4) | lo);
        index += 2;
    }
    Some(out)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
