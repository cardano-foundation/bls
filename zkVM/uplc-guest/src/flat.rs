use alloc::{boxed::Box, rc::Rc, string::String, vec::Vec};
use core::fmt;
use num_bigint::BigInt;
use num_traits::{One, Zero};

use crate::data::{decode_cbor, DataError};
use crate::term::{Builtin, Constant, ConstantType, Program, Term, Version};

const TERM_TAG_WIDTH: usize = 4;
const CONST_TAG_WIDTH: usize = 4;
const BUILTIN_TAG_WIDTH: usize = 7;

const TAG_VAR: u8 = 0;
const TAG_DELAY: u8 = 1;
const TAG_LAMBDA: u8 = 2;
const TAG_APPLY: u8 = 3;
const TAG_CONSTANT: u8 = 4;
const TAG_FORCE: u8 = 5;
const TAG_ERROR: u8 = 6;
const TAG_BUILTIN: u8 = 7;
const TAG_CONSTR: u8 = 8;
const TAG_CASE: u8 = 9;

const CONST_INTEGER: u8 = 0;
const CONST_BYTE_STRING: u8 = 1;
const CONST_STRING: u8 = 2;
const CONST_UNIT: u8 = 3;
const CONST_BOOL: u8 = 4;
const CONST_DATA: u8 = 8;
const CONST_LIST_ONE: u8 = 7;
const CONST_LIST_TWO: u8 = 5;
const CONST_ARRAY_ONE: u8 = 7;
const CONST_ARRAY_TWO: u8 = 12;
const CONST_PAIR_ONE: u8 = 7;
const CONST_PAIR_TWO: u8 = 7;
const CONST_PAIR_THREE: u8 = 6;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    NotEnoughBits(usize),
    NotEnoughBytes(usize),
    NotByteAligned,
    IncorrectNumBits,
    UnknownTermTag(u8),
    UnknownConstantTag(u8),
    MissingTypeTag,
    UnknownTypeTags(Vec<u8>),
    InvalidUtf8,
    UnknownBuiltin(u8),
    Data(DataError),
    UnsupportedConstantType,
    IntegerOutOfRange,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnoughBits(bits) => write!(f, "not enough bits: needed {bits}"),
            Self::NotEnoughBytes(bytes) => write!(f, "not enough bytes: needed {bytes}"),
            Self::NotByteAligned => write!(f, "buffer is not byte aligned"),
            Self::IncorrectNumBits => write!(f, "cannot read more than 8 bits at once"),
            Self::UnknownTermTag(tag) => write!(f, "unknown term tag {tag}"),
            Self::UnknownConstantTag(tag) => write!(f, "unknown constant tag {tag}"),
            Self::MissingTypeTag => write!(f, "missing constant type tag"),
            Self::UnknownTypeTags(tags) => write!(f, "unknown constant type tags {tags:?}"),
            Self::InvalidUtf8 => write!(f, "invalid UTF-8 string constant"),
            Self::UnknownBuiltin(tag) => write!(f, "unknown builtin tag {tag}"),
            Self::Data(error) => write!(f, "invalid Plutus Data CBOR: {error:?}"),
            Self::UnsupportedConstantType => {
                write!(f, "constant type is not supported by this evaluator")
            }
            Self::IntegerOutOfRange => write!(f, "integer does not fit the target word size"),
        }
    }
}

impl From<DataError> for DecodeError {
    fn from(value: DataError) -> Self {
        Self::Data(value)
    }
}

pub fn decode(bytes: &[u8]) -> Result<Program, DecodeError> {
    let bytes = unwrap_cbor(bytes)?;
    let mut decoder = Decoder::new(bytes);
    let major = decoder.word()?;
    let minor = decoder.word()?;
    let patch = decoder.word()?;
    let term = decode_term(&mut decoder)?;
    decoder.filler()?;
    Ok(Program {
        version: Version {
            major,
            minor,
            patch,
        },
        term,
    })
}

fn unwrap_cbor(bytes: &[u8]) -> Result<&[u8], DecodeError> {
    let Some(&initial) = bytes.first() else {
        return Err(DecodeError::NotEnoughBytes(1));
    };
    if initial >> 5 != 2 {
        return Ok(bytes);
    }

    let info = initial & 0x1f;
    let (length, header_len): (usize, usize) = match info {
        0..=23 => (info as usize, 1),
        24 => {
            let value = *bytes.get(1).ok_or(DecodeError::NotEnoughBytes(2))?;
            (value as usize, 2)
        }
        25 => {
            let value = bytes.get(1..3).ok_or(DecodeError::NotEnoughBytes(3))?;
            (u16::from_be_bytes([value[0], value[1]]) as usize, 3)
        }
        26 => {
            let value = bytes.get(1..5).ok_or(DecodeError::NotEnoughBytes(5))?;
            (
                u32::from_be_bytes([value[0], value[1], value[2], value[3]]) as usize,
                5,
            )
        }
        27 => {
            let value = bytes.get(1..9).ok_or(DecodeError::NotEnoughBytes(9))?;
            let length = u64::from_be_bytes([
                value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
            ]);
            (
                usize::try_from(length).map_err(|_| DecodeError::IntegerOutOfRange)?,
                9,
            )
        }
        _ => return Err(DecodeError::UnsupportedConstantType),
    };

    let end = header_len
        .checked_add(length)
        .ok_or(DecodeError::NotEnoughBytes(length))?;
    let payload = bytes
        .get(header_len..end)
        .ok_or(DecodeError::NotEnoughBytes(length))?;
    Ok(payload)
}

fn decode_term(decoder: &mut Decoder<'_>) -> Result<Rc<Term>, DecodeError> {
    let tag = decoder.bits8(TERM_TAG_WIDTH)?;
    match tag {
        TAG_VAR => Ok(Rc::new(Term::Var(decoder.word_usize()?))),
        TAG_DELAY => Ok(Rc::new(Term::Delay(decode_term(decoder)?))),
        TAG_LAMBDA => Ok(Rc::new(Term::Lam(decode_term(decoder)?))),
        TAG_APPLY => {
            let function = decode_term(decoder)?;
            let argument = decode_term(decoder)?;
            Ok(Rc::new(Term::Apply(function, argument)))
        }
        TAG_CONSTANT => Ok(Rc::new(Term::Constant(decode_constant(decoder)?))),
        TAG_FORCE => Ok(Rc::new(Term::Force(decode_term(decoder)?))),
        TAG_ERROR => Ok(Rc::new(Term::Error)),
        TAG_BUILTIN => {
            let tag = decoder.bits8(BUILTIN_TAG_WIDTH)?;
            Ok(Rc::new(Term::Builtin(Builtin(tag))))
        }
        TAG_CONSTR => {
            let tag = decoder.word()?;
            let fields = decoder.list_with(decode_term)?;
            Ok(Rc::new(Term::Constr(tag, fields)))
        }
        TAG_CASE => {
            let constr = decode_term(decoder)?;
            let branches = decoder.list_with(decode_term)?;
            Ok(Rc::new(Term::Case(constr, branches)))
        }
        other => Err(DecodeError::UnknownTermTag(other)),
    }
}

fn decode_constant(decoder: &mut Decoder<'_>) -> Result<Constant, DecodeError> {
    let tags = decoder.list_with(|decoder| decoder.bits8(CONST_TAG_WIDTH))?;
    let (constant_type, _) = type_from_tags(&tags)?;
    decode_constant_with_type(decoder, &constant_type)
}

fn type_from_tags(tags: &[u8]) -> Result<(ConstantType, usize), DecodeError> {
    match tags {
        [CONST_INTEGER, ..] => Ok((ConstantType::Integer, 1)),
        [CONST_BYTE_STRING, ..] => Ok((ConstantType::ByteString, 1)),
        [CONST_STRING, ..] => Ok((ConstantType::String, 1)),
        [CONST_UNIT, ..] => Ok((ConstantType::Unit, 1)),
        [CONST_BOOL, ..] => Ok((ConstantType::Bool, 1)),
        [CONST_DATA, ..] => Ok((ConstantType::Data, 1)),
        [9, ..] => Ok((ConstantType::Bls12_381G1Element, 1)),
        [10, ..] => Ok((ConstantType::Bls12_381G2Element, 1)),
        [11, ..] => Ok((ConstantType::Bls12_381MlResult, 1)),
        [CONST_LIST_ONE, CONST_LIST_TWO, rest @ ..] => {
            let (inner, consumed) = type_from_tags(rest)?;
            Ok((ConstantType::List(Box::new(inner)), 2 + consumed))
        }
        [CONST_ARRAY_ONE, CONST_ARRAY_TWO, rest @ ..] => {
            let (inner, consumed) = type_from_tags(rest)?;
            Ok((ConstantType::Array(Box::new(inner)), 2 + consumed))
        }
        [CONST_PAIR_ONE, CONST_PAIR_TWO, CONST_PAIR_THREE, rest @ ..] => {
            let (first, consumed_first) = type_from_tags(rest)?;
            let (second, consumed_second) = type_from_tags(&rest[consumed_first..])?;
            Ok((
                ConstantType::Pair(Box::new(first), Box::new(second)),
                3 + consumed_first + consumed_second,
            ))
        }
        [] => Err(DecodeError::MissingTypeTag),
        other => Err(DecodeError::UnknownTypeTags(other.to_vec())),
    }
}

fn decode_constant_with_type(
    decoder: &mut Decoder<'_>,
    constant_type: &ConstantType,
) -> Result<Constant, DecodeError> {
    match constant_type {
        ConstantType::Integer => Ok(Constant::Integer(decoder.integer()?)),
        ConstantType::ByteString => Ok(Constant::ByteString(decoder.bytes()?)),
        ConstantType::String => {
            let bytes = decoder.bytes()?;
            let string = String::from_utf8(bytes).map_err(|_| DecodeError::InvalidUtf8)?;
            Ok(Constant::String(string))
        }
        ConstantType::Unit => Ok(Constant::Unit),
        ConstantType::Bool => Ok(Constant::Bool(decoder.bit()?)),
        ConstantType::Bls12_381G1Element
        | ConstantType::Bls12_381G2Element
        | ConstantType::Bls12_381MlResult => Err(DecodeError::UnsupportedConstantType),
        ConstantType::Data => {
            let bytes = decoder.bytes()?;
            Ok(Constant::Data(decode_cbor(&bytes)?))
        }
        ConstantType::List(inner) => {
            let values = decoder.list_with(|decoder| decode_constant_with_type(decoder, inner))?;
            Ok(Constant::List(values))
        }
        ConstantType::Array(inner) => {
            let values = decoder.list_with(|decoder| decode_constant_with_type(decoder, inner))?;
            Ok(Constant::Array(values))
        }
        ConstantType::Pair(first, second) => {
            let first = decode_constant_with_type(decoder, first)?;
            let second = decode_constant_with_type(decoder, second)?;
            Ok(Constant::Pair(Box::new(first), Box::new(second)))
        }
    }
}

struct Decoder<'a> {
    bytes: &'a [u8],
    pos: usize,
    used_bits: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pos: 0,
            used_bits: 0,
        }
    }

    fn word(&mut self) -> Result<u64, DecodeError> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.bits8(8)?;
            let part = (byte & 0x7f) as u64;
            value |= part
                .checked_shl(shift)
                .ok_or(DecodeError::IntegerOutOfRange)?;
            shift += 7;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
    }

    fn word_usize(&mut self) -> Result<usize, DecodeError> {
        usize::try_from(self.word()?).map_err(|_| DecodeError::IntegerOutOfRange)
    }

    fn big_word(&mut self) -> Result<BigInt, DecodeError> {
        let mut value = BigInt::zero();
        let mut shift = 0u32;
        loop {
            let byte = self.bits8(8)?;
            let part = BigInt::from((byte & 0x7f) as u64);
            value |= part << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
    }

    fn integer(&mut self) -> Result<BigInt, DecodeError> {
        let encoded = self.big_word()?;
        let odd = (&encoded & BigInt::one()) == BigInt::one();
        let half: BigInt = &encoded >> 1u32;
        Ok(if odd { -half - 1 } else { half })
    }

    fn list_with<T, F>(&mut self, mut decode: F) -> Result<Vec<T>, DecodeError>
    where
        F: FnMut(&mut Self) -> Result<T, DecodeError>,
    {
        let mut values = Vec::new();
        while self.bit()? {
            values.push(decode(self)?);
        }
        Ok(values)
    }

    fn bits8(&mut self, num_bits: usize) -> Result<u8, DecodeError> {
        if num_bits > 8 {
            return Err(DecodeError::IncorrectNumBits);
        }
        self.ensure_bits(num_bits)?;
        let unused_bits = 8 - self.used_bits;
        let leading_zeroes = 8 - num_bits;
        let current = self.bytes[self.pos] << self.used_bits;
        let mut result = current >> leading_zeroes;
        if num_bits > unused_bits {
            result |= self.bytes[self.pos + 1] >> (unused_bits + leading_zeroes);
        }
        self.drop_bits(num_bits);
        Ok(result)
    }

    fn bit(&mut self) -> Result<bool, DecodeError> {
        if self.pos >= self.bytes.len() {
            return Err(DecodeError::NotEnoughBits(1));
        }
        let bit = self.bytes[self.pos] & (0x80 >> self.used_bits) != 0;
        if self.used_bits == 7 {
            self.pos += 1;
            self.used_bits = 0;
        } else {
            self.used_bits += 1;
        }
        Ok(bit)
    }

    fn filler(&mut self) -> Result<(), DecodeError> {
        while !self.bit()? {}
        Ok(())
    }

    fn bytes(&mut self) -> Result<Vec<u8>, DecodeError> {
        self.filler()?;
        self.byte_array()
    }

    fn byte_array(&mut self) -> Result<Vec<u8>, DecodeError> {
        if self.used_bits != 0 {
            return Err(DecodeError::NotByteAligned);
        }
        let mut output = Vec::new();
        loop {
            self.ensure_bytes(1)?;
            let len = self.bytes[self.pos] as usize;
            self.pos += 1;
            if len == 0 {
                return Ok(output);
            }
            let chunk = self.take_bytes(len)?;
            output.extend_from_slice(chunk);
        }
    }

    fn ensure_bits(&self, required_bits: usize) -> Result<(), DecodeError> {
        let available = self
            .bytes
            .len()
            .saturating_sub(self.pos)
            .checked_mul(8)
            .ok_or(DecodeError::NotEnoughBits(required_bits))?;
        if required_bits > available.saturating_sub(self.used_bits) {
            return Err(DecodeError::NotEnoughBits(required_bits));
        }
        Ok(())
    }

    fn ensure_bytes(&self, required_bytes: usize) -> Result<(), DecodeError> {
        if required_bytes > self.bytes.len().saturating_sub(self.pos) {
            return Err(DecodeError::NotEnoughBytes(required_bytes));
        }
        Ok(())
    }

    fn take_bytes(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        self.ensure_bytes(len)?;
        let end = self.pos + len;
        let bytes = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn drop_bits(&mut self, num_bits: usize) {
        let total = num_bits + self.used_bits;
        self.used_bits = total % 8;
        self.pos += total / 8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO_HASH: &[u8] = include_bytes!("../../hello-world/hello_hash.flat");

    #[test]
    fn decodes_hello_hash() {
        let program = decode(HELLO_HASH).unwrap();
        assert_eq!(
            program.version,
            Version {
                major: 1,
                minor: 1,
                patch: 0
            }
        );
        match program.term.as_ref() {
            Term::Lam(body) => match body.as_ref() {
                Term::Apply(function, _) => match function.as_ref() {
                    Term::Builtin(builtin) => assert_eq!(*builtin, Builtin::SHA2_256),
                    other => panic!("unexpected function: {other:?}"),
                },
                other => panic!("unexpected lambda body: {other:?}"),
            },
            other => panic!("unexpected program term: {other:?}"),
        }
    }

    #[test]
    fn decodes_direct_bytestring_program() {
        let bytes = [
            0x01, 0x01, 0x00, 0x32, 0x37, 0x24, 0x00, 0x29, 0x11, 0x0d, 0x48, 0x65, 0x6c, 0x6c,
            0x6f, 0x2c, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x00, 0x01,
        ];
        let program = decode(&bytes).unwrap();
        match program.term.as_ref() {
            Term::Apply(function, argument) => {
                assert!(matches!(function.as_ref(), Term::Lam(_)));
                assert_eq!(
                    argument.as_ref(),
                    &Term::Constant(Constant::ByteString(b"Hello, world!".to_vec()))
                );
            }
            other => panic!("unexpected program term: {other:?}"),
        }
    }
}
