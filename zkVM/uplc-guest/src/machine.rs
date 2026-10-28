use alloc::{boxed::Box, collections::VecDeque, format, rc::Rc, string::String, vec, vec::Vec};
use core::fmt;
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{ToPrimitive, Zero};
use blake2::Blake2b;
use bls12_381::{
    hash_to_curve::{ExpandMsgXmd, HashToCurve},
    pairing, G1Affine, G1Projective, G2Affine, G2Projective, Gt, Scalar,
};
use group::GroupEncoding;
use sha2::{Digest, Sha256};
use sha3::{Keccak256, Sha3_256};

use crate::data::{encode_cbor, Data};
use crate::flat::{decode, DecodeError};
use crate::term::{hex_encode, Builtin, Constant, Program, Term};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvalError {
    Decode(DecodeError),
    UnboundVariable(usize),
    NotAFunction,
    NotADelay,
    NotAConstr,
    ExpectedByteString,
    ExpectedInteger,
    ExpectedData,
    ExpectedBool,
    UnsupportedBuiltin(u8),
    CaseTagOutOfRange(u64, usize),
    IndexOutOfRange,
    IntegerOutOfRange,
    DivisionByZero,
    ExplicitError,
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Decode(error) => write!(f, "decode error: {error}"),
            Self::UnboundVariable(index) => write!(f, "unbound variable {index}"),
            Self::NotAFunction => write!(f, "attempted to apply a non-function"),
            Self::NotADelay => write!(f, "attempted to force a non-delayed term"),
            Self::NotAConstr => write!(f, "case scrutinee is not a constructor"),
            Self::ExpectedByteString => write!(f, "expected a bytestring constant"),
            Self::ExpectedInteger => write!(f, "expected an integer constant"),
            Self::ExpectedData => write!(f, "expected a data constant"),
            Self::ExpectedBool => write!(f, "expected a bool constant"),
            Self::UnsupportedBuiltin(tag) => write!(f, "unsupported builtin {tag}"),
            Self::IndexOutOfRange => write!(f, "index out of range"),
            Self::IntegerOutOfRange => write!(f, "integer out of range"),
            Self::DivisionByZero => write!(f, "division by zero"),
            Self::CaseTagOutOfRange(tag, branches) => {
                write!(f, "case tag {tag} out of range for {branches} branches")
            }
            Self::ExplicitError => write!(f, "script evaluated to error"),
        }
    }
}

impl From<DecodeError> for EvalError {
    fn from(value: DecodeError) -> Self {
        Self::Decode(value)
    }
}

#[derive(Clone)]
pub struct Env(Option<Rc<EnvNode>>);

struct EnvNode {
    value: Value,
    next: Env,
}

impl Env {
    fn empty() -> Self {
        Self(None)
    }

    fn cons(&self, value: Value) -> Self {
        Self(Some(Rc::new(EnvNode {
            value,
            next: self.clone(),
        })))
    }

    fn get(&self, index: usize) -> Result<Value, EvalError> {
        if index == 0 {
            return Err(EvalError::UnboundVariable(index));
        }
        let mut current = self;
        let mut remaining = index;
        loop {
            let node = current
                .0
                .as_ref()
                .ok_or(EvalError::UnboundVariable(index))?;
            if remaining == 1 {
                return Ok(node.value.clone());
            }
            remaining -= 1;
            current = &node.next;
        }
    }
}

#[derive(Clone)]
pub enum Value {
    Con(Constant),
    Lam { body: Rc<Term>, env: Env },
    Builtin { fun: Builtin, args: Vec<Value> },
    Delay { body: Rc<Term>, env: Env },
    Constr { tag: u64, fields: Vec<Value> },
}

impl Value {
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::Con(Constant::ByteString(bytes)) => Some(bytes),
            _ => None,
        }
    }

    pub fn as_integer(&self) -> Option<&BigInt> {
        match self {
            Self::Con(Constant::Integer(value)) => Some(value),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Con(Constant::Bool(value)) => Some(*value),
            _ => None,
        }
    }

    pub fn as_bls12_381_g1_element(&self) -> Option<&G1Affine> {
        match self {
            Self::Con(Constant::Bls12_381G1Element(value)) => Some(value),
            _ => None,
        }
    }

    pub fn as_bls12_381_g2_element(&self) -> Option<&G2Affine> {
        match self {
            Self::Con(Constant::Bls12_381G2Element(value)) => Some(value),
            _ => None,
        }
    }

    pub fn as_bls12_381_ml_result(&self) -> Option<&Gt> {
        match self {
            Self::Con(Constant::Bls12_381MlResult(value)) => Some(value),
            _ => None,
        }
    }

    pub fn as_data(&self) -> Option<&Data> {
        match self {
            Self::Con(Constant::Data(value)) => Some(value),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&Vec<Constant>> {
        match self {
            Self::Con(Constant::List(values)) => Some(values),
            _ => None,
        }
    }

    pub fn as_pair(&self) -> Option<(&Constant, &Constant)> {
        match self {
            Self::Con(Constant::Pair(first, second)) => Some((first, second)),
            _ => None,
        }
    }

    pub fn to_hex_string(&self) -> Option<String> {
        self.as_bytes().map(hex_encode)
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Con(Constant::Integer(value)) => format!("{value}"),
            Self::Con(Constant::ByteString(bytes)) => format!("#{}", hex_encode(bytes)),
            Self::Con(Constant::String(value)) => format!("\"{value}\""),
            Self::Con(Constant::Bool(value)) => format!("{value}"),
            Self::Con(Constant::Unit) => "()".into(),
            Self::Con(Constant::Data(value)) => format!("{value:?}"),
            Self::Con(Constant::List(values)) => {
                let values: Vec<_> = values.iter().map(describe_constant).collect();
                format!("[{}]", values.join(", "))
            }
            Self::Con(Constant::Array(values)) => {
                let values: Vec<_> = values.iter().map(describe_constant).collect();
                format!("[{}]", values.join(", "))
            }
            Self::Con(Constant::Pair(first, second)) => {
                format!(
                    "({}, {})",
                    describe_constant(first),
                    describe_constant(second)
                )
            }
            Self::Con(Constant::Bls12_381G1Element(_)) => "<bls12_381_G1>".into(),
            Self::Con(Constant::Bls12_381G2Element(_)) => "<bls12_381_G2>".into(),
            Self::Con(Constant::Bls12_381MlResult(_)) => "<bls12_381_MlResult>".into(),
            Self::Lam { .. } => "<lambda>".into(),
            Self::Builtin { fun, .. } => format!("<builtin {}>", fun.0),
            Self::Delay { .. } => "<delay>".into(),
            Self::Constr { tag, fields } => {
                format!("Constr {tag} ({} fields)", fields.len())
            }
        }
    }
}

fn describe_constant(constant: &Constant) -> String {
    match constant {
        Constant::Integer(value) => format!("{value}"),
        Constant::ByteString(bytes) => format!("#{}", hex_encode(bytes)),
        Constant::String(value) => format!("\"{value}\""),
        Constant::Bool(value) => format!("{value}"),
        Constant::Unit => "()".into(),
        Constant::Data(value) => format!("{value:?}"),
        Constant::List(values) => {
            let values: Vec<_> = values.iter().map(describe_constant).collect();
            format!("[{}]", values.join(", "))
        }
        Constant::Array(values) => {
            let values: Vec<_> = values.iter().map(describe_constant).collect();
            format!("[{}]", values.join(", "))
        }
        Constant::Pair(first, second) => {
            format!(
                "({}, {})",
                describe_constant(first),
                describe_constant(second)
            )
        }
        Constant::Bls12_381G1Element(_) => "<bls12_381_G1>".into(),
        Constant::Bls12_381G2Element(_) => "<bls12_381_G2>".into(),
        Constant::Bls12_381MlResult(_) => "<bls12_381_MlResult>".into(),
    }
}

enum Control {
    Eval(Rc<Term>, Env),
    Return(Value),
}

enum Frame {
    ApplyArg {
        arg: Rc<Term>,
        env: Env,
    },
    ApplyFun {
        fun: Value,
    },
    Force,
    Constr {
        tag: u64,
        terms: Vec<Rc<Term>>,
        values: Vec<Value>,
        next: usize,
        env: Env,
    },
    Case {
        branches: Vec<Rc<Term>>,
        env: Env,
    },
    ApplyArgs {
        args: VecDeque<Value>,
    },
}

pub fn eval(program: &Program) -> Result<Value, EvalError> {
    evaluate(program.term.clone())
}

pub fn eval_flat(bytes: &[u8], args: &[Data]) -> Result<Value, EvalError> {
    let program = decode(bytes)?;
    let mut term = program.term;
    for arg in args {
        term = Rc::new(Term::Apply(
            term,
            Rc::new(Term::Constant(Constant::Data(arg.clone()))),
        ));
    }
    evaluate(term)
}

fn evaluate(term: Rc<Term>) -> Result<Value, EvalError> {
    let mut control = Control::Eval(term, Env::empty());
    let mut stack: Vec<Frame> = Vec::new();

    loop {
        match control {
            Control::Eval(term, env) => match term.as_ref() {
                Term::Var(index) => control = Control::Return(env.get(*index)?),
                Term::Lam(body) => {
                    control = Control::Return(Value::Lam {
                        body: body.clone(),
                        env,
                    })
                }
                Term::Apply(function, argument) => {
                    stack.push(Frame::ApplyArg {
                        arg: argument.clone(),
                        env: env.clone(),
                    });
                    control = Control::Eval(function.clone(), env);
                }
                Term::Delay(body) => {
                    control = Control::Return(Value::Delay {
                        body: body.clone(),
                        env,
                    })
                }
                Term::Force(inner) => {
                    stack.push(Frame::Force);
                    control = Control::Eval(inner.clone(), env);
                }
                Term::Constant(constant) => control = Control::Return(Value::Con(constant.clone())),
                Term::Builtin(fun) => {
                    control = Control::Return(Value::Builtin {
                        fun: *fun,
                        args: Vec::new(),
                    })
                }
                Term::Error => return Err(EvalError::ExplicitError),
                Term::Constr(tag, fields) => {
                    if fields.is_empty() {
                        control = Control::Return(Value::Constr {
                            tag: *tag,
                            fields: Vec::new(),
                        });
                    } else {
                        stack.push(Frame::Constr {
                            tag: *tag,
                            terms: fields.clone(),
                            values: Vec::with_capacity(fields.len()),
                            next: 1,
                            env: env.clone(),
                        });
                        control = Control::Eval(fields[0].clone(), env);
                    }
                }
                Term::Case(scrutinee, branches) => {
                    stack.push(Frame::Case {
                        branches: branches.clone(),
                        env: env.clone(),
                    });
                    control = Control::Eval(scrutinee.clone(), env);
                }
            },
            Control::Return(value) => {
                let Some(frame) = stack.pop() else {
                    return Ok(value);
                };
                match frame {
                    Frame::ApplyArg { arg, env } => {
                        stack.push(Frame::ApplyFun { fun: value });
                        control = Control::Eval(arg, env);
                    }
                    Frame::ApplyFun { fun } => {
                        control = apply(fun, value)?;
                    }
                    Frame::Force => match value {
                        Value::Delay { body, env } => control = Control::Eval(body, env),
                        _ => return Err(EvalError::NotADelay),
                    },
                    Frame::Constr {
                        tag,
                        terms,
                        mut values,
                        next,
                        env,
                    } => {
                        values.push(value);
                        if next < terms.len() {
                            let term = terms[next].clone();
                            stack.push(Frame::Constr {
                                tag,
                                terms,
                                values,
                                next: next + 1,
                                env: env.clone(),
                            });
                            control = Control::Eval(term, env);
                        } else {
                            control = Control::Return(Value::Constr {
                                tag,
                                fields: values,
                            });
                        }
                    }
                    Frame::Case { branches, env } => match value {
                        Value::Constr { tag, fields } => {
                            let branch = branches
                                .get(tag as usize)
                                .ok_or(EvalError::CaseTagOutOfRange(tag, branches.len()))?
                                .clone();
                            if fields.is_empty() {
                                control = Control::Eval(branch, env);
                            } else {
                                stack.push(Frame::ApplyArgs {
                                    args: fields.into(),
                                });
                                control = Control::Eval(branch, env);
                            }
                        }
                        _ => return Err(EvalError::NotAConstr),
                    },
                    Frame::ApplyArgs { mut args } => {
                        let arg = args.pop_front().unwrap();
                        if !args.is_empty() {
                            stack.push(Frame::ApplyArgs { args });
                        }
                        control = apply(value, arg)?;
                    }
                }
            }
        }
    }
}

fn apply(fun: Value, arg: Value) -> Result<Control, EvalError> {
    match fun {
        Value::Lam { body, env } => Ok(Control::Eval(body, env.cons(arg))),
        Value::Builtin { fun, mut args } => {
            args.push(arg);
            let arity = builtin_arity(fun).ok_or(EvalError::UnsupportedBuiltin(fun.0))?;
            if args.len() == arity {
                Ok(Control::Return(apply_builtin(fun, &args)?))
            } else {
                Ok(Control::Return(Value::Builtin { fun, args }))
            }
        }
        _ => Err(EvalError::NotAFunction),
    }
}

fn builtin_arity(fun: Builtin) -> Option<usize> {
    match fun {
        Builtin::ADD_INTEGER
        | Builtin::SUBTRACT_INTEGER
        | Builtin::MULTIPLY_INTEGER
        | Builtin::DIVIDE_INTEGER
        | Builtin::QUOTIENT_INTEGER
        | Builtin::REMAINDER_INTEGER
        | Builtin::MOD_INTEGER
        | Builtin::EQUALS_INTEGER
        | Builtin::LESS_THAN_INTEGER
        | Builtin::LESS_THAN_EQUALS_INTEGER
        | Builtin::APPEND_BYTE_STRING
        | Builtin::EQUALS_BYTE_STRING
        | Builtin::LESS_THAN_BYTE_STRING
        | Builtin::LESS_THAN_EQUALS_BYTE_STRING
        | Builtin::CONSTR_DATA
        | Builtin::EQUALS_DATA => Some(2),
        Builtin::SHA2_256
        | Builtin::SHA3_256
        | Builtin::BLAKE2B_256
        | Builtin::KECCAK_256
        | Builtin::BLAKE2B_224
        | Builtin::BLS12_381_G1_NEG
        | Builtin::BLS12_381_G1_COMPRESS
        | Builtin::BLS12_381_G1_UNCOMPRESS
        | Builtin::BLS12_381_G2_NEG
        | Builtin::BLS12_381_G2_COMPRESS
        | Builtin::BLS12_381_G2_UNCOMPRESS
        | Builtin::LENGTH_OF_BYTE_STRING
        | Builtin::UN_B_DATA
        | Builtin::UN_I_DATA
        | Builtin::UN_LIST_DATA
        | Builtin::UN_MAP_DATA
        | Builtin::UN_CONSTR_DATA
        | Builtin::B_DATA
        | Builtin::I_DATA
        | Builtin::LIST_DATA
        | Builtin::MAP_DATA
        | Builtin::SERIALISE_DATA => Some(1),
        Builtin::INDEX_BYTE_STRING => Some(2),
        Builtin::REPLICATE_BYTE => Some(2),
        Builtin::BLS12_381_G1_ADD
        | Builtin::BLS12_381_G1_EQUAL
        | Builtin::BLS12_381_G1_SCALAR_MUL
        | Builtin::BLS12_381_G2_ADD
        | Builtin::BLS12_381_G2_EQUAL
        | Builtin::BLS12_381_G2_SCALAR_MUL
        | Builtin::BLS12_381_MUL_ML_RESULT
        | Builtin::BLS12_381_G1_MULTI_SCALAR_MUL
        | Builtin::BLS12_381_G2_MULTI_SCALAR_MUL => Some(2),
        Builtin::XOR_BYTE_STRING => Some(3),
        Builtin::INTEGER_TO_BYTE_STRING => Some(3),
        Builtin::BLS12_381_G1_HASH_TO_GROUP
        | Builtin::BLS12_381_G2_HASH_TO_GROUP
        | Builtin::BLS12_381_MILLER_LOOP
        | Builtin::BLS12_381_FINAL_VERIFY => Some(2),
        Builtin::SLICE_BYTE_STRING => Some(3),
        Builtin::CHOOSE_DATA => Some(6),
        _ => None,
    }
}

fn apply_builtin(fun: Builtin, args: &[Value]) -> Result<Value, EvalError> {
    match fun {
        Builtin::SHA2_256 => {
            let bytes = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let digest = Sha256::digest(bytes);
            Ok(Value::Con(Constant::ByteString(digest.to_vec())))
        }
        Builtin::SHA3_256 => {
            let bytes = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let digest = Sha3_256::digest(bytes);
            Ok(Value::Con(Constant::ByteString(digest.to_vec())))
        }
        Builtin::KECCAK_256 => {
            let bytes = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let digest = Keccak256::digest(bytes);
            Ok(Value::Con(Constant::ByteString(digest.to_vec())))
        }
        Builtin::BLAKE2B_256 => {
            let bytes = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let digest = Blake2b::<blake2::digest::consts::U32>::digest(bytes);
            Ok(Value::Con(Constant::ByteString(digest.to_vec())))
        }
        Builtin::BLAKE2B_224 => {
            let bytes = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let digest = Blake2b::<blake2::digest::consts::U28>::digest(bytes);
            Ok(Value::Con(Constant::ByteString(digest.to_vec())))
        }
        Builtin::REPLICATE_BYTE => {
            let count = args[0]
                .as_integer()
                .ok_or(EvalError::ExpectedInteger)?
                .to_usize()
                .ok_or(EvalError::IntegerOutOfRange)?;
            let byte = args[1]
                .as_integer()
                .ok_or(EvalError::ExpectedInteger)?
                .to_u8()
                .ok_or(EvalError::IntegerOutOfRange)?;
            Ok(Value::Con(Constant::ByteString(vec![byte; count])))
        }
        Builtin::XOR_BYTE_STRING => {
            let pad = args[0].as_bool().ok_or(EvalError::ExpectedBool)?;
            let left = args[1].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let right = args[2].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let len = left.len().max(right.len());
            let mut result = vec![0u8; len];
            for i in 0..len {
                let l = if i < left.len() { left[i] } else { 0 };
                let r = if i < right.len() { right[i] } else { 0 };
                if !pad && (i >= left.len() || i >= right.len()) {
                    continue;
                }
                result[i] = l ^ r;
            }
            Ok(Value::Con(Constant::ByteString(result)))
        }
        Builtin::INTEGER_TO_BYTE_STRING => {
            let big_endian = args[0].as_bool().ok_or(EvalError::ExpectedBool)?;
            let length = args[1].as_integer().ok_or(EvalError::ExpectedInteger)?;
            let value = args[2].as_integer().ok_or(EvalError::ExpectedInteger)?;
            if value.sign() == num_bigint::Sign::Minus {
                return Err(EvalError::IntegerOutOfRange);
            }
            let length = length.to_usize().ok_or(EvalError::IntegerOutOfRange)?;
            let mut bytes = value.to_bytes_be().1;
            // Remove leading zero byte if present (Sign::NoSign produces [0])
            if bytes.len() == 1 && bytes[0] == 0 && value.sign() == num_bigint::Sign::NoSign {
                // keep as-is for length handling below
            }
            if length > 0 {
                if bytes.len() > length {
                    bytes = bytes.split_off(bytes.len() - length);
                } else if bytes.len() < length {
                    let mut padded = vec![0u8; length - bytes.len()];
                    padded.extend_from_slice(&bytes);
                    bytes = padded;
                }
            }
            if !big_endian {
                bytes.reverse();
            }
            Ok(Value::Con(Constant::ByteString(bytes)))
        }
        Builtin::BLS12_381_G1_ADD => {
            let a = args[0]
                .as_bls12_381_g1_element()
                .ok_or(EvalError::ExpectedData)?;
            let b = args[1]
                .as_bls12_381_g1_element()
                .ok_or(EvalError::ExpectedData)?;
            let result: G1Affine = (G1Projective::from(*a) + G1Projective::from(*b)).into();
            Ok(Value::Con(Constant::Bls12_381G1Element(result)))
        }
        Builtin::BLS12_381_G1_NEG => {
            let a = args[0]
                .as_bls12_381_g1_element()
                .ok_or(EvalError::ExpectedData)?;
            Ok(Value::Con(Constant::Bls12_381G1Element(-*a)))
        }
        Builtin::BLS12_381_G1_SCALAR_MUL => {
            let scalar = args[0]
                .as_integer()
                .ok_or(EvalError::ExpectedInteger)?;
            let point = args[1]
                .as_bls12_381_g1_element()
                .ok_or(EvalError::ExpectedData)?;
            let scalar_bytes = scalar_mod_bls_order(scalar)?;
            let scalar = Scalar::from_bytes(&scalar_bytes)
                .into_option()
                .ok_or(EvalError::IntegerOutOfRange)?;
            let result: G1Affine = (scalar * G1Projective::from(*point)).into();
            Ok(Value::Con(Constant::Bls12_381G1Element(result)))
        }
        Builtin::BLS12_381_G1_EQUAL => {
            let a = args[0]
                .as_bls12_381_g1_element()
                .ok_or(EvalError::ExpectedData)?;
            let b = args[1]
                .as_bls12_381_g1_element()
                .ok_or(EvalError::ExpectedData)?;
            Ok(Value::Con(Constant::Bool(a == b)))
        }
        Builtin::BLS12_381_G1_COMPRESS => {
            let a = args[0]
                .as_bls12_381_g1_element()
                .ok_or(EvalError::ExpectedData)?;
            Ok(Value::Con(Constant::ByteString(
                a.to_bytes().as_ref().to_vec(),
            )))
        }
        Builtin::BLS12_381_G1_UNCOMPRESS => {
            let bytes = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let array: [u8; 48] = bytes
                .try_into()
                .map_err(|_| EvalError::ExpectedByteString)?;
            let mut compressed = <G1Affine as GroupEncoding>::Repr::default();
            compressed.as_mut().copy_from_slice(&array);
            let point = G1Affine::from_bytes(&compressed)
                .into_option()
                .ok_or(EvalError::ExpectedByteString)?;
            Ok(Value::Con(Constant::Bls12_381G1Element(point)))
        }
        Builtin::BLS12_381_G1_HASH_TO_GROUP => {
            let msg = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let dst = args[1].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            if dst.len() > 255 {
                return Err(EvalError::IntegerOutOfRange);
            }
            let point: G1Affine = <G1Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&[msg], dst).into();
            Ok(Value::Con(Constant::Bls12_381G1Element(point)))
        }
        Builtin::BLS12_381_G2_ADD => {
            let a = args[0]
                .as_bls12_381_g2_element()
                .ok_or(EvalError::ExpectedData)?;
            let b = args[1]
                .as_bls12_381_g2_element()
                .ok_or(EvalError::ExpectedData)?;
            let result: G2Affine = (G2Projective::from(*a) + G2Projective::from(*b)).into();
            Ok(Value::Con(Constant::Bls12_381G2Element(result)))
        }
        Builtin::BLS12_381_G2_NEG => {
            let a = args[0]
                .as_bls12_381_g2_element()
                .ok_or(EvalError::ExpectedData)?;
            Ok(Value::Con(Constant::Bls12_381G2Element(-*a)))
        }
        Builtin::BLS12_381_G2_SCALAR_MUL => {
            let scalar = args[0]
                .as_integer()
                .ok_or(EvalError::ExpectedInteger)?;
            let point = args[1]
                .as_bls12_381_g2_element()
                .ok_or(EvalError::ExpectedData)?;
            let scalar_bytes = scalar_mod_bls_order(scalar)?;
            let scalar = Scalar::from_bytes(&scalar_bytes)
                .into_option()
                .ok_or(EvalError::IntegerOutOfRange)?;
            let result: G2Affine = (scalar * G2Projective::from(*point)).into();
            Ok(Value::Con(Constant::Bls12_381G2Element(result)))
        }
        Builtin::BLS12_381_G2_EQUAL => {
            let a = args[0]
                .as_bls12_381_g2_element()
                .ok_or(EvalError::ExpectedData)?;
            let b = args[1]
                .as_bls12_381_g2_element()
                .ok_or(EvalError::ExpectedData)?;
            Ok(Value::Con(Constant::Bool(a == b)))
        }
        Builtin::BLS12_381_G2_COMPRESS => {
            let a = args[0]
                .as_bls12_381_g2_element()
                .ok_or(EvalError::ExpectedData)?;
            Ok(Value::Con(Constant::ByteString(
                a.to_bytes().as_ref().to_vec(),
            )))
        }
        Builtin::BLS12_381_G2_UNCOMPRESS => {
            let bytes = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let array: [u8; 96] = bytes
                .try_into()
                .map_err(|_| EvalError::ExpectedByteString)?;
            let mut compressed = <G2Affine as GroupEncoding>::Repr::default();
            compressed.as_mut().copy_from_slice(&array);
            let point = G2Affine::from_bytes(&compressed)
                .into_option()
                .ok_or(EvalError::ExpectedByteString)?;
            Ok(Value::Con(Constant::Bls12_381G2Element(point)))
        }
        Builtin::BLS12_381_G2_HASH_TO_GROUP => {
            let msg = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let dst = args[1].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            if dst.len() > 255 {
                return Err(EvalError::IntegerOutOfRange);
            }
            let point: G2Affine = <G2Projective as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(&[msg], dst).into();
            Ok(Value::Con(Constant::Bls12_381G2Element(point)))
        }
        Builtin::BLS12_381_MILLER_LOOP => {
            let p = args[0]
                .as_bls12_381_g1_element()
                .ok_or(EvalError::ExpectedData)?;
            let q = args[1]
                .as_bls12_381_g2_element()
                .ok_or(EvalError::ExpectedData)?;
            Ok(Value::Con(Constant::Bls12_381MlResult(pairing(p, q))))
        }
        Builtin::BLS12_381_MUL_ML_RESULT => {
            let a = args[0]
                .as_bls12_381_ml_result()
                .ok_or(EvalError::ExpectedData)?;
            let b = args[1]
                .as_bls12_381_ml_result()
                .ok_or(EvalError::ExpectedData)?;
            Ok(Value::Con(Constant::Bls12_381MlResult(*a + *b)))
        }
        Builtin::BLS12_381_FINAL_VERIFY => {
            let a = args[0]
                .as_bls12_381_ml_result()
                .ok_or(EvalError::ExpectedData)?;
            let b = args[1]
                .as_bls12_381_ml_result()
                .ok_or(EvalError::ExpectedData)?;
            Ok(Value::Con(Constant::Bool(a == b)))
        }
        Builtin::BLS12_381_G1_MULTI_SCALAR_MUL => {
            let scalars = args[0].as_list().ok_or(EvalError::ExpectedData)?;
            let points = args[1].as_list().ok_or(EvalError::ExpectedData)?;
            if scalars.len() != points.len() {
                return Err(EvalError::ExpectedData);
            }
            let mut result = G1Projective::identity();
            for (scalar, point) in scalars.iter().zip(points.iter()) {
                let s = scalar
                    .as_integer()
                    .ok_or(EvalError::ExpectedInteger)?;
                let p = point
                    .as_bls12_381_g1_element()
                    .ok_or(EvalError::ExpectedData)?;
                let scalar_bytes = scalar_mod_bls_order(s)?;
                let scalar = Scalar::from_bytes(&scalar_bytes)
                    .into_option()
                    .ok_or(EvalError::IntegerOutOfRange)?;
                result += scalar * G1Projective::from(*p);
            }
            Ok(Value::Con(Constant::Bls12_381G1Element(result.into())))
        }
        Builtin::BLS12_381_G2_MULTI_SCALAR_MUL => {
            let scalars = args[0].as_list().ok_or(EvalError::ExpectedData)?;
            let points = args[1].as_list().ok_or(EvalError::ExpectedData)?;
            if scalars.len() != points.len() {
                return Err(EvalError::ExpectedData);
            }
            let mut result = G2Projective::identity();
            for (scalar, point) in scalars.iter().zip(points.iter()) {
                let s = scalar
                    .as_integer()
                    .ok_or(EvalError::ExpectedInteger)?;
                let p = point
                    .as_bls12_381_g2_element()
                    .ok_or(EvalError::ExpectedData)?;
                let scalar_bytes = scalar_mod_bls_order(s)?;
                let scalar = Scalar::from_bytes(&scalar_bytes)
                    .into_option()
                    .ok_or(EvalError::IntegerOutOfRange)?;
                result += scalar * G2Projective::from(*p);
            }
            Ok(Value::Con(Constant::Bls12_381G2Element(result.into())))
        }
        Builtin::UN_B_DATA => match &args[0] {
            Value::Con(Constant::Data(Data::B(bytes))) => {
                Ok(Value::Con(Constant::ByteString(bytes.clone())))
            }
            Value::Con(Constant::Data(_)) => Err(EvalError::ExpectedByteString),
            _ => Err(EvalError::ExpectedData),
        },
        Builtin::APPEND_BYTE_STRING => {
            let left = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let right = args[1].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let mut result = Vec::with_capacity(left.len() + right.len());
            result.extend_from_slice(left);
            result.extend_from_slice(right);
            Ok(Value::Con(Constant::ByteString(result)))
        }
        Builtin::SLICE_BYTE_STRING => {
            let start = args[0]
                .as_integer()
                .ok_or(EvalError::ExpectedInteger)?
                .to_usize()
                .ok_or(EvalError::IntegerOutOfRange)?;
            let len = args[1]
                .as_integer()
                .ok_or(EvalError::ExpectedInteger)?
                .to_usize()
                .ok_or(EvalError::IntegerOutOfRange)?;
            let bytes = args[2].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let end = start.saturating_add(len).min(bytes.len());
            let start = start.min(bytes.len());
            Ok(Value::Con(Constant::ByteString(bytes[start..end].to_vec())))
        }
        Builtin::LENGTH_OF_BYTE_STRING => {
            let bytes = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            Ok(Value::Con(Constant::Integer(BigInt::from(bytes.len()))))
        }
        Builtin::INDEX_BYTE_STRING => {
            let bytes = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let index = args[1]
                .as_integer()
                .ok_or(EvalError::ExpectedInteger)?
                .to_usize()
                .ok_or(EvalError::IntegerOutOfRange)?;
            let byte = bytes.get(index).ok_or(EvalError::IndexOutOfRange)?;
            Ok(Value::Con(Constant::Integer(BigInt::from(*byte))))
        }
        Builtin::EQUALS_BYTE_STRING => {
            let left = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let right = args[1].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            Ok(Value::Con(Constant::Bool(left == right)))
        }
        Builtin::LESS_THAN_BYTE_STRING | Builtin::LESS_THAN_EQUALS_BYTE_STRING => {
            let left = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let right = args[1].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            let ordering = left.cmp(right);
            let result = if fun == Builtin::LESS_THAN_BYTE_STRING {
                ordering == core::cmp::Ordering::Less
            } else {
                ordering != core::cmp::Ordering::Greater
            };
            Ok(Value::Con(Constant::Bool(result)))
        }
        Builtin::ADD_INTEGER
        | Builtin::SUBTRACT_INTEGER
        | Builtin::MULTIPLY_INTEGER
        | Builtin::DIVIDE_INTEGER
        | Builtin::QUOTIENT_INTEGER
        | Builtin::REMAINDER_INTEGER
        | Builtin::MOD_INTEGER => {
            let left = args[0].as_integer().ok_or(EvalError::ExpectedInteger)?;
            let right = args[1].as_integer().ok_or(EvalError::ExpectedInteger)?;
            let result = match fun {
                Builtin::ADD_INTEGER => left + right,
                Builtin::SUBTRACT_INTEGER => left - right,
                Builtin::MULTIPLY_INTEGER => left * right,
                Builtin::DIVIDE_INTEGER | Builtin::QUOTIENT_INTEGER
                | Builtin::REMAINDER_INTEGER | Builtin::MOD_INTEGER => {
                    if right.is_zero() {
                        return Err(EvalError::DivisionByZero);
                    }
                    match fun {
                        Builtin::DIVIDE_INTEGER => left.div_floor(right),
                        Builtin::QUOTIENT_INTEGER => left / right,
                        Builtin::REMAINDER_INTEGER => left % right,
                        Builtin::MOD_INTEGER => left.mod_floor(right),
                        _ => unreachable!(),
                    }
                }
                _ => unreachable!(),
            };
            Ok(Value::Con(Constant::Integer(result)))
        }
        Builtin::EQUALS_INTEGER
        | Builtin::LESS_THAN_INTEGER
        | Builtin::LESS_THAN_EQUALS_INTEGER => {
            let left = args[0].as_integer().ok_or(EvalError::ExpectedInteger)?;
            let right = args[1].as_integer().ok_or(EvalError::ExpectedInteger)?;
            let result = match fun {
                Builtin::EQUALS_INTEGER => left == right,
                Builtin::LESS_THAN_INTEGER => left < right,
                Builtin::LESS_THAN_EQUALS_INTEGER => left <= right,
                _ => unreachable!(),
            };
            Ok(Value::Con(Constant::Bool(result)))
        }
        Builtin::B_DATA => {
            let bytes = args[0].as_bytes().ok_or(EvalError::ExpectedByteString)?;
            Ok(Value::Con(Constant::Data(Data::B(bytes.to_vec()))))
        }
        Builtin::I_DATA => {
            let value = args[0].as_integer().ok_or(EvalError::ExpectedInteger)?;
            Ok(Value::Con(Constant::Data(Data::I(value.clone()))))
        }
        Builtin::LIST_DATA => {
            let values = args[0].as_list().ok_or(EvalError::ExpectedData)?;
            let data = values
                .iter()
                .map(constant_to_data)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::Con(Constant::Data(Data::List(data))))
        }
        Builtin::MAP_DATA => {
            let entries = args[0].as_list().ok_or(EvalError::ExpectedData)?;
            let mut data = Vec::with_capacity(entries.len());
            for entry in entries {
                let (key, value) = constant_to_pair(entry)?;
                data.push((constant_to_data(key)?, constant_to_data(value)?));
            }
            Ok(Value::Con(Constant::Data(Data::Map(data))))
        }
        Builtin::CONSTR_DATA => {
            let tag = args[0]
                .as_integer()
                .ok_or(EvalError::ExpectedInteger)?
                .to_u64()
                .ok_or(EvalError::IntegerOutOfRange)?;
            let fields = args[1].as_list().ok_or(EvalError::ExpectedData)?;
            let data = fields
                .iter()
                .map(constant_to_data)
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Value::Con(Constant::Data(Data::Constr(tag, data))))
        }
        Builtin::UN_I_DATA => match args[0].as_data() {
            Some(Data::I(value)) => Ok(Value::Con(Constant::Integer(value.clone()))),
            Some(_) => Err(EvalError::ExpectedInteger),
            None => Err(EvalError::ExpectedData),
        },
        Builtin::UN_LIST_DATA => match args[0].as_data() {
            Some(Data::List(items)) => {
                let values = items.iter().map(data_to_constant).collect();
                Ok(Value::Con(Constant::List(values)))
            }
            Some(_) => Err(EvalError::ExpectedData),
            None => Err(EvalError::ExpectedData),
        },
        Builtin::UN_MAP_DATA => match args[0].as_data() {
            Some(Data::Map(entries)) => {
                let pairs = entries
                    .iter()
                    .map(|(k, v)| {
                        Constant::Pair(
                            Box::new(data_to_constant(k)),
                            Box::new(data_to_constant(v)),
                        )
                    })
                    .collect();
                Ok(Value::Con(Constant::List(pairs)))
            }
            Some(_) => Err(EvalError::ExpectedData),
            None => Err(EvalError::ExpectedData),
        },
        Builtin::UN_CONSTR_DATA => match args[0].as_data() {
            Some(Data::Constr(tag, fields)) => {
                let field_values = fields.iter().map(data_to_constant).collect();
                Ok(Value::Con(Constant::Pair(
                    Box::new(Constant::Integer(BigInt::from(*tag))),
                    Box::new(Constant::List(field_values)),
                )))
            }
            Some(_) => Err(EvalError::ExpectedData),
            None => Err(EvalError::ExpectedData),
        },
        Builtin::EQUALS_DATA => {
            let left = args[0].as_data().ok_or(EvalError::ExpectedData)?;
            let right = args[1].as_data().ok_or(EvalError::ExpectedData)?;
            Ok(Value::Con(Constant::Bool(left == right)))
        }
        Builtin::SERIALISE_DATA => {
            let data = args[0].as_data().ok_or(EvalError::ExpectedData)?;
            Ok(Value::Con(Constant::ByteString(encode_cbor(data))))
        }
        Builtin::CHOOSE_DATA => {
            let data = args[0].as_data().ok_or(EvalError::ExpectedData)?;
            let branch = match data {
                Data::Constr(_, _) => &args[1],
                Data::Map(_) => &args[2],
                Data::List(_) => &args[3],
                Data::I(_) => &args[4],
                Data::B(_) => &args[5],
            };
            Ok(branch.clone())
        }
        _ => Err(EvalError::UnsupportedBuiltin(fun.0)),
    }
}

fn constant_to_data(constant: &Constant) -> Result<Data, EvalError> {
    match constant {
        Constant::Data(data) => Ok(data.clone()),
        _ => Err(EvalError::ExpectedData),
    }
}

fn constant_to_pair(constant: &Constant) -> Result<(&Constant, &Constant), EvalError> {
    match constant {
        Constant::Pair(first, second) => Ok((first, second)),
        _ => Err(EvalError::ExpectedData),
    }
}

fn data_to_constant(data: &Data) -> Constant {
    Constant::Data(data.clone())
}

fn scalar_mod_bls_order(scalar: &BigInt) -> Result<[u8; 32], EvalError> {
    let order = BigInt::from_bytes_be(
        num_bigint::Sign::Plus,
        &[
            0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1,
            0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x01,
        ],
    );
    let reduced = scalar.mod_floor(&order);
    let (_, bytes) = reduced.to_bytes_le();
    let mut result = [0u8; 32];
    if bytes.len() > 32 {
        return Err(EvalError::IntegerOutOfRange);
    }
    result[..bytes.len()].copy_from_slice(&bytes);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::term::Version;

    fn const_bytes(bytes: &[u8]) -> Term {
        Term::Constant(Constant::ByteString(bytes.to_vec()))
    }

    fn const_int(value: i64) -> Term {
        Term::Constant(Constant::Integer(BigInt::from(value)))
    }

    fn const_bool(value: bool) -> Term {
        Term::Constant(Constant::Bool(value))
    }

    fn apply_builtin(fun: Builtin, args: &[Term]) -> Term {
        let mut term = Term::Builtin(fun);
        for arg in args {
            term = Term::Apply(alloc::rc::Rc::new(term), alloc::rc::Rc::new(arg.clone()));
        }
        term
    }

    #[test]
    fn append_byte_string() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::APPEND_BYTE_STRING,
                &[const_bytes(b"Hello, "), const_bytes(b"world!")],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_bytes(), Some(b"Hello, world!".as_slice()));
    }

    #[test]
    fn length_of_byte_string() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::LENGTH_OF_BYTE_STRING,
                &[const_bytes(b"Hello")],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_integer(), Some(&BigInt::from(5)));
    }

    #[test]
    fn index_byte_string() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::INDEX_BYTE_STRING,
                &[const_bytes(b"Hi"), const_int(1)],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_integer(), Some(&BigInt::from(b'i')));
    }

    #[test]
    fn slice_byte_string() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::SLICE_BYTE_STRING,
                &[const_int(1), const_int(3), const_bytes(b"Hello")],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_bytes(), Some(b"ell".as_slice()));
    }

    #[test]
    fn equals_byte_string() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::EQUALS_BYTE_STRING,
                &[const_bytes(b"abc"), const_bytes(b"abc")],
            )),
        };
        let value = eval(&program).unwrap();
        match value {
            Value::Con(Constant::Bool(true)) => {}
            other => panic!("expected true, got {}", other.describe()),
        }
    }

    #[test]
    fn less_than_byte_string() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::LESS_THAN_BYTE_STRING,
                &[const_bytes(b"abc"), const_bytes(b"abd")],
            )),
        };
        let value = eval(&program).unwrap();
        match value {
            Value::Con(Constant::Bool(true)) => {}
            other => panic!("expected true, got {}", other.describe()),
        }
    }

    #[test]
    fn add_integer_golden() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::ADD_INTEGER,
                &[const_int(7), const_int(-3)],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_integer(), Some(&BigInt::from(4)));
    }

    #[test]
    fn multiply_integer_golden() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::MULTIPLY_INTEGER,
                &[const_int(-6), const_int(7)],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_integer(), Some(&BigInt::from(-42)));
    }

    #[test]
    fn divide_and_quotient_integer_distinction() {
        // Euclidean division: -7 div 3 = -3 (floor)
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::DIVIDE_INTEGER,
                &[const_int(-7), const_int(3)],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_integer(), Some(&BigInt::from(-3)));

        // Truncated division: -7 quot 3 = -2
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::QUOTIENT_INTEGER,
                &[const_int(-7), const_int(3)],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_integer(), Some(&BigInt::from(-2)));
    }

    #[test]
    fn mod_and_remainder_integer_distinction() {
        // Euclidean mod: -7 mod 3 = 2
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::MOD_INTEGER,
                &[const_int(-7), const_int(3)],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_integer(), Some(&BigInt::from(2)));

        // Truncated remainder: -7 rem 3 = -1
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::REMAINDER_INTEGER,
                &[const_int(-7), const_int(3)],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_integer(), Some(&BigInt::from(-1)));
    }

    #[test]
    fn integer_arithmetic_property() {
        // (a + b) - b == a
        for a in [-100, -1, 0, 1, 100] {
            for b in [-53, -7, 0, 7, 53] {
                let add = apply_builtin(Builtin::ADD_INTEGER, &[const_int(a), const_int(b)]);
                let program = Program {
                    version: Version {
                        major: 1,
                        minor: 1,
                        patch: 0,
                    },
                    term: alloc::rc::Rc::new(apply_builtin(
                        Builtin::SUBTRACT_INTEGER,
                        &[add, const_int(b)],
                    )),
                };
                let value = eval(&program).unwrap();
                assert_eq!(value.as_integer(), Some(&BigInt::from(a)));
            }
        }
    }

    #[test]
    fn bytearray_append_length_property() {
        // length(append(a, b)) == length(a) + length(b)
        let sizes = [0, 1, 5, 23];
        for len_a in sizes {
            for len_b in sizes {
                let a = vec![0u8; len_a];
                let b = vec![1u8; len_b];
                let append = apply_builtin(
                    Builtin::APPEND_BYTE_STRING,
                    &[const_bytes(&a), const_bytes(&b)],
                );
                let program = Program {
                    version: Version {
                        major: 1,
                        minor: 1,
                        patch: 0,
                    },
                    term: alloc::rc::Rc::new(apply_builtin(
                        Builtin::LENGTH_OF_BYTE_STRING,
                        &[append],
                    )),
                };
                let value = eval(&program).unwrap();
                assert_eq!(
                    value.as_integer(),
                    Some(&BigInt::from(len_a + len_b)),
                    "append length mismatch for {} + {}",
                    len_a,
                    len_b
                );
            }
        }
    }

    #[test]
    fn slice_whole_byte_string_property() {
        // slice(0, len, bytes) == bytes
        for len in [0, 1, 5, 23] {
            let bytes = vec![7u8; len];
            let program = Program {
                version: Version {
                    major: 1,
                    minor: 1,
                    patch: 0,
                },
                term: alloc::rc::Rc::new(apply_builtin(
                    Builtin::SLICE_BYTE_STRING,
                    &[const_int(0), const_int(len as i64), const_bytes(&bytes)],
                )),
            };
            let value = eval(&program).unwrap();
            assert_eq!(value.as_bytes(), Some(bytes.as_slice()));
        }
    }

    fn const_data(data: Data) -> Term {
        Term::Constant(Constant::Data(data))
    }

    fn const_list(items: Vec<Constant>) -> Term {
        Term::Constant(Constant::List(items))
    }

    #[test]
    fn b_data_roundtrip() {
        let data = Data::B(b"hello".to_vec());
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::UN_B_DATA,
                &[const_data(data)],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_bytes(), Some(b"hello".as_slice()));
    }

    #[test]
    fn i_data_roundtrip() {
        let data = Data::I(BigInt::from(-42));
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::UN_I_DATA,
                &[const_data(data)],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_integer(), Some(&BigInt::from(-42)));
    }

    fn hash_program(fun: Builtin, input: &[u8]) -> Value {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(fun, &[const_bytes(input)])),
        };
        eval(&program).unwrap()
    }

    #[test]
    fn sha2_256_empty() {
        let value = hash_program(Builtin::SHA2_256, b"");
        assert_eq!(
            value.as_bytes().map(hex_encode),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string())
        );
    }

    #[test]
    fn sha3_256_empty() {
        let value = hash_program(Builtin::SHA3_256, b"");
        assert_eq!(
            value.as_bytes().map(hex_encode),
            Some("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a".to_string())
        );
    }

    #[test]
    fn keccak_256_empty() {
        let value = hash_program(Builtin::KECCAK_256, b"");
        assert_eq!(
            value.as_bytes().map(hex_encode),
            Some("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470".to_string())
        );
    }

    #[test]
    fn blake2b_256_empty() {
        let value = hash_program(Builtin::BLAKE2B_256, b"");
        assert_eq!(
            value.as_bytes().map(hex_encode),
            Some("0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8".to_string())
        );
    }

    #[test]
    fn blake2b_224_empty() {
        let value = hash_program(Builtin::BLAKE2B_224, b"");
        assert_eq!(
            value.as_bytes().map(hex_encode),
            Some("836cc68931c2e4e3e838602eca1902591d216837bafddfe6f0c8cb07".to_string())
        );
    }

    #[test]
    fn replicate_byte() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: Rc::new(apply_builtin(
                Builtin::REPLICATE_BYTE,
                &[const_int(3), const_int(0xab)],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_bytes(), Some(vec![0xab, 0xab, 0xab].as_slice()));
    }

    #[test]
    fn xor_byte_string() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: Rc::new(apply_builtin(
                Builtin::XOR_BYTE_STRING,
                &[
                    const_bool(true),
                    const_bytes(&[0xff, 0x00]),
                    const_bytes(&[0x0f]),
                ],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_bytes(), Some(vec![0xf0, 0x00].as_slice()));
    }

    #[test]
    fn integer_to_byte_string_big_endian() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: Rc::new(apply_builtin(
                Builtin::INTEGER_TO_BYTE_STRING,
                &[const_bool(true), const_int(2), const_int(0x0102)],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_bytes(), Some(vec![0x01, 0x02].as_slice()));
    }

    #[test]
    fn integer_to_byte_string_little_endian() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: Rc::new(apply_builtin(
                Builtin::INTEGER_TO_BYTE_STRING,
                &[const_bool(false), const_int(2), const_int(0x0102)],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_bytes(), Some(vec![0x02, 0x01].as_slice()));
    }

    #[test]
    fn integer_to_byte_string_zero_padded() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: Rc::new(apply_builtin(
                Builtin::INTEGER_TO_BYTE_STRING,
                &[const_bool(true), const_int(4), const_int(0x0102)],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_bytes(), Some(vec![0x00, 0x00, 0x01, 0x02].as_slice()));
    }

    #[test]
    fn bls12_381_g1_compress_uncompress_roundtrip() {
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: Rc::new(apply_builtin(
                Builtin::BLS12_381_G1_UNCOMPRESS,
                &[const_bytes(G1Affine::generator().to_bytes().as_ref())],
            )),
        };
        let value = eval(&program).unwrap();
        let point = value.as_bls12_381_g1_element().unwrap();
        assert_eq!(*point, G1Affine::generator());
    }

    #[test]
    fn bls12_381_g1_scalar_mul_matches_double() {
        let gen = const_bytes(G1Affine::generator().to_bytes().as_ref());
        let gen_uncompressed = apply_builtin(Builtin::BLS12_381_G1_UNCOMPRESS, &[gen.clone()]);
        let double_add = apply_builtin(
            Builtin::BLS12_381_G1_ADD,
            &[gen_uncompressed.clone(), gen_uncompressed.clone()],
        );
        let double_mul = apply_builtin(
            Builtin::BLS12_381_G1_SCALAR_MUL,
            &[const_int(2), gen_uncompressed],
        );

        let add_program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: Rc::new(double_add),
        };
        let mul_program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: Rc::new(double_mul),
        };

        let add_value = eval(&add_program).unwrap();
        let mul_value = eval(&mul_program).unwrap();
        assert_eq!(
            add_value.as_bls12_381_g1_element(),
            mul_value.as_bls12_381_g1_element()
        );
    }

    #[test]
    fn bls12_381_pairing_generator_is_non_trivial() {
        let g1 = const_bytes(G1Affine::generator().to_bytes().as_ref());
        let g2 = const_bytes(G2Affine::generator().to_bytes().as_ref());
        let g1_uncompressed = apply_builtin(Builtin::BLS12_381_G1_UNCOMPRESS, &[g1]);
        let g2_uncompressed = apply_builtin(Builtin::BLS12_381_G2_UNCOMPRESS, &[g2]);
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: Rc::new(apply_builtin(
                Builtin::BLS12_381_MILLER_LOOP,
                &[g1_uncompressed, g2_uncompressed],
            )),
        };
        let value = eval(&program).unwrap();
        let result = value.as_bls12_381_ml_result().unwrap();
        assert_ne!(*result, Gt::identity());
    }

    #[test]
    fn list_data_roundtrip() {
        let data = Data::List(vec![Data::I(BigInt::from(1)), Data::I(BigInt::from(2))]);
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::UN_LIST_DATA,
                &[const_data(data)],
            )),
        };
        let value = eval(&program).unwrap();
        let items = value.as_list().unwrap();
        assert_eq!(items.len(), 2);
        match &items[0] {
            Constant::Data(Data::I(v)) => assert_eq!(v, &BigInt::from(1)),
            other => panic!("expected Data::I(1), got {other:?}"),
        }
        match &items[1] {
            Constant::Data(Data::I(v)) => assert_eq!(v, &BigInt::from(2)),
            other => panic!("expected Data::I(2), got {other:?}"),
        }
    }

    #[test]
    fn constr_data_roundtrip() {
        let data = Data::Constr(
            5,
            vec![Data::I(BigInt::from(1)), Data::B(b"x".to_vec())],
        );
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::UN_CONSTR_DATA,
                &[const_data(data)],
            )),
        };
        let value = eval(&program).unwrap();
        let (tag, fields) = value.as_pair().unwrap();
        assert_eq!(tag.as_integer(), Some(&BigInt::from(5)));
        let fields = fields.as_list().unwrap();
        assert_eq!(fields.len(), 2);
        match &fields[0] {
            Constant::Data(Data::I(v)) => assert_eq!(v, &BigInt::from(1)),
            other => panic!("expected Data::I(1), got {other:?}"),
        }
        match &fields[1] {
            Constant::Data(Data::B(v)) => assert_eq!(v, b"x"),
            other => panic!("expected Data::B(x), got {other:?}"),
        }
    }

    #[test]
    fn equals_data() {
        let a = Data::B(b"x".to_vec());
        let b = Data::B(b"x".to_vec());
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::EQUALS_DATA,
                &[const_data(a), const_data(b)],
            )),
        };
        let value = eval(&program).unwrap();
        match value {
            Value::Con(Constant::Bool(true)) => {}
            other => panic!("expected true, got {}", other.describe()),
        }
    }

    #[test]
    fn serialise_data_roundtrip() {
        let data = Data::Constr(
            0,
            vec![
                Data::I(BigInt::from(42)),
                Data::B(b"hello".to_vec()),
                Data::List(vec![Data::I(BigInt::from(1))]),
            ],
        );
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::SERIALISE_DATA,
                &[const_data(data.clone())],
            )),
        };
        let value = eval(&program).unwrap();
        let bytes = value.as_bytes().unwrap();
        let decoded = crate::decode_cbor(bytes).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn choose_data_selects_branch() {
        let data = Data::I(BigInt::from(42));
        let program = Program {
            version: Version {
                major: 1,
                minor: 1,
                patch: 0,
            },
            term: alloc::rc::Rc::new(apply_builtin(
                Builtin::CHOOSE_DATA,
                &[
                    const_data(data),
                    const_int(0),
                    const_int(1),
                    const_int(2),
                    const_int(3),
                    const_int(4),
                ],
            )),
        };
        let value = eval(&program).unwrap();
        assert_eq!(value.as_integer(), Some(&BigInt::from(3)));
    }
}
