use alloc::{collections::VecDeque, format, rc::Rc, string::String, vec::Vec};
use core::fmt;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use sha2::{Digest, Sha256};

use crate::data::Data;
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
    UnsupportedBuiltin(u8),
    CaseTagOutOfRange(u64, usize),
    IndexOutOfRange,
    IntegerOutOfRange,
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
            Self::UnsupportedBuiltin(tag) => write!(f, "unsupported builtin {tag}"),
            Self::IndexOutOfRange => write!(f, "index out of range"),
            Self::IntegerOutOfRange => write!(f, "integer out of range"),
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
        | Builtin::LESS_THAN_EQUALS_BYTE_STRING => Some(2),
        Builtin::SHA2_256
        | Builtin::SHA3_256
        | Builtin::BLAKE2B_256
        | Builtin::LENGTH_OF_BYTE_STRING
        | Builtin::UN_B_DATA
        | Builtin::UN_I_DATA
        | Builtin::SERIALISE_DATA => Some(1),
        Builtin::INDEX_BYTE_STRING => Some(2),
        Builtin::SLICE_BYTE_STRING => Some(3),
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
        _ => Err(EvalError::UnsupportedBuiltin(fun.0)),
    }
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
}
