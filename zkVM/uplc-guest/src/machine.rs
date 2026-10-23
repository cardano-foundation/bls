use alloc::{collections::VecDeque, format, rc::Rc, string::String, vec::Vec};
use core::fmt;
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
    ExpectedData,
    UnsupportedBuiltin(u8),
    CaseTagOutOfRange(u64, usize),
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
            Self::ExpectedData => write!(f, "expected a data constant"),
            Self::UnsupportedBuiltin(tag) => write!(f, "unsupported builtin {tag}"),
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
        Builtin::SHA2_256 => Some(1),
        Builtin::UN_B_DATA => Some(1),
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
        _ => Err(EvalError::UnsupportedBuiltin(fun.0)),
    }
}
