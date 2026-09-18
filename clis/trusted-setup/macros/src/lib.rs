//! [`ByteLayout`] derive: one Rust struct drives the byte ABI triple.
//!
//! The native backend crosses the FFI boundary as plain fixed-size byte
//! containers (`bls_backend_fr_t`, `bls_backend_g1_t`, ...).  Historically the
//! byte length, the C typedef name and (when used) the serialization were each
//! written by hand in three places (Rust struct, `bls_backend.h`, serde), so
//! they could drift apart.
//!
//! Deriving `ByteLayout` on `#[repr(C)] struct BlsFr(pub [u8; 32])` regenerates
//! all three from the single struct definition:
//!
//! ```text
//! #[derive(ByteLayout)]
//! #[byte_layout(c_name = "bls_backend_fr_t", serde)]
//! #[repr(C)]
//! pub struct BlsFr(pub [u8; 32]);
//! ```
//!
//! generates:
//! - `BYTE_LEN`, `zero()`, `as_bytes()`, `from_bytes()`, and `From` impls in
//!   both directions against `[u8; N]`;
//! - `C_TYPEDEF` — the exact C typedef text of the struct's `[u8; N]`;
//! - when `serde` is listed, `Serialize`/`Deserialize` delegating to the inner
//!   `[u8; N]` array (lossless for any length via serde's const-generic array
//!   impls).
//!
//! A unit test in `src/bls_ffi.rs` compares every generated `C_TYPEDEF`
//! against the committed `native/include/bls_backend.h`, so any drift between
//! the Rust ABI and the C header fails the build.

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::token::Comma;
use syn::{parse_macro_input, Data, DeriveInput, Expr, Fields, Lit, Meta, Result, Type};

#[proc_macro_derive(ByteLayout, attributes(byte_layout))]
pub fn derive_byte_layout(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand(input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

struct ByteLayoutAttrs {
    c_name: String,
    serde: bool,
}

impl Default for ByteLayoutAttrs {
    fn default() -> Self {
        Self {
            c_name: String::new(),
            serde: false,
        }
    }
}

struct AttrList {
    metas: Punctuated<Meta, Comma>,
}

impl Parse for AttrList {
    fn parse(input: ParseStream) -> Result<Self> {
        Ok(Self {
            metas: Punctuated::parse_terminated(input)?,
        })
    }
}

fn expand(input: DeriveInput) -> Result<TokenStream2> {
    let name = &input.ident;

    let mut attrs = ByteLayoutAttrs::default();
    for attr in &input.attrs {
        if !attr.path().is_ident("byte_layout") {
            continue;
        }
        let list: AttrList = attr.parse_args()?;
        for meta in list.metas {
            match &meta {
                Meta::NameValue(nv) if nv.path.is_ident("c_name") => {
                    let lit = &nv.value;
                    let value = match lit {
                        Expr::Lit(el) => match &el.lit {
                            Lit::Str(s) => s.value(),
                            _ => return Err(syn::Error::new_spanned(lit, "c_name must be a string literal")),
                        },
                        _ => return Err(syn::Error::new_spanned(lit, "c_name must be a string literal")),
                    };
                    if value.is_empty() {
                        return Err(syn::Error::new_spanned(lit, "c_name must not be empty"));
                    }
                    attrs.c_name = value;
                }
                Meta::Path(p) if p.is_ident("serde") => attrs.serde = true,
                other => {
                    return Err(syn::Error::new_spanned(
                        other,
                        "unsupported byte_layout attribute; expected `c_name = \"...\"` and/or `serde`",
                    ))
                }
            }
        }
    }
    if attrs.c_name.is_empty() {
        return Err(syn::Error::new_spanned(
            name,
            "byte_layout requires `c_name = \"...\"` (the C typedef name, e.g. \"bls_backend_fr_t\")",
        ));
    }

    let byte_len = struct_byte_len(&input)?;
    let n = byte_len as usize;

    let derived = &input.ident;
    let c_name = &attrs.c_name;

    let byte_consts = impl_byte_consts(derived, n, c_name);
    let accessors = impl_accessors(derived, n);
    let from_to = impl_from_to(derived, n);
    let serde_impl = if attrs.serde {
        impl_serde(derived, n)
    } else {
        TokenStream2::new()
    };

    Ok(quote! {
        #byte_consts
        #accessors
        #from_to
        #serde_impl
    })
}

/// Validate the struct is `(pub [u8; N])` exactly and return N.
fn struct_byte_len(input: &DeriveInput) -> Result<u64> {
    let fields = match &input.data {
        Data::Struct(data) => &data.fields,
        _ => return Err(syn::Error::new_spanned(&input.ident, "ByteLayout only supports structs")),
    };
    let unnamed = match fields {
        Fields::Unnamed(fields) => fields,
        _ => return Err(syn::Error::new_spanned(&input.ident, "ByteLayout only supports tuple structs with a single `[u8; N]` field")),
    };
    if unnamed.unnamed.len() != 1 {
        return Err(syn::Error::new_spanned(&input.ident, "ByteLayout requires exactly one field: `[u8; N]`"));
    }
    let field = &unnamed.unnamed[0];
    let array = match &field.ty {
        Type::Array(array) => array,
        _ => return Err(syn::Error::new_spanned(&field.ty, "the field must be `[u8; N]`")),
    };
    match array.elem.as_ref() {
        Type::Path(path) if path.qself.is_none() && path.path.is_ident("u8") => {}
        _ => return Err(syn::Error::new_spanned(&array.elem, "the element type must be `u8`")),
    }
    let n = match &array.len {
        Expr::Lit(lit) => match &lit.lit {
            Lit::Int(int) => int.base10_parse::<u64>()?,
            _ => return Err(syn::Error::new_spanned(&array.len, "the array length must be an integer literal")),
        },
        _ => return Err(syn::Error::new_spanned(&array.len, "the array length must be an integer literal")),
    };
    Ok(n)
}

fn impl_byte_consts(name: &syn::Ident, n: usize, c_name: &str) -> TokenStream2 {
    let typedef = format!("typedef struct {{ uint8_t b[{n}]; }} {c_name};");
    quote! {
        impl #name {
            /// Size of the byte container.
            pub const BYTE_LEN: usize = #n;
            /// The exact C typedef text mirrored to `bls_backend.h`.
            pub const C_TYPEDEF: &'static str = #typedef;
        }
    }
}

fn impl_accessors(name: &syn::Ident, n: usize) -> TokenStream2 {
    quote! {
        impl #name {
            /// The byte container with every byte set to zero.
            pub fn zero() -> Self {
                Self([0u8; #n])
            }
            /// Borrow the raw bytes.
            pub fn as_bytes(&self) -> &[u8] {
                &self.0
            }
            /// Build from raw bytes.
            pub fn from_bytes(bytes: [u8; #n]) -> Self {
                Self(bytes)
            }
        }
    }
}

fn impl_from_to(name: &syn::Ident, n: usize) -> TokenStream2 {
    quote! {
        impl From<[u8; #n]> for #name {
            fn from(bytes: [u8; #n]) -> Self {
                Self(bytes)
            }
        }
        impl From<#name> for [u8; #n] {
            fn from(value: #name) -> Self {
                value.0
            }
        }
    }
}

fn impl_serde(name: &syn::Ident, n: usize) -> TokenStream2 {
    let visitor = format_ident!("__{}Visitor", name);
    let expecting = format!("an array of {n} bytes");
    quote! {
        impl ::serde::Serialize for #name {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_bytes(&self.0)
            }
        }
        struct #visitor;
        impl<'de> ::serde::de::Visitor<'de> for #visitor {
            type Value = [u8; #n];
            fn expecting(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.write_str(#expecting)
            }
            fn visit_bytes<E: ::serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                <[u8; #n] as ::core::convert::TryFrom<&[u8]>>::try_from(v)
                    .map_err(|_| ::serde::de::Error::custom("value has the wrong byte length"))
            }
            fn visit_seq<A: ::serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut out = [0u8; #n];
                for slot in out.iter_mut() {
                    *slot = match seq.next_element()? {
                        Some(b) => b,
                        None => {
                            return Err(::serde::de::Error::custom("unexpected end of bytes"))
                        }
                    };
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(::serde::de::Error::custom("too many bytes"));
                }
                Ok(out)
            }
        }
        impl<'de> ::serde::Deserialize<'de> for #name {
            fn deserialize<D: ::serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserializer.deserialize_bytes(#visitor).map(#name)
            }
        }
    }
}