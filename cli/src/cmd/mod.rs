pub mod add;
pub mod compress;
pub mod generate_seed;
pub mod hkdf;
pub mod mul;
pub mod pk;
pub mod scalar;
pub mod sig;
pub mod uncompress;
pub mod verify;

/// Strip `0x` or `0X` prefix from a hex string, if present.
pub fn strip_0x(s: &str) -> &str {
    s.strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s)
}
