#![warn(clippy::all)]

//! Compile-time backend selection for the `groth16` CLI artifact.
//!
//! `BLS_BACKEND` decides *at build time* which backend implementation a given
//! binary contains, so a release artifact provably ships exactly one path:
//!
//!   - `cpu`    — the pure-Rust arkworks path only (`--backend native` is
//!                rejected by the parser and the FFI code is not compiled in).
//!   - `native` — the vendored blst FFI path only (arkworks MSM/pairing code
//!                is not compiled in).  Requires `--features native`.
//!   - `both`   — both implementations, selectable at run time via
//!                `--backend cpu|native` (default `cpu`).  This is the
//!                **default** and is what parity tests and the benchmark rely
//!                on.
//!
//! The same source therefore produces either a single-backend or a
//! dual-backend artifact; tools like CI or packaging can pin a mode with the
//! environment variable without touching the manifest.
//!
//! Usage:
//!
//! ```text
//! BLS_BACKEND=cpu    cargo build --release                 # rust only
//! BLS_BACKEND=native cargo build --release --features native # ffi only
//! cargo build --release --features native                    # both (default)
//! ```

fn main() {
    // Rebuild (and thus re-resolve the backend) when the variable changes.
    println!("cargo:rerun-if-env-changed=BLS_BACKEND");

    // Declare the cfgs this script may emit so rustc's check-cfg lint stops
    // flagging `backend_cpu` / `backend_native` as unexpected.
    println!("cargo::rustc-check-cfg=cfg(backend_cpu)");
    println!("cargo::rustc-check-cfg=cfg(backend_native)");

    let mode = std::env::var("BLS_BACKEND")
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_else(|_| "both".into());

    match mode.as_str() {
        "cpu" => {
            println!("cargo:rustc-cfg=backend_cpu");
        }
        "native" => {
            if std::env::var("CARGO_FEATURE_NATIVE").is_err() {
                panic!(
                    "BLS_BACKEND=native requires the `native` feature: \
                     run `cargo build --features native`"
                );
            }
            println!("cargo:rustc-cfg=backend_native");
        }
        "both" => {
            println!("cargo:rustc-cfg=backend_cpu");
            println!("cargo:rustc-cfg=backend_native");
        }
        other => panic!("BLS_BACKEND={other}: expected one of cpu | native | both"),
    }
}