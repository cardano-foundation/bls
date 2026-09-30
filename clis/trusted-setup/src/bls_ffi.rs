//! Manual, type-checked FFI bindings for the native backend.
//!
//! Half of the demo's "how to do FFI properly": we commit a hand-written
//! `#[repr(C)]`/`extern "C"` binding layer (the demo's `manual_bindings.rs`,
//! gated behind `enable-manual-bindings`) instead of running `bindgen`, so the
//! ABI is explicit and reviewable.  The other half (CMake C++ library, plain-C
//! header, tests) lives in `native/`.
//!
//! Types mirror `native/include/bls_backend.h` byte-for-byte.

use std::ffi::c_char;
use std::os::raw::c_int;

use trusted_setup_macros::ByteLayout;

/// 32-byte little-endian canonical Fr scalar.
#[repr(C)]
#[derive(Clone, Copy, ByteLayout)]
#[byte_layout(c_name = "bls_backend_fr_t", serde)]
pub struct BlsFr(pub [u8; 32]);

/// 96-byte affine G1 point: x (48B BE) || y (48B BE).
#[repr(C)]
#[derive(Clone, Copy, ByteLayout)]
#[byte_layout(c_name = "bls_backend_g1_t", serde)]
pub struct BlsG1(pub [u8; 96]);

/// 192-byte affine G2 point: x.c1 || x.c0 || y.c1 || y.c0 (48B BE each).
#[repr(C)]
#[derive(Clone, Copy, ByteLayout)]
#[byte_layout(c_name = "bls_backend_g2_t", serde)]
pub struct BlsG2(pub [u8; 192]);

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlsStatus {
    Ok = 0,
    InvalidArgument = 1,
    PointNotOnCurve = 2,
    PointNotInGroup = 3,
    InfinityOutput = 4,
    MsmMismatch = 5,
    PairingFailed = 6,
    InternalError = 7,
}

impl BlsStatus {
    pub fn from_raw(raw: c_int) -> Self {
        match raw {
            0 => Self::Ok,
            1 => Self::InvalidArgument,
            2 => Self::PointNotOnCurve,
            3 => Self::PointNotInGroup,
            4 => Self::InfinityOutput,
            5 => Self::MsmMismatch,
            6 => Self::PairingFailed,
            _ => Self::InternalError,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::InvalidArgument => "invalid argument",
            Self::PointNotOnCurve => "point not on the BLS12-381 curve",
            Self::PointNotInGroup => "point not in the prime-order subgroup",
            Self::InfinityOutput => {
                "multi-scalar multiplication produced the point at infinity"
            }
            Self::MsmMismatch => "MSM length mismatch",
            Self::PairingFailed => "pairing error",
            Self::InternalError => "internal native-backend error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendError {
    pub status: BlsStatus,
    pub message: &'static str,
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native backend error {}: {}", self.status as i32, self.message)
    }
}

impl std::error::Error for BackendError {}

unsafe extern "C" {
    fn bls_backend_version() -> u32;
    fn bls_backend_flavor() -> *const c_char;

    fn bls_msm_g1(
        out: *mut BlsG1,
        points: *const BlsG1,
        scalars: *const BlsFr,
        npoints: usize,
    ) -> c_int;

    fn bls_msm_g2(
        out: *mut BlsG2,
        points: *const BlsG2,
        scalars: *const BlsFr,
        npoints: usize,
    ) -> c_int;

    fn bls_pairing_batch_check(
        g1s: *const BlsG1,
        g2s: *const BlsG2,
        npairs: usize,
        ok: *mut c_int,
    ) -> c_int;

    fn bls_ntt_in_place(
        values: *mut BlsFr,
        length: usize,
        root: *const BlsFr,
        inverse: c_int,
    ) -> c_int;
}

pub fn version() -> u32 {
    unsafe { bls_backend_version() }
}

/// The compiled-in flavor, e.g. "blst-pippenger; cpu".
pub fn flavor() -> String {
    let ptr = unsafe { bls_backend_flavor() };
    assert!(!ptr.is_null(), "bls_backend_flavor returned null");
    unsafe { std::ffi::CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}

fn err(status: BlsStatus) -> BackendError {
    BackendError {
        status,
        message: status.as_str(),
    }
}

unsafe fn msm_g1_impl(points: &[BlsG1], scalars: &[BlsFr]) -> Result<BlsG1, BackendError> {
    debug_assert_eq!(points.len(), scalars.len(), "safe wrapper guarantees");
    let mut out = BlsG1([0u8; 96]);
    let raw = unsafe { bls_msm_g1(&mut out, points.as_ptr(), scalars.as_ptr(), points.len()) };
    unsafe { msm_readout(raw, out) }
}

unsafe fn msm_g2_impl(points: &[BlsG2], scalars: &[BlsFr]) -> Result<BlsG2, BackendError> {
    debug_assert_eq!(points.len(), scalars.len(), "safe wrapper guarantees");
    let mut out = BlsG2([0u8; 192]);
    let raw = unsafe { bls_msm_g2(&mut out, points.as_ptr(), scalars.as_ptr(), points.len()) };
    unsafe { msm_readout(raw, out) }
}

/// MSM output semantics: `out` is only meaningful on Ok or InfinityOutput;
/// both carry a well-defined point (the identity in the infinite case).
unsafe fn msm_readout<T>(raw: c_int, out: T) -> Result<T, BackendError> {
    match BlsStatus::from_raw(raw) {
        BlsStatus::Ok => Ok(out),
        BlsStatus::InfinityOutput => Ok(out),
        other => Err(err(other)),
    }
}

pub fn msm_g1(points: &[BlsG1], scalars: &[BlsFr]) -> Result<BlsG1, BackendError> {
    if points.len() != scalars.len() {
        return Err(err(BlsStatus::MsmMismatch));
    }
    unsafe { msm_g1_impl(points, scalars) }
}

pub fn msm_g2(points: &[BlsG2], scalars: &[BlsFr]) -> Result<BlsG2, BackendError> {
    if points.len() != scalars.len() {
        return Err(err(BlsStatus::MsmMismatch));
    }
    unsafe { msm_g2_impl(points, scalars) }
}

/// `Ok(true)` when the batch of pairings multiplies out to one.
pub fn pairing_batch(g1s: &[BlsG1], g2s: &[BlsG2]) -> Result<bool, BackendError> {
    if g1s.len() != g2s.len() {
        return Err(err(BlsStatus::MsmMismatch));
    }
    let mut ok: c_int = 0;
    let raw = unsafe {
        bls_pairing_batch_check(g1s.as_ptr(), g2s.as_ptr(), g1s.len(), &mut ok)
    };
    match BlsStatus::from_raw(raw) {
        BlsStatus::Ok => Ok(ok != 0),
        other => Err(err(other)),
    }
}

pub fn ntt_in_place(values: &mut [BlsFr], root: &BlsFr, inverse: bool) -> Result<(), BackendError> {
    let raw = unsafe { bls_ntt_in_place(values.as_mut_ptr(), values.len(), root, inverse as c_int) };
    match BlsStatus::from_raw(raw) {
        BlsStatus::Ok => Ok(()),
        other => Err(err(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed C ABI header, read verbatim so the check runs in CI.
    const HEADER: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/native/include/bls_backend.h"));

    fn normalize(s: &str) -> String {
        s.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// Parse `#define NAME <int>` out of a C header.
    fn header_macro(header: &str, name: &str) -> Option<i64> {
        let needle = format!("#define {name} ");
        header
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(&needle))
            .and_then(|l| l[needle.len()..].trim().split_whitespace().next())
            .and_then(|v| v.parse::<i64>().ok())
    }

    /// Parse the `bls_backend_status` enum body as `(name, value)` pairs,
    /// skipping comment lines.  Values are what cross the boundary as `c_int`.
    fn header_status_codes(header: &str) -> Vec<(String, i32)> {
        let mut lines = header
            .lines()
            .skip_while(|l| !l.contains("typedef enum"));
        let body: Vec<&str> = lines
            .by_ref()
            .take_while(|l| !l.contains("bls_backend_status"))
            .collect();
        body.iter()
            .map(|l| l.trim())
            .filter(|l| !l.starts_with("/*") && !l.starts_with('*'))
            .filter(|l| l.contains('='))
            .filter_map(|l| {
                let mut parts = l.splitn(2, '=');
                let name = parts.next()?.trim().to_string();
                let val = parts.next()?.trim().trim_end_matches(',');
                Some((name, val.parse::<i32>().ok()?))
            })
            .collect()
    }

    /// One parsed C parameter: its normalized type and its name.
    type CParam = (String, String);

    /// One parsed C prototype: name, return type, parameters.
    type CProto = (String, String, Vec<CParam>);

    /// Parse the header's function prototypes as
    /// `(name, return type, [(param type, param name)])`, normalizing the C
    /// spelling (`bls_backend_g1_t *out` -> `bls_backend_g1_t*`) so a
    /// declaration split across lines compares equal to a single-line one.
    fn header_prototypes(header: &str) -> Vec<CProto> {
        let cleaned = strip_c_comments(header);
        let mut out = Vec::new();
        let mut pending = String::new();
        // A `typedef struct {...} name;` spans lines and is not a prototype.
        let mut in_typedef = false;
        let mut brace_depth = 0i32;

        for line in cleaned.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                // Preprocessor directives are not declarations, and several
                // (`#define ... 48`) contain no `;` at all — letting one
                // accumulate would swallow the declaration after it.
                continue;
            }
            // `extern "C" {` / `}` wrap the whole header; the opening brace
            // would make every later line look mid-declaration.
            if line == "extern \"C\" {" || line == "{" || line == "}" {
                continue;
            }

            if in_typedef {
                brace_depth += line.chars().filter(|&c| c == '{').count() as i32
                    - line.chars().filter(|&c| c == '}').count() as i32;
                if brace_depth <= 0 {
                    in_typedef = false;
                    pending.clear();
                }
                continue;
            }
            if line.starts_with("typedef") {
                let d = line.chars().filter(|&c| c == '{').count() as i32
                    - line.chars().filter(|&c| c == '}').count() as i32;
                if d > 0 {
                    in_typedef = true;
                    brace_depth = d;
                }
                // A single-line typedef (`typedef ... name;`) is already done.
                continue;
            }

            pending.push_str(line);
            pending.push(' ');

            if !ends_declaration(&pending) {
                continue;
            }
            let decl = pending.trim().trim_end_matches(';').trim().to_string();
            pending.clear();

            if decl.is_empty() || !decl.contains('(') {
                continue; // e.g. a bare brace or a struct member
            }
            if let Some(sig) = parse_c_prototype(&decl) {
                out.push(sig);
            }
        }
        out
    }

    /// True when `text` ends a declaration: a `;` at paren/brace depth 0.
    fn ends_declaration(text: &str) -> bool {
        let mut depth = 0i32;
        for c in text.chars() {
            match c {
                '(' | '{' => depth += 1,
                ')' | '}' => depth -= 1,
                ';' if depth <= 0 => return true,
                _ => {}
            }
        }
        false
    }

    /// Remove `/* ... */` and `// ...` from a C header, preserving newlines so
    /// line-based logic downstream still behaves.
    fn strip_c_comments(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        let b: Vec<char> = s.chars().collect();
        let mut i = 0;
        while i < b.len() {
            if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '*' {
                // Block comment: skip to the closing delimiter.
                i += 2;
                while i + 1 < b.len() && !(b[i] == '*' && b[i + 1] == '/') {
                    if b[i] == '\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
                i = (i + 2).min(b.len());
            } else if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '/' {
                // Line comment: skip to end of line.
                while i < b.len() && b[i] != '\n' {
                    i += 1;
                }
            } else {
                out.push(b[i]);
                i += 1;
            }
        }
        out
    }

    /// Parse one C prototype body, e.g.
    /// `bls_backend_status bls_msm_g1(bls_backend_g1_t *out, const bls_backend_g1_t *points, ...)`
    /// into `("bls_backend_status", [("bls_backend_g1_t*", "out"), ...])`.
    fn parse_c_prototype(text: &str) -> Option<CProto> {
        let text = text.trim();
        let open = text.find('(')?;
        let close = text.rfind(')')?;
        if close < open {
            return None;
        }
        // Everything before '(' is "<ret> <name>"; split off the last token as
        // the function name.
        let head = &text[..open];
        let (ret, fname) = split_type_and_name(head)?;

        let args_src = &text[open + 1..close];
        let mut params = Vec::new();
        for raw in split_top_level_commas(args_src) {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            if raw == "void" {
                // `f(void)` means no parameters.
                continue;
            }
            // An array parameter decays to a pointer; we have none in this ABI,
            // but handle it rather than mis-parse silently.
            let raw = raw.split('[').next().unwrap_or(raw).trim();
            let (ty, name) = split_type_and_name(raw)?;
            params.push((normalize_c_type(ty), name.to_string()));
        }
        Some((fname.to_string(), normalize_c_type(ret), params))
    }

    /// Split on commas that are not inside parentheses (e.g. a function-pointer
    /// parameter type).
    fn split_top_level_commas(s: &str) -> Vec<String> {
        let mut parts = Vec::new();
        let mut depth = 0i32;
        let mut cur = String::new();
        for c in s.chars() {
            match c {
                '(' => {
                    depth += 1;
                    cur.push(c);
                }
                ')' => {
                    depth -= 1;
                    cur.push(c);
                }
                ',' if depth == 0 => {
                    parts.push(std::mem::take(&mut cur));
                }
                _ => cur.push(c),
            }
        }
        if !cur.trim().is_empty() {
            parts.push(cur);
        }
        parts
    }

    /// Split a declaration head into `(type, name)`.
    ///
    /// The name is always the final identifier. Everything before it is the
    /// type, with one wrinkle: in a *parameter* (`const char *out`) the `*`
    /// binds to the type, while in a *function head* (`const char *foo(void)`)
    /// it binds to the name. Both spellings are accepted and the trailing `*`
    /// is normalized away by `normalize_c_type`, so callers only need to know
    /// where the name starts.
    fn split_type_and_name(raw: &str) -> Option<(&str, &str)> {
        let raw = raw.trim();
        let is_ident = |c: char| c.is_alphanumeric() || c == '_';

        // Locate the final identifier run; `rfind` gives the index *after* its
        // last character, so walk back to where the run begins.
        let name_end = raw.rfind(is_ident)?;
        let mut name_start = name_end;
        while name_start > 0 {
            let prev = raw[..name_start].chars().next_back()?;
            if !is_ident(prev) {
                break;
            }
            name_start -= prev.len_utf8();
        }
        let name = &raw[name_start..];
        if name.is_empty() || !name.chars().all(is_ident) {
            return None;
        }

        let head_raw = &raw[..name_start];
        // Only identifiers, spaces and pointers may appear before the name.
        if !head_raw
            .chars()
            .all(|c| is_ident(c) || c == ' ' || c == '*')
        {
            return None;
        }
        // The name must be a standalone token: separated by whitespace, or by
        // a `*` that belongs to the type. Without either, the whole head is one
        // identifier and this is not a type/name pair at all.
        let sep = head_raw
            .chars()
            .next_back()
            .map(|c| c == ' ' || c == '*')
            .unwrap_or(false);
        if !sep || head_raw.trim().is_empty() {
            return None;
        }
        // Keep the `*` in the type: it is part of it in both a parameter
        // (`const char *out` -> `const char*`) and a function head
        // (`const char *f(void)` -> return type `const char*`).
        Some((head_raw.trim_end(), name))
    }

    /// `bls_backend_g1_t *` and `bls_backend_g1_t*` are the same type.
    fn normalize_c_type(t: &str) -> String {
        // Collapse whitespace runs, then delete every space adjacent to a `*`
        // so `T *`, `T * ` and `T*` all normalize to `T*`.
        let joined = t.split_whitespace().collect::<Vec<_>>().join(" ");
        let bytes: Vec<char> = joined.chars().collect();
        let mut out = String::with_capacity(joined.len());
        for (i, &c) in bytes.iter().enumerate() {
            if c == ' ' {
                let near_star = bytes[i - 1] == '*' || bytes.get(i + 1) == Some(&'*');
                if near_star {
                    continue;
                }
            }
            out.push(c);
        }
        out
    }

    /// Edge 1 catches a header edit; edge 2 catches a Rust edit. The C++
    /// implementation is out of scope here by design — it is imported code — so
    /// this verifies the declaration, not the definition.
    #[test]
    fn extern_signatures_match_committed_header() {
        // name -> (return type, [(param type, param name)])
        type ExpectedProto<'a> = (&'a str, &'a str, Vec<(&'a str, &'a str)>);
        let expected: Vec<ExpectedProto> = vec![
            ("bls_backend_version", "uint32_t", vec![]),
            ("bls_backend_flavor", "const char*", vec![]),
            (
                "bls_msm_g1",
                "bls_backend_status",
                vec![
                    ("bls_backend_g1_t*", "out"),
                    ("const bls_backend_g1_t*", "points"),
                    ("const bls_backend_fr_t*", "scalars"),
                    ("size_t", "npoints"),
                ],
            ),
            (
                "bls_msm_g2",
                "bls_backend_status",
                vec![
                    ("bls_backend_g2_t*", "out"),
                    ("const bls_backend_g2_t*", "points"),
                    ("const bls_backend_fr_t*", "scalars"),
                    ("size_t", "npoints"),
                ],
            ),
            (
                "bls_pairing_batch_check",
                "bls_backend_status",
                vec![
                    ("const bls_backend_g1_t*", "g1s"),
                    ("const bls_backend_g2_t*", "g2s"),
                    ("size_t", "npairs"),
                    ("int*", "ok"),
                ],
            ),
            (
                "bls_ntt_in_place",
                "bls_backend_status",
                vec![
                    ("bls_backend_fr_t*", "values"),
                    ("size_t", "length"),
                    ("const bls_backend_fr_t*", "root"),
                    ("int", "inverse"),
                ],
            ),
        ];

        // `bls_backend_version(void)` and `bls_backend_flavor(void)` take no
        // parameters; the parser drops a lone `void`.
        let parsed = header_prototypes(HEADER);
        assert_eq!(
            parsed.len(),
            expected.len(),
            "header prototype count changed; bls_backend.h was edited (parsed {parsed:?})"
        );
        for ((name, exp_ret, exp_params), (pname, ret, params)) in
            expected.iter().zip(parsed.iter())
        {
            assert_eq!(&pname, name, "header prototype order changed");
            assert_eq!(
                &normalize_c_type(ret),
                &normalize_c_type(exp_ret),
                "{name}: return type changed"
            );
            assert_eq!(
                params.len(),
                exp_params.len(),
                "{name}: parameter count changed"
            );
            for (j, ((exp_ty, exp_pname), (ty, pname))) in
                exp_params.iter().zip(params.iter()).enumerate()
            {
                assert_eq!(
                    &normalize_c_type(ty),
                    &normalize_c_type(exp_ty),
                    "{name}: parameter {j} ({exp_pname}) type changed \
                     -- a pointer swap here is silent memory corruption"
                );
                assert_eq!(
                    pname, exp_pname,
                    "{name}: parameter {j} renamed (check the binding's naming)"
                );
            }
        }
    }

    /// Edge 2 of the above, enforced at compile time. If the `extern "C"`
    /// declaration drifts from the signature this project intends, assigning it
    /// to the expected fn-pointer type below stops the build.
    #[test]
    fn extern_items_coerce_to_expected_signatures() {
        // These coercions are the actual check; the body only forces them to be
        // evaluated. A mismatch is a compile error, not a test failure.
        const _: unsafe extern "C" fn() -> u32 = bls_backend_version;
        const _: unsafe extern "C" fn() -> *const c_char = bls_backend_flavor;
        const _: unsafe extern "C" fn(*mut BlsG1, *const BlsG1, *const BlsFr, usize) -> c_int =
            bls_msm_g1;
        const _: unsafe extern "C" fn(*mut BlsG2, *const BlsG2, *const BlsFr, usize) -> c_int =
            bls_msm_g2;
        const _: unsafe extern "C" fn(*const BlsG1, *const BlsG2, usize, *mut c_int) -> c_int =
            bls_pairing_batch_check;
        const _: unsafe extern "C" fn(*mut BlsFr, usize, *const BlsFr, c_int) -> c_int =
            bls_ntt_in_place;
    }

    /// Negative control for the prototype parser: the checks above must be able
    /// to fail. Each mutation here corresponds to a real ABI break that would
    /// otherwise pass silently.
    #[test]
    fn prototype_parser_detects_signature_drift() {
        let base = header_prototypes(HEADER);
        assert_eq!(base.len(), 6, "expected six prototypes, got {base:?}");

        // (a) swapping two pointer parameters: silent corruption.
        let swapped = HEADER.replace(
            "bls_backend_g1_t *out,\n                              const bls_backend_g1_t *points,",
            "const bls_backend_g1_t *points,\n                              bls_backend_g1_t *out,",
        );
        assert_ne!(
            header_prototypes(&swapped),
            base,
            "a swapped pointer parameter went undetected"
        );

        // (a2) swapping two parameters of *identical* type. Only the name check
        // can see this, so pin it explicitly: it is easy to weaken the type
        // comparison later and silently lose the case.
        let same_type = HEADER.replace(
            "bls_backend_status bls_ntt_in_place(bls_backend_fr_t *values,",
            "bls_backend_status bls_ntt_in_place(bls_backend_fr_t *root,",
        );
        assert_ne!(
            header_prototypes(&same_type),
            base,
            "a same-typed parameter swap went undetected"
        );

        // (b) dropping a parameter entirely.
        let dropped = HEADER.replace(
            "const bls_backend_fr_t *scalars,\n                              size_t npoints);",
            "size_t npoints);",
        );
        assert_ne!(
            header_prototypes(&dropped),
            base,
            "a dropped parameter went undetected"
        );

        // (c) changing the return type.
        let retyped = HEADER.replace(
            "bls_backend_status bls_pairing_batch_check(",
            "int bls_pairing_batch_check(",
        );
        assert_ne!(
            header_prototypes(&retyped),
            base,
            "a changed return type went undetected"
        );

        // (d) adding a parameter the bindings do not pass.
        let added = HEADER.replace(
            "bls_backend_fr_t *values,",
            "bls_backend_fr_t *values,\n                                     int extra,",
        );
        assert_ne!(
            header_prototypes(&added),
            base,
            "an added parameter went undetected"
        );

        // (e) a prototype mentioned only inside a comment must not be parsed.
        let commented = format!("/* bls_backend_status bls_ghost(int a); */\n{HEADER}");
        assert_eq!(
            header_prototypes(&commented),
            base,
            "a commented-out prototype leaked into the parsed set"
        );
    }

    /// The `BLS_BACKEND_*_BYTES` macros are part of the published ABI contract
    /// and the C++ decode routines hard-code the same 48-byte Fp stride, but
    /// they are `#define`s — not `typedef struct` lines — so the test above
    /// cannot see them.
    #[test]
    fn byte_count_macros_match_rust_layouts() {
        let fp = header_macro(HEADER, "BLS_BACKEND_FP_BYTES")
            .expect("BLS_BACKEND_FP_BYTES missing from bls_backend.h");
        assert_eq!(
            header_macro(HEADER, "BLS_BACKEND_FR_BYTES"),
            Some(BlsFr::BYTE_LEN as i64),
            "FR byte count drifted from BlsFr::BYTE_LEN"
        );
        assert_eq!(
            header_macro(HEADER, "BLS_BACKEND_G1_AFFINE_BYTES"),
            Some(BlsG1::BYTE_LEN as i64),
            "G1 byte count drifted from BlsG1::BYTE_LEN"
        );
        assert_eq!(
            header_macro(HEADER, "BLS_BACKEND_G2_AFFINE_BYTES"),
            Some(BlsG2::BYTE_LEN as i64),
            "G2 byte count drifted from BlsG2::BYTE_LEN"
        );
        // Fp is a coordinate, not a top-level type: 48 bytes, so a G1 is two
        // and a G2 is four, matching the documented c1/c0 layout.
        assert_eq!(fp, 48, "Fp coordinate stride changed");
        assert_eq!(BlsG1::BYTE_LEN, 2 * fp as usize);
        assert_eq!(BlsG2::BYTE_LEN, 4 * fp as usize);
    }

    /// Status codes cross the boundary as raw `c_int`.  If a value is
    /// renumbered on either side, every error is silently reinterpreted — e.g.
    /// an `InfinityOutput` surfacing as `MsmMismatch`.  Nothing in the type
    /// system relates the two enums, so pin them by name and value.
    #[test]
    fn status_codes_match_committed_header() {
        let expected: Vec<(String, i32)> = vec![
            ("BLS_BACKEND_OK".into(), BlsStatus::Ok as i32),
            (
                "BLS_BACKEND_INVALID_ARGUMENT".into(),
                BlsStatus::InvalidArgument as i32,
            ),
            (
                "BLS_BACKEND_POINT_NOT_ON_CURVE".into(),
                BlsStatus::PointNotOnCurve as i32,
            ),
            (
                "BLS_BACKEND_POINT_NOT_IN_GROUP".into(),
                BlsStatus::PointNotInGroup as i32,
            ),
            (
                "BLS_BACKEND_INFINITY_OUTPUT".into(),
                BlsStatus::InfinityOutput as i32,
            ),
            (
                "BLS_BACKEND_MSM_MISMATCH".into(),
                BlsStatus::MsmMismatch as i32,
            ),
            (
                "BLS_BACKEND_PAIRING_FAILED".into(),
                BlsStatus::PairingFailed as i32,
            ),
            (
                "BLS_BACKEND_INTERNAL_ERROR".into(),
                BlsStatus::InternalError as i32,
            ),
        ];
        assert_eq!(
            header_status_codes(HEADER),
            expected,
            "bls_backend_status drifted from BlsStatus; errors would be misreported"
        );
    }

    /// Negative controls: the drift checks must actually be able to fail.
    /// A consistency test that cannot detect inconsistency is worthless, so
    /// each parser is fed a deliberately corrupted header.
    #[test]
    fn drift_detectors_actually_reject_drift() {
        let codes = header_status_codes(HEADER);
        assert_eq!(codes.len(), 8, "parser found the wrong number of statuses");

        // (a) renumbering a status in the middle must change the parsed table.
        let renumbered = HEADER.replace(
            "BLS_BACKEND_MSM_MISMATCH          = 5,",
            "BLS_BACKEND_MSM_MISMATCH          = 6,",
        );
        assert_ne!(
            header_status_codes(&renumbered),
            codes,
            "renumbering a status went undetected"
        );

        // (b) a comment line must not be mistaken for an enumerator.
        let with_comment = HEADER.replace(
            "BLS_BACKEND_OK                    = 0,",
            "/* retired: BLS_BACKEND_OLD = 3, */\n    BLS_BACKEND_OK = 0,",
        );
        assert_eq!(
            header_status_codes(&with_comment),
            codes,
            "a commented-out enumerator leaked into the table"
        );

        // (c) a changed byte count must be visible to the macro parser.
        let resized = HEADER.replace("#define BLS_BACKEND_G1_AFFINE_BYTES 96", "#define BLS_BACKEND_G1_AFFINE_BYTES 128");
        assert_eq!(header_macro(&resized, "BLS_BACKEND_G1_AFFINE_BYTES"), Some(128));
        assert_ne!(
            header_macro(&resized, "BLS_BACKEND_G1_AFFINE_BYTES"),
            header_macro(HEADER, "BLS_BACKEND_G1_AFFINE_BYTES"),
            "a resized G1 went undetected"
        );

        // (d) a missing macro must read as None, not as a silent 0.
        assert_eq!(header_macro(HEADER, "BLS_BACKEND_NO_SUCH_MACRO"), None);
    }

    /// `from_raw` maps unknown codes to `InternalError`.  A value outside
    /// 0..=7 must therefore never decode to a *specific* diagnosis, or a future
    /// header addition would be reported as a real error kind.
    #[test]
    fn unknown_status_codes_degrade_to_internal_error() {
        for raw in [-1, 8, 99, i32::MIN, i32::MAX] {
            assert_eq!(
                BlsStatus::from_raw(raw),
                BlsStatus::InternalError,
                "raw code {raw} decoded to a specific status"
            );
        }
        for status in [
            BlsStatus::Ok,
            BlsStatus::InvalidArgument,
            BlsStatus::PointNotOnCurve,
            BlsStatus::PointNotInGroup,
            BlsStatus::InfinityOutput,
            BlsStatus::MsmMismatch,
            BlsStatus::PairingFailed,
            BlsStatus::InternalError,
        ] {
            assert_eq!(BlsStatus::from_raw(status as c_int), status);
        }
    }

    /// Every generated `C_TYPEDEF` must exist, byte-for-byte, in the committed
    /// `bls_backend.h`.  Renaming a type, changing a byte length, or editing
    /// the header without touching the derive fails here.
    #[test]
    fn c_typedefs_match_committed_header() {
        let expected: Vec<String> = [BlsFr::C_TYPEDEF, BlsG1::C_TYPEDEF, BlsG2::C_TYPEDEF]
            .into_iter()
            .map(|t| normalize(t.trim()))
            .collect();
        let actual: Vec<String> = HEADER
            .lines()
            .map(str::trim)
            .filter(|l| l.starts_with("typedef struct"))
            .map(normalize)
            .collect();
        assert_eq!(
            actual, expected,
            "bls_backend.h typedefs drifted from the ByteLayout metadata"
        );
    }

    #[test]
    fn byte_accessors_and_conversions() {
        let fr = BlsFr([0xAB; 32]);
        assert_eq!(BlsFr::BYTE_LEN, 32);
        assert_eq!(BlsG1::BYTE_LEN, 96);
        assert_eq!(BlsG2::BYTE_LEN, 192);
        assert_eq!(fr.as_bytes(), &[0xAB; 32]);
        let fr2 = BlsFr::from_bytes([0xAB; 32]);
        assert_eq!(fr2.as_bytes(), fr.as_bytes());
        let back: [u8; 32] = fr2.into();
        assert_eq!(back, [0xAB; 32]);
        assert!(BlsG1::zero().as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn serde_roundtrip_json() {
        let fr = BlsFr([0x11; 32]);
        let encoded = serde_json::to_vec(&fr).unwrap();
        let decoded: BlsFr = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), fr.as_bytes());

        let g2 = BlsG2([0x22; 192]);
        let encoded = serde_json::to_vec(&g2).unwrap();
        let decoded: BlsG2 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.as_bytes(), g2.as_bytes());
    }
}