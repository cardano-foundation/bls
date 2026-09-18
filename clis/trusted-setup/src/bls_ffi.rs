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