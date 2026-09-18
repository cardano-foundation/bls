/*
 * bls_backend.h — the C ABI of the native backend library.
 *
 * This is the *only* surface Rust talks to (mirroring the manual FFI-bindings
 * pattern from the wisonye/rust-ffi-demo project).  Everything crossing the
 * boundary is a fixed-size, ABI-stable byte container; no C++ objects and no
 * STL types are ever exposed (vector-like layouts would not be FFI-safe).
 *
 * Value encodings (all canonical, no Zcash "flag" bits):
 *   - Fr     : 32 bytes, *little-endian*, matching blst's MSM scalar byte
 *              order (byte[0] == least significant).
 *   - Fp     : 48 bytes, *big-endian* (blst_fp_from_bendian format).
 *   - G1     : 96 bytes  = x (48 BE) || y (48 BE).
 *   - G2     : 192 bytes = x.c1 (48 BE) || x.c0 (48 BE) ||
 *                          y.c1 (48 BE) || y.c0 (48 BE),
 *              where an Fp2 element is c0 + c1*u.
 *   - G1/G2 point at infinity : all coordinate bytes set to zero.
 */
#ifndef BLS_BACKEND_H
#define BLS_BACKEND_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BLS_BACKEND_MODULE_VERSION   1
#define BLS_BACKEND_FR_BYTES        32
#define BLS_BACKEND_FP_BYTES        48
#define BLS_BACKEND_G1_AFFINE_BYTES 96
#define BLS_BACKEND_G2_AFFINE_BYTES 192

typedef struct { uint8_t b[32]; }  bls_backend_fr_t;
typedef struct { uint8_t b[96]; }  bls_backend_g1_t;
typedef struct { uint8_t b[192]; } bls_backend_g2_t;

typedef enum {
    BLS_BACKEND_OK                    = 0,
    BLS_BACKEND_INVALID_ARGUMENT      = 1,
    BLS_BACKEND_POINT_NOT_ON_CURVE    = 2,
    BLS_BACKEND_POINT_NOT_IN_GROUP    = 3,
    BLS_BACKEND_INFINITY_OUTPUT       = 4,
    BLS_BACKEND_MSM_MISMATCH          = 5,
    BLS_BACKEND_PAIRING_FAILED        = 6,
    BLS_BACKEND_INTERNAL_ERROR        = 7,
} bls_backend_status;

/* Version of the native module and a short flavor string describing which
   acceleration is compiled in ("blst-pippenger; cpu", "cuda" once wired). */
uint32_t bls_backend_version(void);
const char *bls_backend_flavor(void);

/*
 * Multi-scalar multiplication:
 *   out = sum_i scalars[i] * points[i]
 *
 * `points` are affine G1 elements in the encoding above; points with all-zero
 * coordinates (infinity) and their paired scalars are skipped.  `scalars` are
 * 32-byte little-endian canonical Fr values.  If every point/scalar gets
 * skipped, BLS_BACKEND_INFINITY_OUTPUT is returned.
 */
bls_backend_status bls_msm_g1(bls_backend_g1_t *out,
                              const bls_backend_g1_t *points,
                              const bls_backend_fr_t *scalars,
                              size_t npoints);

bls_backend_status bls_msm_g2(bls_backend_g2_t *out,
                              const bls_backend_g2_t *points,
                              const bls_backend_fr_t *scalars,
                              size_t npoints);

/*
 * Batch pairing check used by the Groth16 batch verifier:
 *   prod_i e(g1[i], g2[i]) == 1_GT
 * (in arkworks' additive GT convention this is sum_i pairing == 0).
 * `ok` is set to 1 when the product is the identity, 0 otherwise.  The
 * function itself only fails on FFI/argument errors, never on the result.
 */
bls_backend_status bls_pairing_batch_check(const bls_backend_g1_t *g1s,
                                           const bls_backend_g2_t *g2s,
                                           size_t npairs,
                                           int *ok);

/*
 * Radix-2 in-place number-theoretic transform over BLS12-381's scalar field
 * Fr (DIT Cooley-Tukey, blst_fr_ct_bfly butterflies).
 *
 * `length` must be a power of two >= 1.  `root` is the primitive
 * `length`-th root of unity in Fr, 32-byte little-endian canonical bytes
 * (pass the same root for forward and inverse; the kernel uses its inverse
 * internally).  `inverse == 0` selects the forward transform
 * (X_k = sum_j x_j root^(j*k)), `inverse != 0` the inverse (root^-1,
 * with the usual 1/length scaling).  Values are 32-byte little-endian
 * canonical Fr, transformed in place.
 */
bls_backend_status bls_ntt_in_place(bls_backend_fr_t *values,
                                    size_t length,
                                    const bls_backend_fr_t *root,
                                    int inverse);

#ifdef __cplusplus
}
#endif

#endif /* BLS_BACKEND_H */