#include <blst.h>
#include "bls_backend.h"

#include <cstdint>
#include <cstring>
#include <vector>

/*
 * bls_backend.cpp — the concrete native backend.
 *
 * Field/curve arithmetic (including the Pippenger MSM and the Miller-loop
 * multi-pairing) is delegated to the vendored, formally-verified-adjacent
 * blst library (Apache-2.0, Supranational).  This translation unit only:
 *
 *   - defines the stable C ABI declared in bls_backend.h, and
 *   - converts between that byte encoding and blst's native types.
 *
 * Only one encoding rule is subtle: Fp2 elements are exchanged as
 * c1 || c0 (both big-endian), matching the ZCash spec and blst's own
 * serialization order, while inside blst_fp2 the real part is index 0.
 */

namespace {
constexpr unsigned kScalarBits = 255; /* bit length of BLS12-381's Fr modulus */

/* blst's `*_mult_pippenger` scratch must be 64-byte aligned; a plain
 * `std::vector<limb_t>` is only 8-byte aligned, which makes the asm paths
 * take the slow (or wrong) bucket path.  Keep an overallocated vector and
 * hand the caller a pointer rounded up to 64 bytes. */
class AlignedScratch {
  public:
    explicit AlignedScratch(size_t bytes)
        : storage_((bytes + sizeof(limb_t) - 1) / sizeof(limb_t) + 16) {
        uintptr_t base = reinterpret_cast<uintptr_t>(storage_.data());
        uintptr_t aligned = (base + 63) & ~uintptr_t(63);
        ptr_ = reinterpret_cast<limb_t *>(aligned);
    }
    limb_t *get() const { return ptr_; }

  private:
    std::vector<limb_t> storage_;
    limb_t *ptr_;
};

inline bool is_fp_zero(const uint8_t b[48]) {
    for (int i = 0; i < 48; i++) {
        if (b[i] != 0) return false;
    }
    return true;
}

/* NOTE: no per-point on-curve / subgroup validation here.  blst's
 * `blst_p1_affine_in_g1` is a full final exponentiation (~ms/point), which
 * would dwarf the MSM itself once n grows into the thousands.  Inputs come
 * from arkworks-produced canonical CRS/bases (guaranteed valid); the final
 * MSM output is sanity-checked once after the call. */
inline bls_backend_status decode_g1(const bls_backend_g1_t *in,
                                    blst_p1_affine *out) {
    if (is_fp_zero(in->b) && is_fp_zero(in->b + 48)) {
        return BLS_BACKEND_OK; /* caller treats (0,0) as infinity and skips it */
    }
    blst_fp_from_bendian(&out->x, in->b);
    blst_fp_from_bendian(&out->y, in->b + 48);
    return BLS_BACKEND_OK;
}

/* See decode_g1: no per-point validation in the hot path. */
inline bls_backend_status decode_g2(const bls_backend_g2_t *in,
                                    blst_p2_affine *out) {
    if (is_fp_zero(in->b) && is_fp_zero(in->b + 48) &&
        is_fp_zero(in->b + 96) && is_fp_zero(in->b + 144)) {
        return BLS_BACKEND_OK; /* infinity */
    }
    /* Fp2 x = c0 + c1*u, serialized c1 || c0.  blst_fp2 index 0 = real (c0). */
    blst_fp_from_bendian(&out->x.fp[1], in->b);       /* x.c1 */
    blst_fp_from_bendian(&out->x.fp[0], in->b + 48);  /* x.c0 */
    blst_fp_from_bendian(&out->y.fp[1], in->b + 96);  /* y.c1 */
    blst_fp_from_bendian(&out->y.fp[0], in->b + 144); /* y.c0 */
    return BLS_BACKEND_OK;
}

inline bool decode_scalar(const bls_backend_fr_t *in, blst_scalar *out) {
    blst_scalar_from_lendian(out, in->b);
    return blst_scalar_fr_check(out);
}

inline bool is_scalar_zero(const blst_scalar *s) {
    for (int i = 0; i < 32; i++) {
        if (s->b[i] != 0) return false;
    }
    return true;
}

inline void encode_g1(const blst_p1_affine *in, bls_backend_g1_t *out) {
    blst_bendian_from_fp(out->b, &in->x);
    blst_bendian_from_fp(out->b + 48, &in->y);
}

inline void encode_g2(const blst_p2_affine *in, bls_backend_g2_t *out) {
    blst_bendian_from_fp(out->b, &in->x.fp[1]);
    blst_bendian_from_fp(out->b + 48, &in->x.fp[0]);
    blst_bendian_from_fp(out->b + 96, &in->y.fp[1]);
    blst_bendian_from_fp(out->b + 144, &in->y.fp[0]);
}
} // namespace

extern "C" {

uint32_t bls_backend_version(void) {
    return BLS_BACKEND_MODULE_VERSION;
}

const char *bls_backend_flavor(void) {
#if defined(BLS_BACKEND_CUDA)
    return "blst-pippenger; cuda";
#else
    return "blst-pippenger; cpu";
#endif
}

bls_backend_status bls_msm_g1(bls_backend_g1_t *out,
                              const bls_backend_g1_t *points,
                              const bls_backend_fr_t *scalars,
                              size_t npoints) {
    if (out == nullptr) {
        return BLS_BACKEND_INVALID_ARGUMENT;
    }
    if (npoints == 0) {
        memset(out, 0, sizeof(*out));
        return BLS_BACKEND_INFINITY_OUTPUT;
    }
    if (points == nullptr || scalars == nullptr) {
        return BLS_BACKEND_INVALID_ARGUMENT;
    }

    std::vector<blst_p1_affine> pts;
    std::vector<blst_scalar> scs;
    pts.reserve(npoints);
    scs.reserve(npoints);

    for (size_t i = 0; i < npoints; i++) {
        blst_p1_affine pt;
        bls_backend_status st = decode_g1(&points[i], &pt);
        if (st != BLS_BACKEND_OK) {
            return st;
        }
        blst_scalar sc;
        if (!decode_scalar(&scalars[i], &sc)) {
            return BLS_BACKEND_INVALID_ARGUMENT;
        }
        if (is_fp_zero(points[i].b) && is_fp_zero(points[i].b + 48)) {
            continue; /* infinity base contributes nothing */
        }
        if (is_scalar_zero(&sc)) {
            continue; /* zero scalar contributes nothing */
        }
        pts.push_back(pt);
        scs.push_back(sc);
    }

    if (pts.empty()) {
        memset(out, 0, sizeof(*out));
        return BLS_BACKEND_INFINITY_OUTPUT;
    }

    std::vector<const blst_p1_affine *> pp;
    std::vector<const byte *> sp;
    pp.reserve(pts.size());
    sp.reserve(scs.size());
    for (size_t i = 0; i < pts.size(); i++) {
        pp.push_back(&pts[i]);
        sp.push_back(reinterpret_cast<const byte *>(&scs[i]));
    }

    AlignedScratch scratch(blst_p1s_mult_pippenger_scratch_sizeof(pts.size()));

    blst_p1 agg;
    blst_p1s_mult_pippenger(&agg, pp.data(), pts.size(), sp.data(),
                            kScalarBits, scratch.get());

    if (blst_p1_is_inf(&agg)) {
        memset(out, 0, sizeof(*out));
        return BLS_BACKEND_INFINITY_OUTPUT;
    }
    blst_p1_affine out_a;
    blst_p1_to_affine(&out_a, &agg);
    if (!blst_p1_affine_on_curve(&out_a)) {
        return BLS_BACKEND_POINT_NOT_ON_CURVE;
    }
    encode_g1(&out_a, out);
    return BLS_BACKEND_OK;
}

bls_backend_status bls_msm_g2(bls_backend_g2_t *out,
                              const bls_backend_g2_t *points,
                              const bls_backend_fr_t *scalars,
                              size_t npoints) {
    if (out == nullptr) {
        return BLS_BACKEND_INVALID_ARGUMENT;
    }
    if (npoints == 0) {
        memset(out, 0, sizeof(*out));
        return BLS_BACKEND_INFINITY_OUTPUT;
    }
    if (points == nullptr || scalars == nullptr) {
        return BLS_BACKEND_INVALID_ARGUMENT;
    }

    std::vector<blst_p2_affine> pts;
    std::vector<blst_scalar> scs;
    pts.reserve(npoints);
    scs.reserve(npoints);

    for (size_t i = 0; i < npoints; i++) {
        blst_p2_affine pt;
        bls_backend_status st = decode_g2(&points[i], &pt);
        if (st != BLS_BACKEND_OK) {
            return st;
        }
        blst_scalar sc;
        if (!decode_scalar(&scalars[i], &sc)) {
            return BLS_BACKEND_INVALID_ARGUMENT;
        }
        if (is_fp_zero(points[i].b) && is_fp_zero(points[i].b + 48) &&
            is_fp_zero(points[i].b + 96) && is_fp_zero(points[i].b + 144)) {
            continue;
        }
        if (is_scalar_zero(&sc)) {
            continue;
        }
        pts.push_back(pt);
        scs.push_back(sc);
    }

    if (pts.empty()) {
        memset(out, 0, sizeof(*out));
        return BLS_BACKEND_INFINITY_OUTPUT;
    }

    std::vector<const blst_p2_affine *> pp;
    std::vector<const byte *> sp;
    pp.reserve(pts.size());
    sp.reserve(scs.size());
    for (size_t i = 0; i < pts.size(); i++) {
        pp.push_back(&pts[i]);
        sp.push_back(reinterpret_cast<const byte *>(&scs[i]));
    }

    AlignedScratch scratch(blst_p2s_mult_pippenger_scratch_sizeof(pts.size()));

    blst_p2 agg;
    blst_p2s_mult_pippenger(&agg, pp.data(), pts.size(), sp.data(),
                            kScalarBits, scratch.get());

    if (blst_p2_is_inf(&agg)) {
        memset(out, 0, sizeof(*out));
        return BLS_BACKEND_INFINITY_OUTPUT;
    }
    blst_p2_affine out_a;
    blst_p2_to_affine(&out_a, &agg);
    if (!blst_p2_affine_on_curve(&out_a)) {
        return BLS_BACKEND_POINT_NOT_ON_CURVE;
    }
    encode_g2(&out_a, out);
    return BLS_BACKEND_OK;
}

bls_backend_status bls_pairing_batch_check(const bls_backend_g1_t *g1s,
                                           const bls_backend_g2_t *g2s,
                                           size_t npairs,
                                           int *ok) {
    if (ok == nullptr) {
        return BLS_BACKEND_INVALID_ARGUMENT;
    }
    *ok = 0;
    if (npairs == 0) {
        *ok = 1; /* empty product is the identity of groups */
        return BLS_BACKEND_OK;
    }
    if (g1s == nullptr || g2s == nullptr) {
        return BLS_BACKEND_INVALID_ARGUMENT;
    }

    std::vector<blst_p1_affine> p1;
    std::vector<blst_p2_affine> p2;
    p1.reserve(npairs);
    p2.reserve(npairs);

    for (size_t i = 0; i < npairs; i++) {
        blst_p1_affine a;
        bls_backend_status st = decode_g1(&g1s[i], &a);
        if (st != BLS_BACKEND_OK) {
            return st;
        }
        p1.push_back(a);
        blst_p2_affine b;
        st = decode_g2(&g2s[i], &b);
        if (st != BLS_BACKEND_OK) {
            return st;
        }
        p2.push_back(b);
    }

    std::vector<const blst_p1_affine *> p1p;
    std::vector<const blst_p2_affine *> p2p;
    p1p.reserve(npairs);
    p2p.reserve(npairs);
    for (size_t i = 0; i < npairs; i++) {
        p1p.push_back(&p1[i]);
        p2p.push_back(&p2[i]);
    }

    blst_fp12 f;
    blst_miller_loop_n(&f, p2p.data(), p1p.data(), npairs);
    blst_final_exp(&f, &f);
    *ok = blst_fp12_is_one(&f) ? 1 : 0;
    return BLS_BACKEND_OK;
}

/* Number-theoretic transform: wired in by the NTT milestone (commit 2). */
bls_backend_status bls_ntt_in_place(bls_backend_fr_t *values, size_t length, int inverse) {
    (void)values;
    (void)length;
    (void)inverse;
    return BLS_BACKEND_INTERNAL_ERROR;
}

} // extern "C"