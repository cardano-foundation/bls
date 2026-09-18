/*
 * test_bls_backend.cpp — ground-level tests for the native backend.
 *
 * These run through the same C ABI the Rust crate uses.  Known-truth is built
 * with blst directly (generator constants, scalar multiplication, negation),
 * so the tests validate the MSM / pairing / encoding round-trips without
 * depending on the Rust side.  Rust-side cross-validation against arkworks
 * lives in the trusted-setup crate (feature "native").
 */
#include <blst.h>
#include <bls_backend.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

namespace {

int failures = 0;
int checks = 0;

#define CHECK(cond)                                                    \
    do {                                                               \
        checks++;                                                      \
        if (!(cond)) {                                                 \
            failures++;                                                \
            std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                              \
    } while (0)

void scalar_from_u64(bls_backend_fr_t *out, uint64_t v) {
    std::memset(out->b, 0, 32);
    for (int i = 0; i < 8; i++) {
        out->b[i] = static_cast<uint8_t>((v >> (8 * i)) & 0xff);
    }
}

bool scalar_eq_u64(const bls_backend_fr_t &a, uint64_t v) {
    bls_backend_fr_t b;
    scalar_from_u64(&b, v);
    return std::memcmp(a.b, b.b, 32) == 0;
}

void g1_generator(bls_backend_g1_t *out) {
    const blst_p1_affine *g = blst_p1_affine_generator();
    blst_bendian_from_fp(out->b, &g->x);
    blst_bendian_from_fp(out->b + 48, &g->y);
}

void g2_generator(bls_backend_g2_t *out) {
    const blst_p2_affine *g = blst_p2_affine_generator();
    blst_bendian_from_fp(out->b, &g->x.fp[1]);
    blst_bendian_from_fp(out->b + 48, &g->x.fp[0]);
    blst_bendian_from_fp(out->b + 96, &g->y.fp[1]);
    blst_bendian_from_fp(out->b + 144, &g->y.fp[0]);
}

blst_p1_affine decode_g1(const bls_backend_g1_t *in) {
    blst_p1_affine out;
    blst_fp_from_bendian(&out.x, in->b);
    blst_fp_from_bendian(&out.y, in->b + 48);
    return out;
}

bool g1_eq(const bls_backend_g1_t *a, const bls_backend_g1_t *b) {
    blst_p1_affine da = decode_g1(a);
    blst_p1_affine db = decode_g1(b);
    return blst_p1_affine_is_equal(&da, &db);
}

void negate_g1(blst_p1_affine *p) {
    blst_p1 proj;
    blst_p1_from_affine(&proj, p);
    blst_p1_cneg(&proj, true);
    blst_p1_to_affine(p, &proj);
}

void test_version_and_errors() {
    CHECK(bls_backend_version() == BLS_BACKEND_MODULE_VERSION);
    const char *flavor = bls_backend_flavor();
    CHECK(flavor != nullptr && flavor[0] != '\0');

    bls_backend_g1_t out;
    bls_backend_fr_t s;
    scalar_from_u64(&s, 5);
    CHECK(bls_msm_g1(nullptr, nullptr, &s, 1) == BLS_BACKEND_INVALID_ARGUMENT);
    CHECK(bls_msm_g1(&out, nullptr, &s, 1) == BLS_BACKEND_INVALID_ARGUMENT);
    CHECK(bls_msm_g1(&out, &out, nullptr, 1) == BLS_BACKEND_INVALID_ARGUMENT);

    CHECK(bls_msm_g1(&out, nullptr, nullptr, 0) == BLS_BACKEND_INFINITY_OUTPUT);

    bls_backend_g2_t out2;
    CHECK(bls_msm_g2(nullptr, nullptr, nullptr, 1) == BLS_BACKEND_INVALID_ARGUMENT);
    CHECK(bls_msm_g2(&out2, nullptr, nullptr, 0) == BLS_BACKEND_INFINITY_OUTPUT);

    int ok = -1;
    CHECK(bls_pairing_batch_check(nullptr, nullptr, 0, nullptr) ==
          BLS_BACKEND_INVALID_ARGUMENT);

    /* garbage coordinates must be rejected by the on-curve check */
    bls_backend_g1_t bad;
    std::memset(bad.b, 0xff, sizeof(bad.b));
    CHECK(bls_msm_g1(&out, &bad, &s, 1) == BLS_BACKEND_POINT_NOT_ON_CURVE);

    /* NTT: length-1 transform is the identity (any root) */
    bls_backend_fr_t root, v;
    scalar_from_u64(&root, 1);
    scalar_from_u64(&v, 3);
    CHECK(bls_ntt_in_place(&v, 1, &root, 0) == BLS_BACKEND_OK);
    CHECK(scalar_eq_u64(v, 3));

    /* non-power-of-two length and null root are rejected */
    scalar_from_u64(&v, 3);
    CHECK(bls_ntt_in_place(&v, 3, &root, 0) == BLS_BACKEND_INVALID_ARGUMENT);
    CHECK(bls_ntt_in_place(&v, 2, nullptr, 0) == BLS_BACKEND_INVALID_ARGUMENT);

    /* n = 2 oracle.  The order-2 root is -1; the forward transform with it
     * is [x0+x1, x0-x1], computed below with blst Fr arithmetic as an
     * independent known-truth. */
    bls_backend_fr_t neg_one, x0, x1;
    {
        blst_fr a_m, b_m, one_m, neg_m, sum_m, diff_m;
        uint64_t lv[4] = {5, 0, 0, 0};
        blst_fr_from_uint64(&a_m, lv);
        lv[0] = 7;
        blst_fr_from_uint64(&b_m, lv);
        lv[0] = 1;
        blst_fr_from_uint64(&one_m, lv);
        blst_fr_cneg(&neg_m, &one_m, 1); /* -1 = p - 1 */
        blst_fr_add(&sum_m, &a_m, &b_m);
        blst_fr_sub(&diff_m, &a_m, &b_m);

        blst_scalar s;
        blst_scalar_from_fr(&s, &neg_m);
        std::memcpy(neg_one.b, s.b, 32);
        blst_scalar_from_fr(&s, &sum_m);
        std::memcpy(x0.b, s.b, 32);
        blst_scalar_from_fr(&s, &diff_m);
        std::memcpy(x1.b, s.b, 32);
    }
    bls_backend_fr_t two[2], two_orig[2];
    scalar_from_u64(&two[0], 5);
    scalar_from_u64(&two[1], 7);
    two_orig[0] = two[0];
    two_orig[1] = two[1];
    CHECK(bls_ntt_in_place(two, 2, &neg_one, 0) == BLS_BACKEND_OK);
    CHECK(std::memcmp(two[0].b, x0.b, 32) == 0); /* x0 + x1 */
    CHECK(std::memcmp(two[1].b, x1.b, 32) == 0); /* x0 - x1 */
    CHECK(bls_ntt_in_place(two, 2, &neg_one, 1) == BLS_BACKEND_OK);
    CHECK(std::memcmp(two[0].b, two_orig[0].b, 32) == 0);
    CHECK(std::memcmp(two[1].b, two_orig[1].b, 32) == 0);
}

void test_msm_g1() {
    bls_backend_g1_t g;
    g1_generator(&g);

    bls_backend_fr_t s5, s3, s2, s0;
    scalar_from_u64(&s5, 5);
    scalar_from_u64(&s3, 3);
    scalar_from_u64(&s2, 2);
    scalar_from_u64(&s0, 0);

    bls_backend_g1_t out5;

    CHECK(bls_msm_g1(&out5, &g, &s5, 1) == BLS_BACKEND_OK);

    /* G*5 == G*3 + G*2 */
    {
        bls_backend_g1_t pp[2] = {g, g};
        bls_backend_fr_t ss[2] = {s3, s2};
        bls_backend_g1_t out;
        CHECK(bls_msm_g1(&out, pp, ss, 2) == BLS_BACKEND_OK);
        CHECK(g1_eq(&out, &out5));
    }

    /* skip infinity point (0,0):  inf*7 + G*3 == G*3 */
    {
        bls_backend_g1_t zero = {};
        bls_backend_g1_t pp[2] = {zero, g};
        bls_backend_fr_t ss[2] = {s5, s3};
        bls_backend_g1_t out;
        CHECK(bls_msm_g1(&out, pp, ss, 2) == BLS_BACKEND_OK);
        CHECK(g1_eq(&out, &out5) == 0);
    }

    /* skip zero scalar: G*0 + G*3 == G*3 */
    {
        bls_backend_g1_t pp[2] = {g, g};
        bls_backend_fr_t ss[2] = {s0, s3};
        bls_backend_g1_t out;
        CHECK(bls_msm_g1(&out, pp, ss, 2) == BLS_BACKEND_OK);
        bls_backend_g1_t expect;
        CHECK(bls_msm_g1(&expect, &g, &s3, 1) == BLS_BACKEND_OK);
        CHECK(g1_eq(&out, &expect));
    }
}

void test_pairing() {
    bls_backend_g1_t p;
    g1_generator(&p);
    bls_backend_g2_t q;
    g2_generator(&q);

    /* -P so that e(P,Q) * e(-P,Q) == 1 */
    blst_p1_affine p_dec = decode_g1(&p);
    negate_g1(&p_dec);
    bls_backend_g1_t neg_p;
    blst_bendian_from_fp(neg_p.b, &p_dec.x);
    blst_bendian_from_fp(neg_p.b + 48, &p_dec.y);

    bls_backend_g1_t g1s[2] = {p, neg_p};
    bls_backend_g2_t g2s[2] = {q, q};

    int ok = 0;
    CHECK(bls_pairing_batch_check(g1s, g2s, 2, &ok) == BLS_BACKEND_OK);
    CHECK(ok == 1);

    /* e(P,Q) * e(P,Q) != 1 (and both evaluations are non-identity products) */
    bls_backend_g1_t g1s_bad[2] = {p, p};
    ok = 0;
    CHECK(bls_pairing_batch_check(g1s_bad, g2s, 2, &ok) == BLS_BACKEND_OK);
    CHECK(ok == 0);

    /* empty product is the identity */
    ok = 0;
    CHECK(bls_pairing_batch_check(nullptr, nullptr, 0, &ok) == BLS_BACKEND_OK);
    CHECK(ok == 1);
}

} // namespace

int main() {
    test_version_and_errors();
    test_msm_g1();
    test_pairing();

    std::printf("bls_backend tests: %d checks, %d failures\n", checks, failures);
    return failures == 0 ? 0 : 1;
}