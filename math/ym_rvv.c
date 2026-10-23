// yesmath: the RVV 1.0 versions. Same integer arithmetic as the scalar ones in
// ym_math.c, so the results are identical (tests/ check it). Built only for
// RISC-V with V; normalize needs Zvbb (vector clz) as well, else it stays
// scalar. Register groups of 1 (2 for 64-bit results; 8 for memory copies).
#if defined(__riscv_vector)
#include <riscv_vector.h>
#include "ym_internal.h"

ym_i64 ym_dot_q16_rvv(const ym_i32* a, const ym_i32* b, ym_u64 n) {
    size_t vlmax = __riscv_vsetvlmax_e64m2();
    vint64m2_t acc = __riscv_vmv_v_x_i64m2(0, vlmax);
    for (size_t vl; n > 0; n -= vl, a += vl, b += vl) {
        vl = __riscv_vsetvl_e32m1(n);
        acc = __riscv_vwmacc_vv_i64m2_tu(acc, __riscv_vle32_v_i32m1((const int32_t*)a, vl),
                                         __riscv_vle32_v_i32m1((const int32_t*)b, vl), vl);
    }
    return __riscv_vmv_x_s_i64m1_i64(__riscv_vredsum_vs_i64m2_i64m1(acc, __riscv_vmv_v_x_i64m1(0, 1), vlmax));
}

void ym_gain_q15_rvv(const ym_i16* in, ym_i16* out, ym_u64 n, ym_i16 gain) {
    for (size_t vl; n > 0; n -= vl, in += vl, out += vl) {
        vl = __riscv_vsetvl_e16m1(n);
        __riscv_vse16_v_i16m1(out, __riscv_vsmul_vx_i16m1(__riscv_vle16_v_i16m1(in, vl), gain, __RISCV_VXRM_RNU, vl), vl);
    }
}

void ym_mix_q15_rvv(const ym_i16* a, const ym_i16* b, ym_i16* out, ym_u64 n) {
    for (size_t vl; n > 0; n -= vl, a += vl, b += vl, out += vl) {
        vl = __riscv_vsetvl_e16m1(n);
        __riscv_vse16_v_i16m1(out, __riscv_vsadd_vv_i16m1(__riscv_vle16_v_i16m1(a, vl), __riscv_vle16_v_i16m1(b, vl), vl), vl);
    }
}

void ym_biquad8_run_rvv(YmBiquad8* f, const ym_i16* in, ym_i16* out, ym_u64 frames) {
    size_t vl = __riscv_vsetvl_e64m4(8);
    if (vl < 8) { ym_biquad8_run_scalar(f, in, out, frames); return; }    // needs 8 lanes of 64 bits
    vint64m4_t s1 = __riscv_vle64_v_i64m4((const int64_t*)f->s1, vl), s2 = __riscv_vle64_v_i64m4((const int64_t*)f->s2, vl);
    for (ym_u64 i = 0; i < frames; i++, in += 8, out += 8) {
        vint64m4_t x0 = __riscv_vsext_vf4_i64m4(__riscv_vle16_v_i16m1(in, vl), vl);
        vint64m4_t acc = __riscv_vmacc_vx_i64m4(s1, f->b0, x0, vl);
        s1 = __riscv_vadd_vv_i64m4(__riscv_vsub_vv_i64m4(__riscv_vmul_vx_i64m4(x0, f->b1, vl),
                 __riscv_vsra_vx_i64m4(__riscv_vmul_vx_i64m4(acc, f->a1, vl), 14, vl), vl), s2, vl);
        s2 = __riscv_vsub_vv_i64m4(__riscv_vmul_vx_i64m4(x0, f->b2, vl),
                 __riscv_vsra_vx_i64m4(__riscv_vmul_vx_i64m4(acc, f->a2, vl), 14, vl), vl);
        vint64m4_t y0 = __riscv_vsra_vx_i64m4(__riscv_vadd_vx_i64m4(acc, 1 << 13, vl), 14, vl);
        vint32m2_t w = __riscv_vnclip_wx_i32m2(y0, 0, __RISCV_VXRM_RDN, vl);
        __riscv_vse16_v_i16m1(out, __riscv_vnclip_wx_i16m1(w, 0, __RISCV_VXRM_RDN, vl), vl);
    }
    __riscv_vse64_v_i64m4((int64_t*)f->s1, s1, vl);
    __riscv_vse64_v_i64m4((int64_t*)f->s2, s2, vl);
}

void ym_fir_sym_q15_rvv(const ym_i16* h, ym_u32 ntaps, const ym_i16* x, ym_i16* y, ym_u64 n) {
    for (size_t i = 0, vl; i < n; i += vl) {
        vl = __riscv_vsetvl_e16m1(n - i);
        vint32m2_t acc = __riscv_vmv_v_x_i32m2(0, vl);
        for (ym_u32 k = 0; k < ntaps / 2; k++) {
            vint32m2_t s = __riscv_vwadd_vv_i32m2(__riscv_vle16_v_i16m1(x + i + k, vl),
                                                  __riscv_vle16_v_i16m1(x + i + ntaps - 1 - k, vl), vl);
            acc = __riscv_vmacc_vx_i32m2(acc, h[k], s, vl);
        }
        __riscv_vse16_v_i16m1(y + i, __riscv_vnclip_wx_i16m1(acc, 15, __RISCV_VXRM_RNU, vl), vl);
    }
}

static void row_sums_rvv(const ym_u8* row, ym_u16* r, ym_u32 w) {
    for (size_t x = 1, vl; x + 1 < w; x += vl) {
        vl = __riscv_vsetvl_e8m1(w - 1 - x);
        vuint16m2_t s = __riscv_vwaddu_vv_u16m2(__riscv_vle8_v_u8m1(row + x - 1, vl), __riscv_vle8_v_u8m1(row + x + 1, vl), vl);
        s = __riscv_vadd_vv_u16m2(s, __riscv_vsll_vx_u16m2(__riscv_vzext_vf2_u16m2(__riscv_vle8_v_u8m1(row + x, vl), vl), 1, vl), vl);
        __riscv_vse16_v_u16m2(r + x, s, vl);
    }
}

void ym_blur3x3_u8_rvv(const ym_u8* src, ym_u8* dst, ym_u32 w, ym_u32 h, ym_u32 stride, ym_u16* scratch) {
    for (ym_u32 x = 0; x < w; x++) { dst[x] = src[x]; dst[(h - 1) * stride + x] = src[(h - 1) * stride + x]; }
    for (ym_u32 y = 1; y + 1 < h; y++) { dst[y * stride] = src[y * stride]; dst[y * stride + w - 1] = src[y * stride + w - 1]; }
    row_sums_rvv(src, scratch, w);
    row_sums_rvv(src + stride, scratch + w, w);
    for (ym_u32 y = 1; y + 1 < h; y++) {
        row_sums_rvv(src + (y + 1) * stride, scratch + ((y + 1) % 3) * w, w);
        const ym_u16 *a = scratch + ((y - 1) % 3) * w, *b = scratch + (y % 3) * w, *c = scratch + ((y + 1) % 3) * w;
        for (size_t x = 1, vl; x + 1 < w; x += vl) {
            vl = __riscv_vsetvl_e16m2(w - 1 - x);
            vuint16m2_t s = __riscv_vadd_vv_u16m2(__riscv_vle16_v_u16m2(a + x, vl), __riscv_vle16_v_u16m2(c + x, vl), vl);
            s = __riscv_vadd_vv_u16m2(s, __riscv_vsll_vx_u16m2(__riscv_vle16_v_u16m2(b + x, vl), 1, vl), vl);
            s = __riscv_vsrl_vx_u16m2(__riscv_vadd_vx_u16m2(s, 8, vl), 4, vl);
            __riscv_vse8_v_u8m1(dst + y * stride + x, __riscv_vncvt_x_x_w_u8m1(s, vl), vl);
        }
    }
}

void ym_memcpy_rvv(void* dst, const void* src, ym_u64 n) {
    ym_u8* d = dst;
    const ym_u8* s = src;
    for (size_t vl; n > 0; n -= vl, s += vl, d += vl) {
        vl = __riscv_vsetvl_e8m8(n);
        __riscv_vse8_v_u8m8(d, __riscv_vle8_v_u8m8(s, vl), vl);
    }
}

void ym_memset_rvv(void* dst, int c, ym_u64 n) {
    ym_u8* d = dst;
    for (size_t vl; n > 0; n -= vl, d += vl) {
        vl = __riscv_vsetvl_e8m8(n);
        __riscv_vse8_v_u8m8(d, __riscv_vmv_v_x_u8m8((ym_u8)c, vl), vl);
    }
}

#if defined(__riscv_zvbb)
// The scalar normalize lane by lane: HLL log2 with vector clz and indexed
// loads into the same tables, 2^x likewise, then the three products.
static inline vint32m1_t scale(vint32m1_t c, vint64m2_t r, size_t vl) {
    vint64m2_t p = __riscv_vmul_vv_i64m2(__riscv_vsext_vf2_i64m2(c, vl), r, vl);
    return __riscv_vnsra_wx_i32m1(__riscv_vadd_vx_i64m2(p, 1LL << 31, vl), 32, vl);
}
void ym_normalize3_batch_rvv(const ym_i32* px, const ym_i32* py, const ym_i32* pz,
                             ym_i32* ox, ym_i32* oy, ym_i32* oz, ym_u64 n) {
    const uint32_t* lt = &ym_log_seg[0].base;
    const uint32_t* et = &ym_exp_seg[0].base;
    for (size_t i0 = 0, vl; i0 < n; i0 += vl) {
        vl = __riscv_vsetvl_e32m1(n - i0);
        vint32m1_t x = __riscv_vle32_v_i32m1((const int32_t*)px + i0, vl), y = __riscv_vle32_v_i32m1((const int32_t*)py + i0, vl),
                   z = __riscv_vle32_v_i32m1((const int32_t*)pz + i0, vl);
        vint64m2_t s = __riscv_vwmul_vv_i64m2(x, x, vl);
        s = __riscv_vwmacc_vv_i64m2(s, y, y, vl);
        s = __riscv_vwmacc_vv_i64m2(s, z, z, vl);
        vuint64m2_t a = __riscv_vreinterpret_v_i64m2_u64m2(__riscv_vsra_vx_i64m2(s, 16, vl));
        vuint64m2_t lz = __riscv_vclz_v_u64m2(a, vl);
        vuint64m2_t f = __riscv_vsll_vv_u64m2(a, lz, vl);
        vuint64m2_t off = __riscv_vsll_vx_u64m2(__riscv_vand_vx_u64m2(__riscv_vsrl_vx_u64m2(f, 53, vl), 1023, vl), 3, vl);
        vuint64m2_t base = __riscv_vzext_vf2_u64m2(__riscv_vluxei64_v_u32m1(lt, off, vl), vl);
        vuint64m2_t rise = __riscv_vzext_vf2_u64m2(__riscv_vluxei64_v_u32m1(lt + 1, off, vl), vl);
        vuint64m2_t r = __riscv_vsrl_vx_u64m2(__riscv_vsll_vx_u64m2(f, 11, vl), 32, vl);
        vint64m2_t l = __riscv_vreinterpret_v_u64m2_i64m2(__riscv_vadd_vv_u64m2(
            __riscv_vadd_vv_u64m2(base, __riscv_vsrl_vx_u64m2(__riscv_vmul_vv_u64m2(rise, r, vl), 32, vl), vl),
            __riscv_vsll_vx_u64m2(__riscv_vrsub_vx_u64m2(lz, 47, vl), 32, vl), vl));
        vint64m2_t e = __riscv_vadd_vx_i64m2(__riscv_vneg_v_i64m2(__riscv_vsra_vx_i64m2(l, 1, vl), vl), 16LL << 32, vl);
        vint64m2_t sh = __riscv_vsub_vx_i64m2(__riscv_vsra_vx_i64m2(e, 32, vl), 15, vl);
        vuint64m2_t fe = __riscv_vand_vx_u64m2(__riscv_vreinterpret_v_i64m2_u64m2(e), 0xFFFFFFFFULL, vl);
        vuint64m2_t eo = __riscv_vsll_vx_u64m2(__riscv_vsrl_vx_u64m2(fe, 22, vl), 3, vl);
        vuint64m2_t eb = __riscv_vzext_vf2_u64m2(__riscv_vluxei64_v_u32m1(et, eo, vl), vl);
        vuint64m2_t er = __riscv_vzext_vf2_u64m2(__riscv_vluxei64_v_u32m1(et + 1, eo, vl), vl);
        vuint64m2_t m = __riscv_vadd_vv_u64m2(eb, __riscv_vsrl_vx_u64m2(__riscv_vmul_vv_u64m2(er,
            __riscv_vand_vx_u64m2(__riscv_vsll_vx_u64m2(fe, 10, vl), 0xFFFFFFFFULL, vl), vl), 32, vl), vl);
        vbool32_t left = __riscv_vmsge_vx_i64m2_b32(sh, 0, vl);
        vuint64m2_t up = __riscv_vreinterpret_v_i64m2_u64m2(__riscv_vmax_vx_i64m2(sh, 0, vl));
        vuint64m2_t dn = __riscv_vreinterpret_v_i64m2_u64m2(__riscv_vmax_vx_i64m2(__riscv_vneg_v_i64m2(sh, vl), 0, vl));
        vuint64m2_t vr = __riscv_vsrl_vv_u64m2(__riscv_vadd_vv_u64m2(m, __riscv_vsrl_vx_u64m2(
            __riscv_vsll_vv_u64m2(__riscv_vmv_v_x_u64m2(1, vl), dn, vl), 1, vl), vl), dn, vl);
        vint64m2_t rq = __riscv_vreinterpret_v_u64m2_i64m2(__riscv_vmerge_vvm_u64m2(vr, __riscv_vsll_vv_u64m2(m, up, vl), left, vl));
        __riscv_vse32_v_i32m1((int32_t*)ox + i0, scale(x, rq, vl), vl);
        __riscv_vse32_v_i32m1((int32_t*)oy + i0, scale(y, rq, vl), vl);
        __riscv_vse32_v_i32m1((int32_t*)oz + i0, scale(z, rq, vl), vl);
    }
}
#else
void ym_normalize3_batch_rvv(const ym_i32* x, const ym_i32* y, const ym_i32* z,
                             ym_i32* ox, ym_i32* oy, ym_i32* oz, ym_u64 n) {
    ym_normalize3_batch_scalar(x, y, z, ox, oy, oz, n);   // no vector clz: the scalar version
}
#endif

#endif // __riscv_vector
