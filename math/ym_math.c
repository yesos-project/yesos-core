// yesmath: the scalar functions (see yesmath.h). Each one is the champion of
// its contest in the YesOS lab, with the same arithmetic. Integer only.
#include "ym_internal.h"

// ---- HLL: log2 and 2^x through tables of 1024 segments -----------------------------
ym_i64 ym_log2_q32(ym_u64 a) {
    ym_u32 z = (ym_u32)__builtin_clzll(a);                // top bit 63 - z: log2 = 63 - z - 16 + log2(1 + f)
    ym_u64 f = a << z;
    const YmSegU* s = &ym_log_seg[(f >> 53) & 1023];
    ym_u64 r = (f << 11) >> 32;                           // position inside the segment, Q32
    return ((ym_i64)(47 - z) << 32) + s->base + (ym_i64)(((ym_u64)s->rise * r) >> 32);
}

ym_u64 ym_exp2_q16(ym_i64 l) {
    ym_i64 n = l >> 32;
    ym_u32 f = (ym_u32)l;
    const YmSegU* s = &ym_exp_seg[f >> 22];
    ym_u64 m = s->base + (((ym_u64)s->rise * (ym_u32)(f << 10)) >> 32);   // 2^f in [1, 2), Q31
    ym_i64 sh = n - 15;
    if (sh >= 32) return ~0ULL;
    if (sh >= 0) return m << sh;
    if (sh < -33) return 0;
    return (m + (1ULL << (-sh - 1))) >> -sh;
}

ym_u64 ym_sqrt_q16(ym_u64 a) { return ym_exp2_q16(ym_log2_q32(a) >> 1); }
ym_u64 ym_rsqrt_q16(ym_u64 a) { return ym_exp2_q16(-(ym_log2_q32(a) >> 1)); }
ym_u64 ym_rsqrt_q32(ym_u64 a) { return ym_exp2_q16(-(ym_log2_q32(a) >> 1) + (16LL << 32)); }
ym_u64 ym_exp_q16(ym_i64 x) { return ym_exp2_q16((ym_i64)(((ym_i128)x * YM_LOG2E_Q32) >> 16)); }
ym_i64 ym_ln_q16(ym_u64 x) { return (ym_i64)(((ym_i128)ym_log2_q32(x) * YM_LN2_Q32 + ((ym_i128)1 << 47)) >> 48); }
ym_u64 ym_pow_q16(ym_u64 x, ym_i64 p) { return ym_exp2_q16((ym_i64)(((ym_i128)ym_log2_q32(x) * p) >> 16)); }

// ---- sin, cos: one turn in 1024 segments -----------------------------------------------
static ym_i64 sin_turns(ym_u32 u) {                       // u: turns, Q32
    const YmSegI* s = &ym_sin_seg[u >> 22];
    ym_i64 v = s->base + (((ym_i64)s->rise * (ym_i64)(u & ((1u << 22) - 1))) >> 22);
    return (v + (1 << 13)) >> 14;
}
static ym_u32 turns(ym_i64 x) { return (ym_u32)(ym_u64)(((ym_i128)x * YM_INV_2PI_Q32) >> 16); }
ym_i64 ym_sin_q16(ym_i64 x) { return sin_turns(turns(x)); }
ym_i64 ym_cos_q16(ym_i64 x) { return sin_turns(turns(x) + 0x40000000u); }

// ---- atan2: one octant, t = small / large, atan(t) from a table ----------------------
ym_i64 ym_atan2_q16(ym_i64 y, ym_i64 x) {
    if (x == 0 && y == 0) return 0;
    ym_u64 ax = x < 0 ? (ym_u64)-x : (ym_u64)x, ay = y < 0 ? (ym_u64)-y : (ym_u64)y;
    int swap = ay > ax;
    ym_u64 num = swap ? ax : ay, den = swap ? ay : ax;
    while ((num | den) >> 31) { num >>= 1; den >>= 1; }
    ym_u64 t = (num << 32) / den;
    ym_i64 a;
    if (t >> 32) a = YM_QUARTER_PI_Q32;
    else {
        const YmSegU* s = &ym_atan_seg[t >> 22];
        a = (ym_i64)s->base + (ym_i64)(((ym_u64)s->rise * (t & ((1u << 22) - 1))) >> 22);
    }
    if (swap) a = YM_HALF_PI_Q32 - a;
    if (x < 0) a = YM_PI_Q32 - a;
    if (y < 0) a = -a;
    return (a + 0x8000) >> 16;
}

// ---- 3D ------------------------------------------------------------------------------
static inline ym_i32 scale_q32(ym_i32 c, ym_i64 r) { return (ym_i32)(((ym_i128)c * r + ((ym_i128)1 << 31)) >> 32); }

void ym_normalize3_q16(const ym_i32 v[3], ym_i32 out[3]) {
    ym_i64 len2 = ((ym_i64)v[0] * v[0] + (ym_i64)v[1] * v[1] + (ym_i64)v[2] * v[2]) >> 16;
    ym_i64 r = (ym_i64)ym_rsqrt_q32((ym_u64)len2);
    for (int i = 0; i < 3; i++) out[i] = scale_q32(v[i], r);
}

void ym_normalize3_batch_scalar(const ym_i32* x, const ym_i32* y, const ym_i32* z,
                                ym_i32* ox, ym_i32* oy, ym_i32* oz, ym_u64 n) {
    for (ym_u64 i = 0; i < n; i++) {
        ym_i32 v[3] = { x[i], y[i], z[i] }, o[3];
        ym_normalize3_q16(v, o);
        ox[i] = o[0]; oy[i] = o[1]; oz[i] = o[2];
    }
}

ym_i64 ym_dot_q16_scalar(const ym_i32* a, const ym_i32* b, ym_u64 n) {
    ym_i64 s = 0;
    for (ym_u64 i = 0; i < n; i++) s += (ym_i64)a[i] * b[i];
    return s;
}

// ---- audio --------------------------------------------------------------------------
void ym_gain_q15_scalar(const ym_i16* in, ym_i16* out, ym_u64 n, ym_i16 gain) {
    for (ym_u64 i = 0; i < n; i++) out[i] = ym_sat16(((ym_i32)in[i] * gain + (1 << 14)) >> 15);
}

void ym_mix_q15_scalar(const ym_i16* a, const ym_i16* b, ym_i16* out, ym_u64 n) {
    for (ym_u64 i = 0; i < n; i++) out[i] = ym_sat16((ym_i32)a[i] + b[i]);
}

void ym_biquad_init(YmBiquad* f, const ym_i32 c[5]) {
    f->b0 = c[0]; f->b1 = c[1]; f->b2 = c[2]; f->a1 = c[3]; f->a2 = c[4];
    f->s1 = f->s2 = 0;
}

void ym_biquad_run(YmBiquad* f, const ym_i16* in, ym_i16* out, ym_u64 n, ym_u64 stride) {
    ym_i64 s1 = f->s1, s2 = f->s2;
    for (ym_u64 i = 0; i < n; i++) {
        ym_i64 x0 = in[i * stride];
        ym_i64 acc = f->b0 * x0 + s1;                     // Q29
        s1 = f->b1 * x0 - ((f->a1 * acc) >> 14) + s2;
        s2 = f->b2 * x0 - ((f->a2 * acc) >> 14);
        out[i * stride] = ym_sat16((acc + (1 << 13)) >> 14);
    }
    f->s1 = s1;
    f->s2 = s2;
}

void ym_biquad8_init(YmBiquad8* f, const ym_i32 c[5]) {
    f->b0 = c[0]; f->b1 = c[1]; f->b2 = c[2]; f->a1 = c[3]; f->a2 = c[4];
    for (int k = 0; k < 8; k++) f->s1[k] = f->s2[k] = 0;
}

void ym_biquad8_run_scalar(YmBiquad8* f, const ym_i16* in, ym_i16* out, ym_u64 frames) {
    for (int c = 0; c < 8; c++) {
        YmBiquad one = { f->b0, f->b1, f->b2, f->a1, f->a2, f->s1[c], f->s2[c] };
        ym_biquad_run(&one, in + c, out + c, frames, 8);
        f->s1[c] = one.s1;
        f->s2[c] = one.s2;
    }
}

void ym_fir_sym_q15_scalar(const ym_i16* h, ym_u32 ntaps, const ym_i16* x, ym_i16* y, ym_u64 n) {
    for (ym_u64 i = 0; i < n; i++) {
        ym_i32 acc = 0;
        for (ym_u32 k = 0; k < ntaps / 2; k++) acc += (ym_i32)h[k] * (x[i + k] + x[i + ntaps - 1 - k]);
        y[i] = ym_sat16((acc + (1 << 14)) >> 15);
    }
}

ym_u64 ym_resample_sinc8(const ym_i16* x, ym_u64 nx, ym_i16* y, ym_u64 ny, ym_u64* pos, ym_u64 step) {
    ym_u64 m = 0, p = *pos;
    for (; m < ny; m++, p += step) {
        ym_u64 q = p + (1ULL << 23);                      // the nearest of 256 phases
        ym_u64 i = q >> 32;
        if (i < 3 || i + 4 >= nx) break;
        const ym_i16* h = ym_sinc8[(q >> 24) & 255];
        ym_i32 acc = 0;
        for (int k = 0; k < 8; k++) acc += (ym_i32)h[k] * x[i - 3 + k];
        y[m] = ym_sat16((acc + (1 << 14)) >> 15);
    }
    *pos = p;
    return m;
}

// ---- images --------------------------------------------------------------------------
// Row sums r = p[x-1] + 2 p[x] + p[x+1] kept for three rows in scratch.
static void row_sums(const ym_u8* row, ym_u16* r, ym_u32 w) {
    for (ym_u32 x = 1; x + 1 < w; x++) r[x] = (ym_u16)(row[x - 1] + 2 * row[x] + row[x + 1]);
}

static void blur_border(const ym_u8* src, ym_u8* dst, ym_u32 w, ym_u32 h, ym_u32 stride) {
    for (ym_u32 x = 0; x < w; x++) { dst[x] = src[x]; dst[(h - 1) * stride + x] = src[(h - 1) * stride + x]; }
    for (ym_u32 y = 1; y + 1 < h; y++) { dst[y * stride] = src[y * stride]; dst[y * stride + w - 1] = src[y * stride + w - 1]; }
}

void ym_blur3x3_u8_scalar(const ym_u8* src, ym_u8* dst, ym_u32 w, ym_u32 h, ym_u32 stride, ym_u16* scratch) {
    blur_border(src, dst, w, h, stride);
    row_sums(src, scratch, w);
    row_sums(src + stride, scratch + w, w);
    for (ym_u32 y = 1; y + 1 < h; y++) {
        row_sums(src + (y + 1) * stride, scratch + ((y + 1) % 3) * w, w);
        const ym_u16 *a = scratch + ((y - 1) % 3) * w, *b = scratch + (y % 3) * w, *c = scratch + ((y + 1) % 3) * w;
        for (ym_u32 x = 1; x + 1 < w; x++) dst[y * stride + x] = (ym_u8)((a[x] + 2 * b[x] + c[x] + 8) >> 4);
    }
}

// ---- memory -----------------------------------------------------------------------------
void ym_memcpy_scalar(void* dst, const void* src, ym_u64 n) {
    ym_u8* d = dst;
    const ym_u8* s = src;
    if ((((ym_u64)d ^ (ym_u64)s) & 7) == 0) {
        while (n && ((ym_u64)d & 7)) { *d++ = *s++; n--; }
        for (; n >= 8; n -= 8, d += 8, s += 8) *(ym_u64*)d = *(const ym_u64*)s;
    }
    while (n--) *d++ = *s++;
}

void ym_memset_scalar(void* dst, int c, ym_u64 n) {
    ym_u8* d = dst;
    ym_u64 w = (ym_u8)c * 0x0101010101010101ULL;
    while (n && ((ym_u64)d & 7)) { *d++ = (ym_u8)c; n--; }
    for (; n >= 8; n -= 8, d += 8) *(ym_u64*)d = w;
    while (n--) *d++ = (ym_u8)c;
}
