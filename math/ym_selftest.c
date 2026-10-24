// yesmath self-check: every public function on inputs from a fixed
// pseudo-random sequence; each one's outputs are reduced to an FNV-1a hash.
// (No timing: under QEMU without -icount minstret follows the clock, not the
// instructions; the costs were measured in the lab with -icount.)
// The same file is built into the kernel (`math test`) and, with YM_HOST,
// into the host library of tools/test_math.py, so both sides compute the same
// hashes from the same inputs. The batch functions run twice when the hart
// has V: scalar, then vector; the results must be identical.
#include "ym_internal.h"

#define N_MATH 256
#define N_VEC 256
#define N_DOT 1024
#define N_AUD 1024
#define N_FRAMES 256
#define N_FIR 512
#define FIR_TAPS 32
#define N_RSX 600
#define N_RS 512
#define IMG_W 64
#define IMG_H 64
#define N_MEM 4096

static ym_u64 g_rng;
static ym_u64 rnd(void) { g_rng ^= g_rng << 13; g_rng ^= g_rng >> 7; g_rng ^= g_rng << 17; return g_rng; }
static ym_i64 rnd_pm(ym_u64 range) { return (ym_i64)(rnd() % (2 * range + 1)) - (ym_i64)range; }   // [-range, range]

static ym_u64 fnv(const void* p, ym_u64 n, ym_u64 h) {
    const ym_u8* b = p;
    for (ym_u64 i = 0; i < n; i++) { h ^= b[i]; h *= 0x100000001B3ULL; }
    return h;
}
#define FNV0 0xCBF29CE484222325ULL

static ym_u64 m_pos[N_MATH], m_powx[N_MATH], o64[N_MATH];
static ym_i64 m_log[N_MATH], m_exp[N_MATH], m_powp[N_MATH], m_ang[N_MATH], m_y[N_MATH], m_x[N_MATH];
static ym_i32 v_x[N_VEC], v_y[N_VEC], v_z[N_VEC], n_x[N_VEC], n_y[N_VEC], n_z[N_VEC];
static ym_i32 d_a[N_DOT], d_b[N_DOT];
static ym_i16 au_a[N_AUD], au_b[N_AUD], au_o[N_AUD];
static ym_i16 bq_in[N_FRAMES * 8], bq_out[N_FRAMES * 8];
static ym_i16 fir_x[N_FIR + FIR_TAPS - 1], fir_y[N_FIR];
static ym_i16 rs_x[N_RSX], rs_y[N_RS];
static ym_u8 img_in[IMG_W * IMG_H], img_out[IMG_W * IMG_H];
static ym_u16 scratch[3 * IMG_W];
static ym_u8 mem_src[N_MEM], mem_dst[N_MEM + 16] __attribute__((aligned(8)));
static YmBiquad8 bq;

// 32-tap low-pass (windowed sinc, cut-off 0.2 of the rate, unity gain): first half
static const ym_i16 fir_h[FIR_TAPS] = {
    0, -2, -11, 0, 62, 70, -120, -313, 0, 725, 659, -962, -2300, 0, 6366, 12209,
    12209, 6366, 0, -2300, -962, 659, 725, 0, -313, -120, 70, 62, 0, -11, -2, 0 };
// Low-pass biquad, f0 = 0.05 of the rate, Q 0.707, Q14 {b0, b1, b2, a1, a2}
static const ym_i32 bq_coef[5] = { 329, 658, 329, -25575, 10507 };

static void make_inputs(void) {
    g_rng = 0x59455353454C4654ULL;                         // "YESSELFT"
    for (int i = 0; i < N_MATH; i++) {
        m_pos[i] = 1024 + rnd() % (30000ULL << 16);         // [1/64, 30000]
        m_log[i] = (ym_i64)(rnd() % (52ULL << 32)) - (6LL << 32);
        m_exp[i] = rnd_pm(10 << 16);
        m_powx[i] = 4096 + rnd() % (100ULL << 16);
        m_powp[i] = rnd_pm(3 << 16);
        m_ang[i] = rnd_pm(1000LL << 16);
        m_y[i] = i ? rnd_pm(1000LL << 16) : 0;               // atan2(0, 0) included
        m_x[i] = i ? rnd_pm(1000LL << 16) : 0;
    }
    for (int i = 0; i < N_VEC; i++) {
        v_x[i] = (ym_i32)rnd_pm(1000 << 16); v_y[i] = (ym_i32)rnd_pm(1000 << 16); v_z[i] = (ym_i32)rnd_pm(1000 << 16);
    }
    for (int i = 0; i < N_DOT; i++) { d_a[i] = (ym_i32)rnd_pm(1000 << 16); d_b[i] = (ym_i32)rnd_pm(1000 << 16); }
    for (int i = 0; i < N_AUD; i++) { au_a[i] = (ym_i16)rnd_pm(32767); au_b[i] = (ym_i16)rnd_pm(32767); }
    au_a[0] = au_b[0] = -32768;                            // both saturation ends
    au_a[1] = au_b[1] = 32767;
    for (int i = 0; i < N_FRAMES * 8; i++) bq_in[i] = (ym_i16)rnd_pm(20000);
    for (int i = 0; i < N_FIR + FIR_TAPS - 1; i++) fir_x[i] = (ym_i16)rnd_pm(32767);
    for (int i = 0; i < N_RSX; i++)                        // 5 kHz at 44.1 kHz, half scale; x[3] is time 0
        rs_x[i] = (ym_i16)((ym_sin_q16((ym_i64)(i - 3) * 5000 * 411775 / 44100) * 16384) >> 16);
    for (int i = 0; i < IMG_W * IMG_H; i++) img_in[i] = (ym_u8)rnd();
    for (int i = 0; i < N_MEM; i++) mem_src[i] = (ym_u8)rnd();
}

typedef void (*YmReport)(const char* name, int rvv, ym_u64 hash);

#define MATH1(name, expr) do { for (int i = 0; i < N_MATH; i++) o64[i] = (ym_u64)(expr); \
    rep(name, 0, fnv(o64, sizeof(o64), FNV0)); } while (0)

#define RUN(name, rvv, call, hash) do { call; rep(name, rvv, hash); } while (0)

static void batch(YmReport rep, int rvv) {
    RUN("normalize3", rvv, ym_normalize3_batch(v_x, v_y, v_z, n_x, n_y, n_z, N_VEC),
          fnv(n_z, sizeof(n_z), fnv(n_y, sizeof(n_y), fnv(n_x, sizeof(n_x), FNV0))));
    ym_i64 s = 0;
    RUN("dot", rvv, s = ym_dot_q16(d_a, d_b, N_DOT), fnv(&s, 8, FNV0));
    RUN("gain", rvv, ym_gain_q15(au_a, au_o, N_AUD, 23170), fnv(au_o, sizeof(au_o), FNV0));
    RUN("mix", rvv, ym_mix_q15(au_a, au_b, au_o, N_AUD), fnv(au_o, sizeof(au_o), FNV0));
    ym_biquad8_init(&bq, bq_coef);
    RUN("biquad8", rvv, ym_biquad8_run(&bq, bq_in, bq_out, N_FRAMES),
          fnv(bq.s2, sizeof(bq.s2), fnv(bq.s1, sizeof(bq.s1), fnv(bq_out, sizeof(bq_out), FNV0))));
    RUN("fir_sym", rvv, ym_fir_sym_q15(fir_h, FIR_TAPS, fir_x, fir_y, N_FIR), fnv(fir_y, sizeof(fir_y), FNV0));
    RUN("blur3x3", rvv, ym_blur3x3_u8(img_in, img_out, IMG_W, IMG_H, IMG_W, scratch),
          fnv(img_out, sizeof(img_out), FNV0));
    for (int i = 0; i < N_MEM + 16; i++) mem_dst[i] = 0;
    RUN("memcpy", rvv, ym_memcpy(mem_dst + 3, mem_src + 5, N_MEM - 7), fnv(mem_dst, sizeof(mem_dst), FNV0));
    for (int i = 0; i < N_MEM + 16; i++) mem_dst[i] = 0;
    RUN("memset", rvv, ym_memset(mem_dst + 1, 0xA7, N_MEM - 3), fnv(mem_dst, sizeof(mem_dst), FNV0));
    for (int i = 0; i < N_MEM + 16; i++) mem_dst[i] = 0;
    RUN("fill32", rvv, ym_fill32((ym_u32*)(void*)(mem_dst + 4), 0x00C0FFEEu, N_MEM / 4 - 3), fnv(mem_dst, sizeof(mem_dst), FNV0));
}

void ym_selftest(YmReport rep) {
    int was = ym_has_rvv();
    make_inputs();
    MATH1("sqrt", ym_sqrt_q16(m_pos[i]));
    MATH1("rsqrt_q16", ym_rsqrt_q16(m_pos[i]));
    MATH1("rsqrt_q32", ym_rsqrt_q32(m_pos[i]));
    MATH1("log2_q32", ym_log2_q32(m_pos[i]));
    MATH1("exp2", ym_exp2_q16(m_log[i]));
    MATH1("exp", ym_exp_q16(m_exp[i]));
    MATH1("ln", ym_ln_q16(m_pos[i]));
    MATH1("pow", ym_pow_q16(m_powx[i], m_powp[i]));
    MATH1("sin", ym_sin_q16(m_ang[i]));
    MATH1("cos", ym_cos_q16(m_ang[i]));
    MATH1("atan2", ym_atan2_q16(m_y[i], m_x[i]));
    ym_use_rvv(0);
    batch(rep, 0);
    if (was) {
        ym_use_rvv(1);
        batch(rep, 1);
    }
    ym_use_rvv(was);
    ym_u64 pos = 3ULL << 32, m = 0;
    RUN("resample", 0, m = ym_resample_sinc8(rs_x, N_RSX, rs_y, N_RS, &pos, 0xEB333333ULL),
          fnv(rs_y, m * 2, fnv(&pos, 8, FNV0)));
}
