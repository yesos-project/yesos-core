#ifndef YESMATH_H
#define YESMATH_H

// yesmath: integer math for bare-metal RISC-V (RV64 with Zbb; RVV 1.0 used
// when the hart has it), the optional core module "math" (sources in math/).
// Each function is the method that won a contest of candidates in the YesOS
// lab (accuracy against exact math, retired instructions on RISC-V);
// tools/test_math.py checks the accuracy stated here.
// No floating point anywhere. Self-contained types (ym_*), so this header
// can be included next to the YesOS types.h or the compiler's <stdint.h>.
//
// Formats: Q16.16 is a signed or unsigned 64-bit integer holding value * 2^16;
// Q32 holds value * 2^32; Q15 audio samples are int16 (value * 32768); Q14
// filter coefficients are value * 16384.

typedef signed char        ym_i8;
typedef unsigned char      ym_u8;
typedef signed short       ym_i16;
typedef unsigned short     ym_u16;
typedef signed int         ym_i32;
typedef unsigned int       ym_u32;
typedef signed long long   ym_i64;
typedef unsigned long long ym_u64;

// ---- setup ---------------------------------------------------------------------------
// Picks the vector versions if the hart has the V extension (misa), else the
// scalar ones; results are identical either way. The caller must have enabled
// the vector unit (mstatus.VS; the YesOS boot does) before using yesmath on a hart with V.
void ym_init(void);
int  ym_has_rvv(void);              // 1 if the vector versions are in use
void ym_use_rvv(int on);            // tests: force one or the other (on = 0: scalar)

// ---- Q16.16 functions -------------------------------------------------------------------
// HLL (hybrid linear-logarithmic): log2 by clz and a table of 1024 segments,
// 2^x by a table. "Q16-accurate": within one Q16.16 step (2^-16) of the exact
// value, or within 2^-20 of it when the value is large (tests/test_yesmath.py).
ym_u64 ym_sqrt_q16(ym_u64 a);               // sqrt(a), a > 0: within 1 step (a < 30000)
ym_u64 ym_rsqrt_q16(ym_u64 a);              // 1/sqrt(a), a > 0: within 1 step
ym_u64 ym_rsqrt_q32(ym_u64 a);              // 1/sqrt(a) as Q32, a > 0: 2^16 more resolution
ym_i64 ym_log2_q32(ym_u64 a);               // log2(a) as Q32, a > 0: within 2^-23
ym_u64 ym_exp2_q16(ym_i64 l);               // 2^(l / 2^32): Q16-accurate; 0 below 2^-17, saturated above 2^47
ym_u64 ym_exp_q16(ym_i64 x);                // e^x: Q16-accurate (x in [-10, 10] tested)
ym_i64 ym_ln_q16(ym_u64 x);                 // ln(x), x > 0: within 1 step
ym_u64 ym_pow_q16(ym_u64 x, ym_i64 p);      // x^p, x > 0: Q16-accurate (x in [1/16, 100], p in [-3, 3], results in [1/64, 30000])
ym_i64 ym_sin_q16(ym_i64 x);                // sin(x), any x: within 1 step (table, 1024 segments)
ym_i64 ym_cos_q16(ym_i64 x);                // cos(x), any x: within 1 step
ym_i64 ym_atan2_q16(ym_i64 y, ym_i64 x);    // atan2(y, x) in [-pi, pi]: within 1 step; 0 for (0, 0)

// ---- 3D ---------------------------------------------------------------------------------
// v / |v| for Q16.16 vectors with |v| >= 2^-8 and components below 2^15.
void ym_normalize3_q16(const ym_i32 v[3], ym_i32 out[3]);
void ym_normalize3_batch(const ym_i32* x, const ym_i32* y, const ym_i32* z,
                         ym_i32* ox, ym_i32* oy, ym_i32* oz, ym_u64 n);
// Exact sum of a[i] * b[i] (Q16.16 inputs give a Q32 sum).
ym_i64 ym_dot_q16(const ym_i32* a, const ym_i32* b, ym_u64 n);

// ---- audio (Q15 samples) --------------------------------------------------------------
void ym_gain_q15(const ym_i16* in, ym_i16* out, ym_u64 n, ym_i16 gain);   // sat((x g + 2^14) >> 15)
void ym_mix_q15(const ym_i16* a, const ym_i16* b, ym_i16* out, ym_u64 n);  // sat(a + b)

// Biquad, transposed direct form II, Q14 coefficients {b0, b1, b2, a1, a2}
// (a0 = 1); its states keep 14 more bits than the samples.
typedef struct { ym_i64 b0, b1, b2, a1, a2, s1, s2; } YmBiquad;
void ym_biquad_init(YmBiquad* f, const ym_i32 coef_q14[5]);
void ym_biquad_run(YmBiquad* f, const ym_i16* in, ym_i16* out, ym_u64 n, ym_u64 stride);
// The same filter on 8 channels of interleaved frames (frame i: 8 samples).
typedef struct { ym_i64 b0, b1, b2, a1, a2, s1[8], s2[8]; } YmBiquad8;
void ym_biquad8_init(YmBiquad8* f, const ym_i32 coef_q14[5]);
void ym_biquad8_run(YmBiquad8* f, const ym_i16* in, ym_i16* out, ym_u64 frames);

// Symmetric FIR: y[i] = sat((sum h[k] x[i + k] + 2^14) >> 15), ntaps even,
// h[k] = h[ntaps - 1 - k] (only the first half is read); x holds n + ntaps - 1
// samples, and sum |h| must stay below 2^16 (gain below 2).
void ym_fir_sym_q15(const ym_i16* h, ym_u32 ntaps, const ym_i16* x, ym_i16* y, ym_u64 n);

// Resampling with an 8-tap windowed sinc (256 phases): output m is the input
// at position pos + m * step (Q32, in input samples), from x[i - 3 .. i + 4].
// Writes up to ny outputs while the taps stay inside x[0 .. nx - 1]; returns
// how many, and the next position in *pos. step = (rate_in << 32) / rate_out.
ym_u64 ym_resample_sinc8(const ym_i16* x, ym_u64 nx, ym_i16* y, ym_u64 ny, ym_u64* pos, ym_u64 step);

// ---- images --------------------------------------------------------------------------
// 3x3 Gaussian blur ([1 2 1] x [1 2 1] / 16, rounded) of an 8-bit image, w >= 3,
// h >= 3; the border pixels are copied. scratch: 3 * w 16-bit values.
void ym_blur3x3_u8(const ym_u8* src, ym_u8* dst, ym_u32 w, ym_u32 h, ym_u32 stride, ym_u16* scratch);

// ---- memory ----------------------------------------------------------------------------
void ym_memcpy(void* dst, const void* src, ym_u64 n);
void ym_memset(void* dst, int c, ym_u64 n);
void ym_fill32(ym_u32* dst, ym_u32 v, ym_u64 n);   // n 32-bit words (dst 4-byte aligned), e.g. pixels

#endif // YESMATH_H
