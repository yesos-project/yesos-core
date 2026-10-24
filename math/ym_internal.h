#ifndef YM_INTERNAL_H
#define YM_INTERNAL_H
// yesmath internals: tables, constants, and the scalar and vector versions
// that the public functions choose between (ym_dispatch.c).
#include "yesmath.h"

typedef __int128 ym_i128;
typedef struct { ym_u32 base, rise; } YmSegU;     // a segment: value at its start, rise over it
typedef struct { ym_i32 base, rise; } YmSegI;

extern const YmSegU ym_log_seg[1024];              // log2(1 + f), Q32
extern const YmSegU ym_exp_seg[1024];              // 2^f, Q31
extern const YmSegI ym_sin_seg[1024];              // sin(2 pi t), Q30
extern const YmSegU ym_atan_seg[1024];             // atan(t), t in [0, 1], Q32
extern const ym_i16 ym_sinc8[256][8];               // resampler phases, Q15

#define YM_LN2_Q32         2977044472LL
#define YM_LOG2E_Q32       6196328019LL
#define YM_PI_Q32          13493037705LL
#define YM_HALF_PI_Q32     6746518852LL
#define YM_QUARTER_PI_Q32  3373259426LL
#define YM_INV_2PI_Q32     683565276LL

extern int ym_rvv_on;

// Scalar versions (always built).
void   ym_normalize3_batch_scalar(const ym_i32* x, const ym_i32* y, const ym_i32* z, ym_i32* ox, ym_i32* oy, ym_i32* oz, ym_u64 n);
ym_i64 ym_dot_q16_scalar(const ym_i32* a, const ym_i32* b, ym_u64 n);
void   ym_gain_q15_scalar(const ym_i16* in, ym_i16* out, ym_u64 n, ym_i16 gain);
void   ym_mix_q15_scalar(const ym_i16* a, const ym_i16* b, ym_i16* out, ym_u64 n);
void   ym_biquad8_run_scalar(YmBiquad8* f, const ym_i16* in, ym_i16* out, ym_u64 frames);
void   ym_fir_sym_q15_scalar(const ym_i16* h, ym_u32 ntaps, const ym_i16* x, ym_i16* y, ym_u64 n);
void   ym_blur3x3_u8_scalar(const ym_u8* src, ym_u8* dst, ym_u32 w, ym_u32 h, ym_u32 stride, ym_u16* scratch);
void   ym_memcpy_scalar(void* dst, const void* src, ym_u64 n);
void   ym_memset_scalar(void* dst, int c, ym_u64 n);
void   ym_fill32_scalar(ym_u32* dst, ym_u32 v, ym_u64 n);

// Vector versions (ym_rvv.c, only when built for RISC-V with V).
void   ym_normalize3_batch_rvv(const ym_i32* x, const ym_i32* y, const ym_i32* z, ym_i32* ox, ym_i32* oy, ym_i32* oz, ym_u64 n);
ym_i64 ym_dot_q16_rvv(const ym_i32* a, const ym_i32* b, ym_u64 n);
void   ym_gain_q15_rvv(const ym_i16* in, ym_i16* out, ym_u64 n, ym_i16 gain);
void   ym_mix_q15_rvv(const ym_i16* a, const ym_i16* b, ym_i16* out, ym_u64 n);
void   ym_biquad8_run_rvv(YmBiquad8* f, const ym_i16* in, ym_i16* out, ym_u64 frames);
void   ym_fir_sym_q15_rvv(const ym_i16* h, ym_u32 ntaps, const ym_i16* x, ym_i16* y, ym_u64 n);
void   ym_blur3x3_u8_rvv(const ym_u8* src, ym_u8* dst, ym_u32 w, ym_u32 h, ym_u32 stride, ym_u16* scratch);
void   ym_memcpy_rvv(void* dst, const void* src, ym_u64 n);
void   ym_memset_rvv(void* dst, int c, ym_u64 n);
void   ym_fill32_rvv(ym_u32* dst, ym_u32 v, ym_u64 n);

static inline ym_i16 ym_sat16(ym_i64 v) { return v > 32767 ? 32767 : v < -32768 ? -32768 : (ym_i16)v; }

#endif
