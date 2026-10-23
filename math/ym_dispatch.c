// yesmath: choosing between the scalar and the vector versions.
#include "ym_internal.h"

int ym_rvv_on;

void ym_init(void) {
    ym_rvv_on = 0;
#if defined(__riscv_vector) && !defined(YM_HOST)
    ym_u64 misa;
    __asm__ __volatile__("csrr %0, misa" : "=r"(misa));          // machine mode
    ym_rvv_on = (misa >> ('V' - 'A')) & 1;
#endif
}

int  ym_has_rvv(void) { return ym_rvv_on; }
void ym_use_rvv(int on) {
#if defined(__riscv_vector) && !defined(YM_HOST)
    ym_rvv_on = on != 0;
#else
    (void)on;
#endif
}

#if defined(__riscv_vector) && !defined(YM_HOST)
#define PICK(call_rvv, call_scalar) do { if (ym_rvv_on) call_rvv; else call_scalar; } while (0)
#else
#define PICK(call_rvv, call_scalar) call_scalar
#endif

void ym_normalize3_batch(const ym_i32* x, const ym_i32* y, const ym_i32* z, ym_i32* ox, ym_i32* oy, ym_i32* oz, ym_u64 n) {
    PICK(ym_normalize3_batch_rvv(x, y, z, ox, oy, oz, n), ym_normalize3_batch_scalar(x, y, z, ox, oy, oz, n));
}
ym_i64 ym_dot_q16(const ym_i32* a, const ym_i32* b, ym_u64 n) {
#if defined(__riscv_vector) && !defined(YM_HOST)
    if (ym_rvv_on) return ym_dot_q16_rvv(a, b, n);
#endif
    return ym_dot_q16_scalar(a, b, n);
}
void ym_gain_q15(const ym_i16* in, ym_i16* out, ym_u64 n, ym_i16 g) { PICK(ym_gain_q15_rvv(in, out, n, g), ym_gain_q15_scalar(in, out, n, g)); }
void ym_mix_q15(const ym_i16* a, const ym_i16* b, ym_i16* out, ym_u64 n) { PICK(ym_mix_q15_rvv(a, b, out, n), ym_mix_q15_scalar(a, b, out, n)); }
void ym_biquad8_run(YmBiquad8* f, const ym_i16* in, ym_i16* out, ym_u64 frames) {
    PICK(ym_biquad8_run_rvv(f, in, out, frames), ym_biquad8_run_scalar(f, in, out, frames));
}
void ym_fir_sym_q15(const ym_i16* h, ym_u32 ntaps, const ym_i16* x, ym_i16* y, ym_u64 n) {
    PICK(ym_fir_sym_q15_rvv(h, ntaps, x, y, n), ym_fir_sym_q15_scalar(h, ntaps, x, y, n));
}
void ym_blur3x3_u8(const ym_u8* src, ym_u8* dst, ym_u32 w, ym_u32 h, ym_u32 stride, ym_u16* scratch) {
    PICK(ym_blur3x3_u8_rvv(src, dst, w, h, stride, scratch), ym_blur3x3_u8_scalar(src, dst, w, h, stride, scratch));
}
void ym_memcpy(void* d, const void* s, ym_u64 n) { PICK(ym_memcpy_rvv(d, s, n), ym_memcpy_scalar(d, s, n)); }
void ym_memset(void* d, int c, ym_u64 n) { PICK(ym_memset_rvv(d, c, n), ym_memset_scalar(d, c, n)); }
