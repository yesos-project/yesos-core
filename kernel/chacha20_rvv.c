// ChaCha20, the RVV 1.0 version (see kernel/chacha20.c for the method).
// Standard types only: <riscv_vector.h> brings <stdint.h>.
#include <riscv_vector.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_BLOCKS 8

static void wipe(volatile uint8_t* p, size_t n) {
    while (n--) *p++ = 0;
}


#define VROTL(x, n, vl) __riscv_vor_vv_u32m1(__riscv_vsll_vx_u32m1(x, n, vl), __riscv_vsrl_vx_u32m1(x, 32 - (n), vl), vl)
#define VQR(a, b, c, d) do { \
    a = __riscv_vadd_vv_u32m1(a, b, vl); d = VROTL(__riscv_vxor_vv_u32m1(d, a, vl), 16, vl); \
    c = __riscv_vadd_vv_u32m1(c, d, vl); b = VROTL(__riscv_vxor_vv_u32m1(b, c, vl), 12, vl); \
    a = __riscv_vadd_vv_u32m1(a, b, vl); d = VROTL(__riscv_vxor_vv_u32m1(d, a, vl), 8, vl);  \
    c = __riscv_vadd_vv_u32m1(c, d, vl); b = VROTL(__riscv_vxor_vv_u32m1(b, c, vl), 7, vl); } while (0)

// vl blocks of keystream (vl <= MAX_BLOCKS), from block `counter`, into ks.
static void blocks_rvv(const uint32_t st[16], uint32_t counter, size_t vl, uint32_t* ks) {
    vuint32m1_t ctr = __riscv_vadd_vx_u32m1(__riscv_vid_v_u32m1(vl), counter, vl);
    vuint32m1_t x0 = __riscv_vmv_v_x_u32m1(st[0], vl), x1 = __riscv_vmv_v_x_u32m1(st[1], vl);
    vuint32m1_t x2 = __riscv_vmv_v_x_u32m1(st[2], vl), x3 = __riscv_vmv_v_x_u32m1(st[3], vl);
    vuint32m1_t x4 = __riscv_vmv_v_x_u32m1(st[4], vl), x5 = __riscv_vmv_v_x_u32m1(st[5], vl);
    vuint32m1_t x6 = __riscv_vmv_v_x_u32m1(st[6], vl), x7 = __riscv_vmv_v_x_u32m1(st[7], vl);
    vuint32m1_t x8 = __riscv_vmv_v_x_u32m1(st[8], vl), x9 = __riscv_vmv_v_x_u32m1(st[9], vl);
    vuint32m1_t x10 = __riscv_vmv_v_x_u32m1(st[10], vl), x11 = __riscv_vmv_v_x_u32m1(st[11], vl);
    vuint32m1_t x12 = ctr;
    vuint32m1_t x13 = __riscv_vmv_v_x_u32m1(st[13], vl), x14 = __riscv_vmv_v_x_u32m1(st[14], vl);
    vuint32m1_t x15 = __riscv_vmv_v_x_u32m1(st[15], vl);
    for (int r = 0; r < 10; r++) {
        VQR(x0, x4, x8, x12); VQR(x1, x5, x9, x13); VQR(x2, x6, x10, x14); VQR(x3, x7, x11, x15);
        VQR(x0, x5, x10, x15); VQR(x1, x6, x11, x12); VQR(x2, x7, x8, x13); VQR(x3, x4, x9, x14);
    }
    const ptrdiff_t stride = 64;                    // word i of block j at ks[16 j + i]
#define OUT(i, v) __riscv_vsse32_v_u32m1(ks + (i), stride, v, vl)
    OUT(0, __riscv_vadd_vx_u32m1(x0, st[0], vl));   OUT(1, __riscv_vadd_vx_u32m1(x1, st[1], vl));
    OUT(2, __riscv_vadd_vx_u32m1(x2, st[2], vl));   OUT(3, __riscv_vadd_vx_u32m1(x3, st[3], vl));
    OUT(4, __riscv_vadd_vx_u32m1(x4, st[4], vl));   OUT(5, __riscv_vadd_vx_u32m1(x5, st[5], vl));
    OUT(6, __riscv_vadd_vx_u32m1(x6, st[6], vl));   OUT(7, __riscv_vadd_vx_u32m1(x7, st[7], vl));
    OUT(8, __riscv_vadd_vx_u32m1(x8, st[8], vl));   OUT(9, __riscv_vadd_vx_u32m1(x9, st[9], vl));
    OUT(10, __riscv_vadd_vx_u32m1(x10, st[10], vl)); OUT(11, __riscv_vadd_vx_u32m1(x11, st[11], vl));
    OUT(12, __riscv_vadd_vv_u32m1(x12, ctr, vl));
    OUT(13, __riscv_vadd_vx_u32m1(x13, st[13], vl)); OUT(14, __riscv_vadd_vx_u32m1(x14, st[14], vl));
    OUT(15, __riscv_vadd_vx_u32m1(x15, st[15], vl));
#undef OUT
}

void cc20_xor_rvv(const uint32_t st[16], uint32_t counter, uint8_t* data, size_t len);
void cc20_xor_rvv(const uint32_t st[16], uint32_t counter, uint8_t* data, size_t len) {
    uint32_t ks[16 * MAX_BLOCKS] __attribute__((aligned(64)));
    while (len) {
        size_t want = (len + 63) / 64;
        size_t vl = __riscv_vsetvl_e32m1(want < MAX_BLOCKS ? want : MAX_BLOCKS);
        blocks_rvv(st, counter, vl, ks);            // little-endian words: the keystream bytes
        counter += (uint32_t)vl;
        size_t n = len < vl * 64 ? len : vl * 64;
        const uint8_t* k = (const uint8_t*)ks;
        for (size_t done = 0, m; done < n; done += m) {
            m = __riscv_vsetvl_e8m8(n - done);
            vuint8m8_t d = __riscv_vle8_v_u8m8(data + done, m);
            __riscv_vse8_v_u8m8(data + done, __riscv_vxor_vv_u8m8(d, __riscv_vle8_v_u8m8(k + done, m), m), m);
        }
        data += n;
        len -= n;
    }
    wipe((volatile uint8_t*)ks, sizeof(ks));
    uint64_t vlmax;                                      // clear all 32 vector registers
    __asm__ __volatile__("vsetvli %0, zero, e8, m8, ta, ma\n\t"
                         "vmv.v.i v0, 0\n\tvmv.v.i v8, 0\n\tvmv.v.i v16, 0\n\tvmv.v.i v24, 0"
                         : "=r"(vlmax) : : "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7", "v8", "v9", "v10",
                           "v11", "v12", "v13", "v14", "v15", "v16", "v17", "v18", "v19", "v20", "v21", "v22",
                           "v23", "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "memory");
}
