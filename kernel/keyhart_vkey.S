/*
 * YesOS 2.0 - Register-resident key primitives for the key hart.
 *
 * Keys live only in vector register groups (e64, LMUL=2, vl=4 -> 32 bytes):
 *   slot 0 = K  v30  vault data key (DEK)
 *   slot 1 = T  v28  temporary key (KEK during wrap/unwrap)
 *   slot 2 = D  v22  data key being re-wrapped
 *           S  v26  XChaCha20 subkey (HChaCha20 output)
 *           v24     scratch for element extraction
 *
 * ChaCha20/HChaCha20 run entirely in scalar registers: the 16 state words are
 * s0-s11 and a4-a7. Key material is never stored to memory; only
 * keystream XOR data (ciphertext/plaintext) and, by design, the Poly1305
 * one-time key (block 0 of the keystream) are written. Every register that
 * held key-derived values is zeroed before returning.
 *
 * Nothing else on the key hart may touch vector registers (enforced at build
 * time by tools/check_keyhart_vector.py).
 */

.section .text
.option norvc

#define X0  s0
#define X1  s1
#define X2  s2
#define X3  s3
#define X4  s4
#define X5  s5
#define X6  s6
#define X7  s7
#define X8  s8
#define X9  s9
#define X10 s10
#define X11 s11
#define X12 a4
#define X13 a5
#define X14 a6
#define X15 a7

.macro VSET
    vsetivli zero, 4, e64, m2, ta, ma
.endm

/* Save / restore callee-saved s0-s11 (caller values, not key material). */
.macro SAVE_S
    addi sp, sp, -96
    sd s0, 0(sp)
    sd s1, 8(sp)
    sd s2, 16(sp)
    sd s3, 24(sp)
    sd s4, 32(sp)
    sd s5, 40(sp)
    sd s6, 48(sp)
    sd s7, 56(sp)
    sd s8, 64(sp)
    sd s9, 72(sp)
    sd s10, 80(sp)
    sd s11, 88(sp)
.endm

.macro RESTORE_S
    ld s0, 0(sp)
    ld s1, 8(sp)
    ld s2, 16(sp)
    ld s3, 24(sp)
    ld s4, 32(sp)
    ld s5, 40(sp)
    ld s6, 48(sp)
    ld s7, 56(sp)
    ld s8, 64(sp)
    ld s9, 72(sp)
    ld s10, 80(sp)
    ld s11, 88(sp)
    addi sp, sp, 96
.endm

/* Zero every temporary that may hold key-derived data. */
.macro SCRUB
    li t0, 0
    li t1, 0
    li t2, 0
    li t3, 0
    li t4, 0
    li t5, 0
    li t6, 0
    li a4, 0
    li a5, 0
    li a6, 0
    li a7, 0
    VSET
    vmv.v.i v24, 0
.endm

/* lo/hi <- 32-bit halves of 64-bit element \idx of vector group \v */
.macro ELEM v, idx, lo, hi
.if \idx == 0
    vmv.x.s t0, \v
.else
    vslidedown.vi v24, \v, \idx
    vmv.x.s t0, v24
.endif
    addiw \lo, t0, 0
    srai  \hi, t0, 32
.endm

/* State words 4..11 <- key in group \v */
.macro LOAD_KEY v
    VSET
    ELEM \v, 0, X4, X5
    ELEM \v, 1, X6, X7
    ELEM \v, 2, X8, X9
    ELEM \v, 3, X10, X11
.endm

/* State words 4..11 += key in group \v (final ChaCha addition) */
.macro ADD_KEY v
    VSET
    ELEM \v, 0, t1, t2
    addw X4, X4, t1
    addw X5, X5, t2
    ELEM \v, 1, t1, t2
    addw X6, X6, t1
    addw X7, X7, t2
    ELEM \v, 2, t1, t2
    addw X8, X8, t1
    addw X9, X9, t2
    ELEM \v, 3, t1, t2
    addw X10, X10, t1
    addw X11, X11, t2
.endm

.macro CONSTANTS
    li X0, 0x61707865
    li X1, 0x3320646e
    li X2, 0x79622d32
    li X3, 0x6b206574
.endm

.macro ADD_CONSTANTS
    li t1, 0x61707865
    addw X0, X0, t1
    li t1, 0x3320646e
    addw X1, X1, t1
    li t1, 0x79622d32
    addw X2, X2, t1
    li t1, 0x6b206574
    addw X3, X3, t1
.endm

/* rotl(16,12,8,7) == rotr(16,20,24,25) */
.macro QR a, b, c, d
    addw \a, \a, \b
    xor  \d, \d, \a
    roriw \d, \d, 16
    addw \c, \c, \d
    xor  \b, \b, \c
    roriw \b, \b, 20
    addw \a, \a, \b
    xor  \d, \d, \a
    roriw \d, \d, 24
    addw \c, \c, \d
    xor  \b, \b, \c
    roriw \b, \b, 25
.endm

/* 10 double rounds; uses t3 as counter */
.macro ROUNDS
    li t3, 10
1:
    QR X0, X4, X8,  X12
    QR X1, X5, X9,  X13
    QR X2, X6, X10, X14
    QR X3, X7, X11, X15
    QR X0, X5, X10, X15
    QR X1, X6, X11, X12
    QR X2, X7, X8,  X13
    QR X3, X4, X9,  X14
    addi t3, t3, -1
    bnez t3, 1b
.endm

/* \reg <- little-endian 32-bit word at \off(\base), byte loads (any alignment) */
.macro LOADW reg, base, off
    lbu \reg, \off(\base)
    lbu t2, \off+1(\base)
    slli t2, t2, 8
    or  \reg, \reg, t2
    lbu t2, \off+2(\base)
    slli t2, t2, 16
    or  \reg, \reg, t2
    lbu t2, \off+3(\base)
    slli t2, t2, 24
    or  \reg, \reg, t2
.endm

/* store low 32 bits of \reg at \off(\base), byte stores */
.macro STOREW reg, base, off
    sb  \reg, \off(\base)
    srli t2, \reg, 8
    sb  t2, \off+1(\base)
    srli t2, \reg, 16
    sb  t2, \off+2(\base)
    srli t2, \reg, 24
    sb  t2, \off+3(\base)
.endm

/*
 * XOR keystream word \k into up to 4 bytes at in=a2/out=a3, t5 = bytes left.
 * Advances a2/a3, decrements t5. Jumps to \done when t5 reaches 0.
 */
.macro XORW k, done
    beqz t5, \done
    li  t4, 4
    bltu t5, t4, 2f
    LOADW t1, a2, 0
    xor t1, t1, \k
    STOREW t1, a3, 0
    addi a2, a2, 4
    addi a3, a3, 4
    addi t5, t5, -4
    j 3f
2:  /* tail: 1..3 bytes */
    mv  t1, \k
4:
    lbu t0, 0(a2)
    xor t0, t0, t1
    sb  t0, 0(a3)
    srli t1, t1, 8
    addi a2, a2, 1
    addi a3, a3, 1
    addi t5, t5, -1
    bnez t5, 4b
    j \done
3:
.endm

/* ChaCha20 block with key from S (v26), counter t6, nonce words at (a0). */
.macro CHACHA_BLOCK_S
    CONSTANTS
    LOAD_KEY v26
    mv X12, t6
    LOADW X13, a0, 0
    LOADW X14, a0, 4
    LOADW X15, a0, 8
    ROUNDS
    ADD_CONSTANTS
    ADD_KEY v26
    addw X12, X12, t6
    LOADW t1, a0, 0
    addw X13, X13, t1
    LOADW t1, a0, 4
    addw X14, X14, t1
    LOADW t1, a0, 8
    addw X15, X15, t1
.endm

/* group \v <- 64-bit words w0..w3 built from 32-bit pairs (lo, hi) */
.macro PACK dst, lo, hi
    zext.w \dst, \lo
    slli t2, \hi, 32
    or  \dst, \dst, t2
.endm

.macro INSERT v
    VSET
    vslide1down.vx \v, \v, t0
    vslide1down.vx \v, \v, t1
    vslide1down.vx \v, \v, t3
    vslide1down.vx \v, \v, t4
.endm

/* ------------------------------------------------------------------------ */

/* void kh_vk_load(U32 slot, const U8* src32) */
.global kh_vk_load
kh_vk_load:
    VSET
    li t0, 1
    beq a0, t0, 1f
    li t0, 2
    beq a0, t0, 2f
    vle64.v v30, (a1)      /* vl=4 x e64 = 32 bytes; src must be 8-byte aligned */
    j 9f
1:  vle64.v v28, (a1)
    j 9f
2:  vle64.v v22, (a1)
9:  ret
.size kh_vk_load, . - kh_vk_load

/* void kh_vk_clear(U32 slot) */
.global kh_vk_clear
kh_vk_clear:
    VSET
    li t0, 1
    beq a0, t0, 1f
    li t0, 2
    beq a0, t0, 2f
    vmv.v.i v30, 0
    j 9f
1:  vmv.v.i v28, 0
    j 9f
2:  vmv.v.i v22, 0
9:  vmv.v.i v24, 0
    vmv.v.i v26, 0
    ret

/* void kh_vk_clear_sub(void) : wipe the XChaCha20 subkey and scratch */
.global kh_vk_clear_sub
kh_vk_clear_sub:
    VSET
    vmv.v.i v24, 0
    vmv.v.i v26, 0
    ret

/* void kh_vk_hchacha(U32 src_slot, const U8* nonce16) : S <- HChaCha20(slot, nonce) */
.global kh_vk_hchacha
kh_vk_hchacha:
    SAVE_S
    CONSTANTS
    li t0, 1
    beq a0, t0, 1f
    LOAD_KEY v30
    j 2f
1:  LOAD_KEY v28
2:  LOADW X12, a1, 0
    LOADW X13, a1, 4
    LOADW X14, a1, 8
    LOADW X15, a1, 12
    ROUNDS
    PACK t0, X0, X1
    PACK t1, X2, X3
    PACK t3, X12, X13
    PACK t4, X14, X15
    INSERT v26
    li t0, 0
    li t1, 0
    li t3, 0
    li t4, 0
    li t2, 0
    li a4, 0
    li a5, 0
    li a6, 0
    li a7, 0
    vmv.v.i v24, 0
    RESTORE_S
    ret

/*
 * void kh_vk_chacha_xor(const U8* nonce12, U32 counter, const U8* in, U8* out, size_t len)
 * out = in XOR ChaCha20(S, nonce12, counter...). in == out allowed.
 */
.global kh_vk_chacha_xor
kh_vk_chacha_xor:
    SAVE_S
    mv t6, a1
    mv t5, a4
.Lxor_block:
    beqz t5, .Lxor_done
    CHACHA_BLOCK_S
    XORW X0,  .Lxor_next
    XORW X1,  .Lxor_next
    XORW X2,  .Lxor_next
    XORW X3,  .Lxor_next
    XORW X4,  .Lxor_next
    XORW X5,  .Lxor_next
    XORW X6,  .Lxor_next
    XORW X7,  .Lxor_next
    XORW X8,  .Lxor_next
    XORW X9,  .Lxor_next
    XORW X10, .Lxor_next
    XORW X11, .Lxor_next
    XORW X12, .Lxor_next
    XORW X13, .Lxor_next
    XORW X14, .Lxor_next
    XORW X15, .Lxor_next
.Lxor_next:
    addiw t6, t6, 1
    j .Lxor_block
.Lxor_done:
    SCRUB
    RESTORE_S
    ret

/*
 * void kh_vk_chacha_to_slot(const U8* nonce12, U32 counter, const U8* in32, U32 dst_slot)
 * dst slot (0=K, 2=D) <- in32 XOR first 32 bytes of ChaCha20 block (S, nonce, counter).
 * Used to unwrap the data key straight into registers.
 */
.global kh_vk_chacha_to_slot
kh_vk_chacha_to_slot:
    SAVE_S
    mv t6, a1
    mv a1, a2              /* in32 */
    mv a2, a3              /* dst slot */
    CHACHA_BLOCK_S
    LOADW t1, a1, 0
    xor X0, X0, t1
    LOADW t1, a1, 4
    xor X1, X1, t1
    LOADW t1, a1, 8
    xor X2, X2, t1
    LOADW t1, a1, 12
    xor X3, X3, t1
    LOADW t1, a1, 16
    xor X4, X4, t1
    LOADW t1, a1, 20
    xor X5, X5, t1
    LOADW t1, a1, 24
    xor X6, X6, t1
    LOADW t1, a1, 28
    xor X7, X7, t1
    mv t5, a2
    PACK t0, X0, X1
    PACK t1, X2, X3
    PACK t3, X4, X5
    PACK t4, X6, X7
    li t2, 2
    beq t5, t2, 1f
    INSERT v30
    j 2f
1:  INSERT v22
2:  SCRUB
    RESTORE_S
    ret

/*
 * void kh_vk_chacha_from_slot(const U8* nonce12, U32 counter, U32 src_slot, U8* out32)
 * out32 <- key in src slot (0=K, 2=D) XOR first 32 bytes of ChaCha20 block.
 * Used to wrap the data key without it ever being written in clear.
 */
.global kh_vk_chacha_from_slot
kh_vk_chacha_from_slot:
    SAVE_S
    mv t6, a1
    mv t5, a2
    mv a1, a3              /* out32 */
    CHACHA_BLOCK_S
    li t2, 2
    beq t5, t2, 1f
    VSET
    ELEM v30, 0, t1, t3
    xor X0, X0, t1
    xor X1, X1, t3
    ELEM v30, 1, t1, t3
    xor X2, X2, t1
    xor X3, X3, t3
    ELEM v30, 2, t1, t3
    xor X4, X4, t1
    xor X5, X5, t3
    ELEM v30, 3, t1, t3
    xor X6, X6, t1
    xor X7, X7, t3
    j 2f
1:  VSET
    ELEM v22, 0, t1, t3
    xor X0, X0, t1
    xor X1, X1, t3
    ELEM v22, 1, t1, t3
    xor X2, X2, t1
    xor X3, X3, t3
    ELEM v22, 2, t1, t3
    xor X4, X4, t1
    xor X5, X5, t3
    ELEM v22, 3, t1, t3
    xor X6, X6, t1
    xor X7, X7, t3
2:  STOREW X0, a1, 0
    STOREW X1, a1, 4
    STOREW X2, a1, 8
    STOREW X3, a1, 12
    STOREW X4, a1, 16
    STOREW X5, a1, 20
    STOREW X6, a1, 24
    STOREW X7, a1, 28
    SCRUB
    RESTORE_S
    ret

/*
 * U64 kh_vk_count(U32 slot, const U8* p, size_t len)
 * Counts byte offsets in [p, p+len-8] where the first 8 key bytes of the slot
 * appear (any alignment). Used by the self-test to prove the key is not in RAM.
 */
.global kh_vk_count
kh_vk_count:
    VSET
    li t0, 2
    beq a0, t0, 1f
    vmv.x.s t1, v30
    j 2f
1:  vmv.x.s t1, v22
2:  li a0, 0
    li t3, 8
    bltu a2, t3, 9f
    addi a2, a2, -7
3:  /* t0 <- 8 bytes at a1 */
    li t0, 0
    li t4, 7
4:  add t5, a1, t4
    lbu t5, 0(t5)
    slli t0, t0, 8
    or  t0, t0, t5
    addi t4, t4, -1
    bgez t4, 4b
    bne t0, t1, 5f
    addi a0, a0, 1
5:  addi a1, a1, 1
    addi a2, a2, -1
    bnez a2, 3b
9:  li t0, 0
    li t1, 0
    li t5, 0
    ret
