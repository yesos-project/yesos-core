#include "holyq_rv64_emit.h"
#include "kprintf.h"

// Register names in RISC-V ABI
static const char* const g_reg_names[32] = {
    "zero", "ra", "sp", "gp", "tp", "t0", "t1", "t2",
    "s0",   "s1", "a0", "a1", "a2", "a3", "a4", "a5",
    "a6",   "a7", "s2", "s3", "s4", "s5", "s6", "s7",
    "s8",   "s9", "s10","s11","t3", "t4", "t5", "t6"
};

const char* rv64_reg_name(U8 reg) {
    if (reg < 32) return g_reg_names[reg];
    return "unk";
}

void rv64_emit_init(RV64EmitBuf* buf, U32* mem, size_t capacity_insts, U64 base_pc) {
    buf->code = mem;
    buf->count = 0;
    buf->capacity = capacity_insts;
    buf->base_pc = base_pc;
}

void rv64_emit_u32(RV64EmitBuf* buf, U32 instr) {
    if (buf->count < buf->capacity) {
        buf->code[buf->count++] = instr;
    }
}

// ----------------------------------------------------------------------------
// Low-Level Instruction Encoders
// ----------------------------------------------------------------------------
static inline U32 rv_enc_r(U32 opcode, U32 funct3, U32 funct7, U8 rd, U8 rs1, U8 rs2) {
    return ((funct7 & 0x7F) << 25) |
           ((rs2 & 0x1F) << 20) |
           ((rs1 & 0x1F) << 15) |
           ((funct3 & 0x7) << 12) |
           ((rd & 0x1F) << 7) |
           (opcode & 0x7F);
}

static inline U32 rv_enc_i(U32 opcode, U32 funct3, U8 rd, U8 rs1, I32 imm) {
    return (((U32)imm & 0xFFF) << 20) |
           ((rs1 & 0x1F) << 15) |
           ((funct3 & 0x7) << 12) |
           ((rd & 0x1F) << 7) |
           (opcode & 0x7F);
}

static inline U32 rv_enc_s(U32 opcode, U32 funct3, U8 rs1, U8 rs2, I32 imm) {
    U32 uimm = (U32)imm;
    return (((uimm >> 5) & 0x7F) << 25) |
           ((rs2 & 0x1F) << 20) |
           ((rs1 & 0x1F) << 15) |
           ((funct3 & 0x7) << 12) |
           ((uimm & 0x1F) << 7) |
           (opcode & 0x7F);
}

static inline U32 rv_enc_b(U32 funct3, U8 rs1, U8 rs2, I32 imm) {
    U32 uimm = (U32)imm;
    U32 imm12   = (uimm >> 12) & 0x1;
    U32 imm10_5 = (uimm >> 5) & 0x3F;
    U32 imm4_1  = (uimm >> 1) & 0xF;
    U32 imm11   = (uimm >> 11) & 0x1;
    return (imm12 << 31) |
           (imm10_5 << 25) |
           ((rs2 & 0x1F) << 20) |
           ((rs1 & 0x1F) << 15) |
           ((funct3 & 0x7) << 12) |
           (imm4_1 << 8) |
           (imm11 << 7) |
           0x63;
}

static inline U32 rv_enc_u(U32 opcode, U8 rd, U32 imm20) {
    return ((imm20 & 0xFFFFF) << 12) |
           ((rd & 0x1F) << 7) |
           (opcode & 0x7F);
}

static inline U32 rv_enc_j(U8 rd, I32 imm) {
    U32 uimm = (U32)imm;
    U32 imm20    = (uimm >> 20) & 0x1;
    U32 imm10_1  = (uimm >> 1) & 0x3FF;
    U32 imm11    = (uimm >> 11) & 0x1;
    U32 imm19_12 = (uimm >> 12) & 0xFF;
    return (imm20 << 31) |
           (imm10_1 << 21) |
           (imm11 << 20) |
           (imm19_12 << 12) |
           ((rd & 0x1F) << 7) |
           0x6F;
}

// ----------------------------------------------------------------------------
// ALU Immediate Instructions
// ----------------------------------------------------------------------------
void rv64_emit_addi(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm) {
    rv64_emit_u32(buf, rv_enc_i(0x13, 0x0, rd, rs1, imm));
}

void rv64_emit_addiw(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm) {
    rv64_emit_u32(buf, rv_enc_i(0x1B, 0x0, rd, rs1, imm));
}

void rv64_emit_slli(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 shamt) {
    rv64_emit_u32(buf, rv_enc_i(0x13, 0x1, rd, rs1, (I32)(shamt & 0x3F)));
}

void rv64_emit_srli(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 shamt) {
    rv64_emit_u32(buf, rv_enc_i(0x13, 0x5, rd, rs1, (I32)(shamt & 0x3F)));
}

void rv64_emit_srai(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 shamt) {
    rv64_emit_u32(buf, rv_enc_i(0x13, 0x5, rd, rs1, (I32)(0x400 | (shamt & 0x3F))));
}

void rv64_emit_andi(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm) {
    rv64_emit_u32(buf, rv_enc_i(0x13, 0x7, rd, rs1, imm));
}

void rv64_emit_ori(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm) {
    rv64_emit_u32(buf, rv_enc_i(0x13, 0x6, rd, rs1, imm));
}

void rv64_emit_xori(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm) {
    rv64_emit_u32(buf, rv_enc_i(0x13, 0x4, rd, rs1, imm));
}

void rv64_emit_slti(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm) {
    rv64_emit_u32(buf, rv_enc_i(0x13, 0x2, rd, rs1, imm));
}

void rv64_emit_sltiu(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm) {
    rv64_emit_u32(buf, rv_enc_i(0x13, 0x3, rd, rs1, imm));
}

// ----------------------------------------------------------------------------
// ALU Reg-Reg Instructions (RV64I + RV64M)
// ----------------------------------------------------------------------------
void rv64_emit_add(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x0, 0x00, rd, rs1, rs2));
}

void rv64_emit_sub(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x0, 0x20, rd, rs1, rs2));
}

void rv64_emit_mul(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x0, 0x01, rd, rs1, rs2));
}

void rv64_emit_div(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x4, 0x01, rd, rs1, rs2));
}

void rv64_emit_divu(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x5, 0x01, rd, rs1, rs2));
}

void rv64_emit_rem(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x6, 0x01, rd, rs1, rs2));
}

void rv64_emit_remu(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x7, 0x01, rd, rs1, rs2));
}

void rv64_emit_sll(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x1, 0x00, rd, rs1, rs2));
}

void rv64_emit_srl(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x5, 0x00, rd, rs1, rs2));
}

void rv64_emit_sra(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x5, 0x20, rd, rs1, rs2));
}

void rv64_emit_and(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x7, 0x00, rd, rs1, rs2));
}

void rv64_emit_or(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x6, 0x00, rd, rs1, rs2));
}

void rv64_emit_xor(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x4, 0x00, rd, rs1, rs2));
}

void rv64_emit_slt(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x2, 0x00, rd, rs1, rs2));
}

void rv64_emit_sltu(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x3, 0x00, rd, rs1, rs2));
}

// ----------------------------------------------------------------------------
// RV64 Zba & Zbb Extensions
// ----------------------------------------------------------------------------
void rv64_emit_sh1add(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    // sh1add rd, rs1, rs2: funct7=0x10, funct3=0x2, opcode=0x33
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x2, 0x10, rd, rs1, rs2));
}

void rv64_emit_sh2add(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    // sh2add rd, rs1, rs2: funct7=0x10, funct3=0x4, opcode=0x33
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x4, 0x10, rd, rs1, rs2));
}

void rv64_emit_sh3add(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    // sh3add rd, rs1, rs2: funct7=0x10, funct3=0x6, opcode=0x33
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x6, 0x10, rd, rs1, rs2));
}

void rv64_emit_min(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    // min rd, rs1, rs2: funct7=0x05, funct3=0x4, opcode=0x33
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x4, 0x05, rd, rs1, rs2));
}

void rv64_emit_max(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2) {
    // max rd, rs1, rs2: funct7=0x05, funct3=0x6, opcode=0x33
    rv64_emit_u32(buf, rv_enc_r(0x33, 0x6, 0x05, rd, rs1, rs2));
}

void rv64_emit_clz(RV64EmitBuf* buf, U8 rd, U8 rs1) {
    // clz rd, rs1: funct7=0x30, rs2=0, funct3=0x1, opcode=0x13
    rv64_emit_u32(buf, rv_enc_r(0x13, 0x1, 0x30, rd, rs1, 0));
}

void rv64_emit_ctz(RV64EmitBuf* buf, U8 rd, U8 rs1) {
    // ctz rd, rs1: funct7=0x30, rs2=1, funct3=0x1, opcode=0x13
    rv64_emit_u32(buf, rv_enc_r(0x13, 0x1, 0x30, rd, rs1, 1));
}

void rv64_emit_cpop(RV64EmitBuf* buf, U8 rd, U8 rs1) {
    // cpop rd, rs1: funct7=0x30, rs2=2, funct3=0x1, opcode=0x13
    rv64_emit_u32(buf, rv_enc_r(0x13, 0x1, 0x30, rd, rs1, 2));
}

// ----------------------------------------------------------------------------
// Upper Immediate & Memory (Loads/Stores)
// ----------------------------------------------------------------------------
void rv64_emit_lui(RV64EmitBuf* buf, U8 rd, U32 imm20) {
    rv64_emit_u32(buf, rv_enc_u(0x37, rd, imm20));
}

void rv64_emit_auipc(RV64EmitBuf* buf, U8 rd, U32 imm20) {
    rv64_emit_u32(buf, rv_enc_u(0x17, rd, imm20));
}

void rv64_emit_ld(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 offset) {
    rv64_emit_u32(buf, rv_enc_i(0x03, 0x3, rd, rs1, offset));
}

void rv64_emit_sd(RV64EmitBuf* buf, U8 rs2, U8 rs1, I32 offset) {
    rv64_emit_u32(buf, rv_enc_s(0x23, 0x3, rs1, rs2, offset));
}

void rv64_emit_lw(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 offset) {
    rv64_emit_u32(buf, rv_enc_i(0x03, 0x2, rd, rs1, offset));
}

void rv64_emit_sw(RV64EmitBuf* buf, U8 rs2, U8 rs1, I32 offset) {
    rv64_emit_u32(buf, rv_enc_s(0x23, 0x2, rs1, rs2, offset));
}

// ----------------------------------------------------------------------------
// Jumps, Calls, Returns & Branches
// ----------------------------------------------------------------------------
void rv64_emit_jalr(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 offset) {
    rv64_emit_u32(buf, rv_enc_i(0x67, 0x0, rd, rs1, offset));
}

void rv64_emit_jal(RV64EmitBuf* buf, U8 rd, I32 offset) {
    rv64_emit_u32(buf, rv_enc_j(rd, offset));
}

void rv64_emit_ret(RV64EmitBuf* buf) {
    // ret = jalr x0, x1, 0 (0x00008067)
    rv64_emit_u32(buf, 0x00008067);
}

void rv64_emit_nop(RV64EmitBuf* buf) {
    // nop = addi x0, x0, 0 (0x00000013)
    rv64_emit_u32(buf, 0x00000013);
}

void rv64_emit_call(RV64EmitBuf* buf, U64 func_ptr) {
    // Synthesize 64-bit function address into RV_REG_T6 and execute jalr ra, t6, 0
    rv64_emit_li64(buf, RV_REG_T6, func_ptr);
    rv64_emit_jalr(buf, RV_REG_RA, RV_REG_T6, 0);
}

void rv64_emit_beq(RV64EmitBuf* buf, U8 rs1, U8 rs2, I32 offset) {
    rv64_emit_u32(buf, rv_enc_b(0x0, rs1, rs2, offset));
}

void rv64_emit_bne(RV64EmitBuf* buf, U8 rs1, U8 rs2, I32 offset) {
    rv64_emit_u32(buf, rv_enc_b(0x1, rs1, rs2, offset));
}

void rv64_emit_blt(RV64EmitBuf* buf, U8 rs1, U8 rs2, I32 offset) {
    rv64_emit_u32(buf, rv_enc_b(0x4, rs1, rs2, offset));
}

void rv64_emit_bge(RV64EmitBuf* buf, U8 rs1, U8 rs2, I32 offset) {
    rv64_emit_u32(buf, rv_enc_b(0x5, rs1, rs2, offset));
}

void rv64_emit_bltu(RV64EmitBuf* buf, U8 rs1, U8 rs2, I32 offset) {
    rv64_emit_u32(buf, rv_enc_b(0x6, rs1, rs2, offset));
}

void rv64_emit_bgeu(RV64EmitBuf* buf, U8 rs1, U8 rs2, I32 offset) {
    rv64_emit_u32(buf, rv_enc_b(0x7, rs1, rs2, offset));
}

// ----------------------------------------------------------------------------
// Backpatching Helpers
// ----------------------------------------------------------------------------
size_t rv64_emit_branch_placeholder(RV64EmitBuf* buf, U32 funct3, U8 rs1, U8 rs2) {
    size_t idx = buf->count;
    rv64_emit_u32(buf, rv_enc_b(funct3, rs1, rs2, 0));
    return idx;
}

void rv64_patch_branch(RV64EmitBuf* buf, size_t branch_idx, size_t target_idx) {
    if (branch_idx >= buf->count) return;
    I32 byte_offset = (I32)((target_idx - branch_idx) * sizeof(U32));
    U32 orig = buf->code[branch_idx];
    U8 funct3 = (orig >> 12) & 0x7;
    U8 rs1 = (orig >> 15) & 0x1F;
    U8 rs2 = (orig >> 20) & 0x1F;
    buf->code[branch_idx] = rv_enc_b(funct3, rs1, rs2, byte_offset);
}

size_t rv64_emit_jal_placeholder(RV64EmitBuf* buf, U8 rd) {
    size_t idx = buf->count;
    rv64_emit_u32(buf, rv_enc_j(rd, 0));
    return idx;
}

void rv64_patch_jal(RV64EmitBuf* buf, size_t jal_idx, size_t target_idx) {
    if (jal_idx >= buf->count) return;
    I32 byte_offset = (I32)((target_idx - jal_idx) * sizeof(U32));
    U32 orig = buf->code[jal_idx];
    U8 rd = (orig >> 7) & 0x1F;
    buf->code[jal_idx] = rv_enc_j(rd, byte_offset);
}

// ----------------------------------------------------------------------------
// 64-Bit Immediate Synthesis
// ----------------------------------------------------------------------------
void rv64_emit_li64(RV64EmitBuf* buf, U8 rd, U64 val) {
    I64 sval = (I64)val;

    // 1. Fits in 12-bit signed immediate (-2048 to 2047)
    if (sval >= -2048 && sval <= 2047) {
        rv64_emit_addi(buf, rd, RV_REG_ZERO, (I32)sval);
        return;
    }

    // 2. Fits in 32-bit signed immediate (lui + addiw)
    if (sval == (I64)(I32)sval) {
        I32 val32 = (I32)sval;
        I32 hi = (val32 + 0x800) >> 12;
        I32 lo = val32 - (hi << 12);
        rv64_emit_lui(buf, rd, (U32)hi & 0xFFFFF);
        rv64_emit_addiw(buf, rd, rd, lo);
        return;
    }

    // 3. Positive 32-bit immediate (e.g., YesOS physical RAM 0x80000000 - 0x8FFFFFFF)
    if ((val >> 32) == 0) {
        U32 val32 = (U32)val;
        I32 hi = ((I32)val32 + 0x800) >> 12;
        I32 lo = (I32)val32 - (hi << 12);
        rv64_emit_lui(buf, rd, (U32)hi & 0xFFFFF);
        rv64_emit_addi(buf, rd, rd, lo);
        rv64_emit_slli(buf, rd, rd, 32);
        rv64_emit_srli(buf, rd, rd, 32);
        return;
    }

    // 4. Arbitrary 64-bit value: load high 32 bits into rd, shift left 32, load low 32 bits into temp and combine
    U32 hi_part = (U32)(val >> 32);
    U32 lo_part = (U32)(val & 0xFFFFFFFFULL);

    I32 h_hi = ((I32)hi_part + 0x800) >> 12;
    I32 h_lo = (I32)hi_part - (h_hi << 12);
    rv64_emit_lui(buf, rd, (U32)h_hi & 0xFFFFF);
    rv64_emit_addi(buf, rd, rd, h_lo);
    rv64_emit_slli(buf, rd, rd, 32);

    if (lo_part != 0) {
        U8 tmp = (rd == RV_REG_T6) ? RV_REG_T5 : RV_REG_T6;
        I32 l_hi = ((I32)lo_part + 0x800) >> 12;
        I32 l_lo = (I32)lo_part - (l_hi << 12);
        rv64_emit_lui(buf, tmp, (U32)l_hi & 0xFFFFF);
        rv64_emit_addi(buf, tmp, tmp, l_lo);
        rv64_emit_slli(buf, tmp, tmp, 32);
        rv64_emit_srli(buf, tmp, tmp, 32);
        rv64_emit_or(buf, rd, rd, tmp);
    }
}

// ----------------------------------------------------------------------------
// Cache & Pipeline Flush
// ----------------------------------------------------------------------------
void rv64_emit_fence_i(RV64EmitBuf* buf) {
    // fence.i = 0x0000100F
    rv64_emit_u32(buf, 0x0000100F);
}

void rv64_flush_icache(void* start, size_t bytes) {
    (void)start;
    (void)bytes;
    // Machine Mode Memory fence & Instruction Cache Invalidation
    __asm__ __volatile__("fence rw, rw" ::: "memory");
    __asm__ __volatile__("fence.i" ::: "memory");
}

// ----------------------------------------------------------------------------
// RVV 1.0 Vector Extension Emitters
// ----------------------------------------------------------------------------

static const char* const g_rv_vregs[32] = {
    "v0", "v1", "v2", "v3", "v4", "v5", "v6", "v7",
    "v8", "v9", "v10", "v11", "v12", "v13", "v14", "v15",
    "v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
    "v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31"
};

const char* rv64_vreg_name(U8 reg) {
    if (reg < 32) return g_rv_vregs[reg];
    return "v?";
}

void rv64_emit_vsetvli(RV64EmitBuf* buf, U8 rd, U8 rs1, RVV_SEW sew, RVV_LMUL lmul, Bool ta, Bool ma) {
    U32 zimm = (ma ? 0x80 : 0) | (ta ? 0x40 : 0) | (((U32)sew & 0x7) << 3) | ((U32)lmul & 0x7);
    U32 inst = ((zimm & 0x7FF) << 20) | (((U32)rs1 & 0x1F) << 15) | (0x7 << 12) | (((U32)rd & 0x1F) << 7) | 0x57;
    rv64_emit_u32(buf, inst);
}

static inline void emit_vle(RV64EmitBuf* buf, U8 vd, U8 rs1, U8 width) {
    U32 inst = (1 << 25) | (((U32)rs1 & 0x1F) << 15) | (((U32)width & 0x7) << 12) | (((U32)vd & 0x1F) << 7) | 0x07;
    rv64_emit_u32(buf, inst);
}

void rv64_emit_vle8(RV64EmitBuf* buf, U8 vd, U8 rs1)  { emit_vle(buf, vd, rs1, 0x0); }
void rv64_emit_vle16(RV64EmitBuf* buf, U8 vd, U8 rs1) { emit_vle(buf, vd, rs1, 0x5); }
void rv64_emit_vle32(RV64EmitBuf* buf, U8 vd, U8 rs1) { emit_vle(buf, vd, rs1, 0x6); }
void rv64_emit_vle64(RV64EmitBuf* buf, U8 vd, U8 rs1) { emit_vle(buf, vd, rs1, 0x7); }

static inline void emit_vse(RV64EmitBuf* buf, U8 vs3, U8 rs1, U8 width) {
    U32 inst = (1 << 25) | (((U32)rs1 & 0x1F) << 15) | (((U32)width & 0x7) << 12) | (((U32)vs3 & 0x1F) << 7) | 0x27;
    rv64_emit_u32(buf, inst);
}

void rv64_emit_vse8(RV64EmitBuf* buf, U8 vs3, U8 rs1)  { emit_vse(buf, vs3, rs1, 0x0); }
void rv64_emit_vse16(RV64EmitBuf* buf, U8 vs3, U8 rs1) { emit_vse(buf, vs3, rs1, 0x5); }
void rv64_emit_vse32(RV64EmitBuf* buf, U8 vs3, U8 rs1) { emit_vse(buf, vs3, rs1, 0x6); }
void rv64_emit_vse64(RV64EmitBuf* buf, U8 vs3, U8 rs1) { emit_vse(buf, vs3, rs1, 0x7); }

static inline void emit_v_vv(RV64EmitBuf* buf, U8 funct6, U8 funct3, U8 vd, U8 vs2, U8 vs1) {
    U32 inst = (((U32)funct6 & 0x3F) << 26) | (1 << 25) | (((U32)vs2 & 0x1F) << 20) |
               (((U32)vs1 & 0x1F) << 15) | (((U32)funct3 & 0x7) << 12) | (((U32)vd & 0x1F) << 7) | 0x57;
    rv64_emit_u32(buf, inst);
}

void rv64_emit_vadd_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1) { emit_v_vv(buf, 0x00, 0x0, vd, vs2, vs1); }
void rv64_emit_vsub_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1) { emit_v_vv(buf, 0x02, 0x0, vd, vs2, vs1); }
void rv64_emit_vmul_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1) { emit_v_vv(buf, 0x25, 0x2, vd, vs2, vs1); }
void rv64_emit_vand_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1) { emit_v_vv(buf, 0x09, 0x0, vd, vs2, vs1); }
void rv64_emit_vor_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1)  { emit_v_vv(buf, 0x0A, 0x0, vd, vs2, vs1); }
void rv64_emit_vxor_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1) { emit_v_vv(buf, 0x0B, 0x0, vd, vs2, vs1); }
void rv64_emit_vmin_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1) { emit_v_vv(buf, 0x05, 0x0, vd, vs2, vs1); }
void rv64_emit_vmax_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1) { emit_v_vv(buf, 0x07, 0x0, vd, vs2, vs1); }

static inline void emit_v_vx(RV64EmitBuf* buf, U8 funct6, U8 funct3, U8 vd, U8 vs2, U8 rs1) {
    U32 inst = (((U32)funct6 & 0x3F) << 26) | (1 << 25) | (((U32)vs2 & 0x1F) << 20) |
               (((U32)rs1 & 0x1F) << 15) | (((U32)funct3 & 0x7) << 12) | (((U32)vd & 0x1F) << 7) | 0x57;
    rv64_emit_u32(buf, inst);
}

void rv64_emit_vadd_vx(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 rs1) { emit_v_vx(buf, 0x00, 0x4, vd, vs2, rs1); }
void rv64_emit_vsub_vx(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 rs1) { emit_v_vx(buf, 0x02, 0x4, vd, vs2, rs1); }
void rv64_emit_vmul_vx(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 rs1) { emit_v_vx(buf, 0x25, 0x6, vd, vs2, rs1); }
void rv64_emit_vmin_vx(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 rs1) { emit_v_vx(buf, 0x05, 0x4, vd, vs2, rs1); }
void rv64_emit_vmax_vx(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 rs1) { emit_v_vx(buf, 0x07, 0x4, vd, vs2, rs1); }

void rv64_emit_vredsum_vs(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1) {
    emit_v_vv(buf, 0x00, 0x2, vd, vs2, vs1);
}

void rv64_emit_vmv_x_s(RV64EmitBuf* buf, U8 rd, U8 vs2) {
    U32 inst = (0x10 << 26) | (1 << 25) | (((U32)vs2 & 0x1F) << 20) | (0 << 15) | (0x2 << 12) | (((U32)rd & 0x1F) << 7) | 0x57;
    rv64_emit_u32(buf, inst);
}

void rv64_emit_vmv_v_x(RV64EmitBuf* buf, U8 vd, U8 rs1) {
    U32 inst = (0x17 << 26) | (1 << 25) | (0 << 20) | (((U32)rs1 & 0x1F) << 15) | (0x4 << 12) | (((U32)vd & 0x1F) << 7) | 0x57;
    rv64_emit_u32(buf, inst);
}

void rv64_emit_vmv_v_i(RV64EmitBuf* buf, U8 vd, I8 simm5) {
    U32 inst = (0x17 << 26) | (1 << 25) | (0 << 20) | (((U32)simm5 & 0x1F) << 15) | (0x3 << 12) | (((U32)vd & 0x1F) << 7) | 0x57;
    rv64_emit_u32(buf, inst);
}

// ----------------------------------------------------------------------------
// Telemetry & Mini-Disassembler
// ----------------------------------------------------------------------------
void rv64_disasm_print(const U32* code, size_t count, U64 base_addr) {
    if (!code || count == 0) return;

    for (size_t i = 0; i < count; i++) {
        U32 inst = code[i];
        U64 pc = base_addr + (i * 4);
        U8 opcode = inst & 0x7F;
        U8 rd     = (inst >> 7) & 0x1F;
        U8 funct3 = (inst >> 12) & 0x7;
        U8 rs1    = (inst >> 15) & 0x1F;
        U8 rs2    = (inst >> 20) & 0x1F;
        U8 funct7 = (inst >> 25) & 0x7F;
        I32 imm_i = (I32)(inst) >> 20;

        kprintf("  %p:  %08x    ", pc, (U64)(inst & 0xFFFFFFFFULL));

        if (inst == 0x00008067) {
            kprintf("ret\n");
            continue;
        }
        if (inst == 0x00000013) {
            kprintf("nop\n");
            continue;
        }
        if (inst == 0x0000100F) {
            kprintf("fence.i\n");
            continue;
        }

        switch (opcode) {
            case 0x13: // OP-IMM
                switch (funct3) {
                    case 0x0:
                        if (rs1 == 0) kprintf("li\t%s, %d\n", rv64_reg_name(rd), imm_i);
                        else if (imm_i == 0) kprintf("mv\t%s, %s\n", rv64_reg_name(rd), rv64_reg_name(rs1));
                        else kprintf("addi\t%s, %s, %d\n", rv64_reg_name(rd), rv64_reg_name(rs1), imm_i);
                        break;
                    case 0x1: kprintf("slli\t%s, %s, %u\n", rv64_reg_name(rd), rv64_reg_name(rs1), rs2 & 0x3F); break;
                    case 0x2: kprintf("slti\t%s, %s, %d\n", rv64_reg_name(rd), rv64_reg_name(rs1), imm_i); break;
                    case 0x3: kprintf("sltiu\t%s, %s, %d\n", rv64_reg_name(rd), rv64_reg_name(rs1), imm_i); break;
                    case 0x4: kprintf("xori\t%s, %s, %d\n", rv64_reg_name(rd), rv64_reg_name(rs1), imm_i); break;
                    case 0x5:
                        if (funct7 & 0x20) kprintf("srai\t%s, %s, %u\n", rv64_reg_name(rd), rv64_reg_name(rs1), rs2 & 0x3F);
                        else kprintf("srli\t%s, %s, %u\n", rv64_reg_name(rd), rv64_reg_name(rs1), rs2 & 0x3F);
                        break;
                    case 0x6: kprintf("ori\t%s, %s, %d\n", rv64_reg_name(rd), rv64_reg_name(rs1), imm_i); break;
                    case 0x7: kprintf("andi\t%s, %s, %d\n", rv64_reg_name(rd), rv64_reg_name(rs1), imm_i); break;
                    default:  kprintf("op-imm\tfunct3=%u\n", funct3); break;
                }
                break;

            case 0x1B: // OP-IMM-32
                if (funct3 == 0x0) kprintf("addiw\t%s, %s, %d\n", rv64_reg_name(rd), rv64_reg_name(rs1), imm_i);
                else kprintf("op-imm-32\tfunct3=%u\n", funct3);
                break;

            case 0x33: // OP (RV64I + RV64M + Zba + Zbb)
                if (funct7 == 0x00) {
                    const char* ops[] = {"add", "sll", "slt", "sltu", "xor", "srl", "or", "and"};
                    kprintf("%s\t%s, %s, %s\n", ops[funct3], rv64_reg_name(rd), rv64_reg_name(rs1), rv64_reg_name(rs2));
                } else if (funct7 == 0x20) {
                    if (funct3 == 0x0) kprintf("sub\t%s, %s, %s\n", rv64_reg_name(rd), rv64_reg_name(rs1), rv64_reg_name(rs2));
                    else if (funct3 == 0x5) kprintf("sra\t%s, %s, %s\n", rv64_reg_name(rd), rv64_reg_name(rs1), rv64_reg_name(rs2));
                    else kprintf("op funct7=0x20 funct3=%u\n", funct3);
                } else if (funct7 == 0x01) { // RV64M
                    const char* m_ops[] = {"mul", "mulh", "mulhsu", "mulhu", "div", "divu", "rem", "remu"};
                    kprintf("%s\t%s, %s, %s [RV64M]\n", m_ops[funct3], rv64_reg_name(rd), rv64_reg_name(rs1), rv64_reg_name(rs2));
                } else if (funct7 == 0x10) { // Zba
                    if (funct3 == 0x2) kprintf("sh1add\t%s, %s, %s [Zba]\n", rv64_reg_name(rd), rv64_reg_name(rs1), rv64_reg_name(rs2));
                    else if (funct3 == 0x4) kprintf("sh2add\t%s, %s, %s [Zba]\n", rv64_reg_name(rd), rv64_reg_name(rs1), rv64_reg_name(rs2));
                    else if (funct3 == 0x6) kprintf("sh3add\t%s, %s, %s [Zba]\n", rv64_reg_name(rd), rv64_reg_name(rs1), rv64_reg_name(rs2));
                    else kprintf("zba funct3=%u\n", funct3);
                } else if (funct7 == 0x05) { // Zbb
                    if (funct3 == 0x4) kprintf("min\t%s, %s, %s [Zbb]\n", rv64_reg_name(rd), rv64_reg_name(rs1), rv64_reg_name(rs2));
                    else if (funct3 == 0x6) kprintf("max\t%s, %s, %s [Zbb]\n", rv64_reg_name(rd), rv64_reg_name(rs1), rv64_reg_name(rs2));
                    else kprintf("zbb funct3=%u\n", funct3);
                } else {
                    kprintf("op\tfunct7=0x%02x\n", funct7);
                }
                break;

            case 0x37: // LUI
                kprintf("lui\t%s, 0x%x\n", rv64_reg_name(rd), (inst >> 12) & 0xFFFFF);
                break;

            case 0x17: // AUIPC
                kprintf("auipc\t%s, 0x%x\n", rv64_reg_name(rd), (inst >> 12) & 0xFFFFF);
                break;

            case 0x03: // LOAD
                if (funct3 == 0x3) kprintf("ld\t%s, %d(%s)\n", rv64_reg_name(rd), imm_i, rv64_reg_name(rs1));
                else if (funct3 == 0x2) kprintf("lw\t%s, %d(%s)\n", rv64_reg_name(rd), imm_i, rv64_reg_name(rs1));
                else kprintf("load\tfunct3=%u\n", funct3);
                break;

            case 0x23: // STORE
                {
                    I32 s_imm = (I32)((((inst >> 25) & 0x7F) << 5) | ((inst >> 7) & 0x1F));
                    if (s_imm & 0x800) s_imm |= 0xFFFFF000;
                    if (funct3 == 0x3) kprintf("sd\t%s, %d(%s)\n", rv64_reg_name(rs2), s_imm, rv64_reg_name(rs1));
                    else if (funct3 == 0x2) kprintf("sw\t%s, %d(%s)\n", rv64_reg_name(rs2), s_imm, rv64_reg_name(rs1));
                    else kprintf("store\tfunct3=%u\n", funct3);
                }
                break;

            case 0x63: // BRANCH
                {
                    U32 uimm12 = (inst >> 31) & 1;
                    U32 uimm10_5 = (inst >> 25) & 0x3F;
                    U32 uimm4_1 = (inst >> 8) & 0xF;
                    U32 uimm11 = (inst >> 7) & 1;
                    I32 b_offset = (I32)((uimm12 << 12) | (uimm11 << 11) | (uimm10_5 << 5) | (uimm4_1 << 1));
                    if (b_offset & 0x1000) b_offset |= 0xFFFFE000;
                    const char* b_ops[] = {"beq", "bne", "unk", "unk", "blt", "bge", "bltu", "bgeu"};
                    kprintf("%s\t%s, %s, %d (target: %p)\n", b_ops[funct3], rv64_reg_name(rs1), rv64_reg_name(rs2), b_offset, pc + b_offset);
                }
                break;

            case 0x67: // JALR
                kprintf("jalr\t%s, %s, %d\n", rv64_reg_name(rd), rv64_reg_name(rs1), imm_i);
                break;

            case 0x6F: // JAL
                {
                    U32 imm20 = (inst >> 31) & 1;
                    U32 imm10_1 = (inst >> 21) & 0x3FF;
                    U32 imm11 = (inst >> 20) & 1;
                    U32 imm19_12 = (inst >> 12) & 0xFF;
                    I32 j_offset = (I32)((imm20 << 20) | (imm19_12 << 12) | (imm11 << 11) | (imm10_1 << 1));
                    if (j_offset & 0x100000) j_offset |= 0xFFE00000;
                    if (rd == 0) kprintf("j\t%d (target: %p)\n", j_offset, pc + j_offset);
                    else kprintf("jal\t%s, %d (target: %p)\n", rv64_reg_name(rd), j_offset, pc + j_offset);
                }
                break;

            case 0x07: // VECTOR LOAD (RVV 1.0)
                {
                    const char* w_str = (funct3 == 0x7) ? "vle64.v" : (funct3 == 0x6) ? "vle32.v" : (funct3 == 0x5) ? "vle16.v" : "vle8.v";
                    kprintf("%s\t%s, (%s) [RVV 1.0]\n", w_str, rv64_vreg_name(rd), rv64_reg_name(rs1));
                }
                break;

            case 0x27: // VECTOR STORE (RVV 1.0)
                {
                    const char* w_str = (funct3 == 0x7) ? "vse64.v" : (funct3 == 0x6) ? "vse32.v" : (funct3 == 0x5) ? "vse16.v" : "vse8.v";
                    kprintf("%s\t%s, (%s) [RVV 1.0]\n", w_str, rv64_vreg_name(rd), rv64_reg_name(rs1));
                }
                break;

            case 0x57: // VECTOR ARITHMETIC / CONFIG (RVV 1.0)
                if (funct3 == 0x7) {
                    U32 zimm = (inst >> 20) & 0x7FF;
                    U32 sew_idx = (zimm >> 3) & 0x7;
                    U32 lmul_idx = zimm & 0x7;
                    const char* sew_strs[] = {"e8", "e16", "e32", "e64", "?", "?", "?", "?"};
                    const char* lmul_strs[] = {"m1", "m2", "m4", "m8", "?", "mf8", "mf4", "mf2"};
                    kprintf("vsetvli\t%s, %s, %s, %s, ta, ma [RVV 1.0]\n",
                            rv64_reg_name(rd), rv64_reg_name(rs1),
                            sew_strs[sew_idx], lmul_strs[lmul_idx]);
                } else if (funct3 == 0x0) { // OPIVV
                    U32 funct6 = (inst >> 26) & 0x3F;
                    U32 vs2 = (inst >> 20) & 0x1F;
                    U32 vs1 = (inst >> 15) & 0x1F;
                    const char* op = "vop.vv";
                    if (funct6 == 0x00) op = "vadd.vv";
                    else if (funct6 == 0x02) op = "vsub.vv";
                    else if (funct6 == 0x05) op = "vmin.vv";
                    else if (funct6 == 0x07) op = "vmax.vv";
                    else if (funct6 == 0x09) op = "vand.vv";
                    else if (funct6 == 0x0A) op = "vor.vv";
                    else if (funct6 == 0x0B) op = "vxor.vv";
                    kprintf("%s\t%s, %s, %s [RVV 1.0]\n", op, rv64_vreg_name(rd), rv64_vreg_name(vs2), rv64_vreg_name(vs1));
                } else if (funct3 == 0x2) { // OPMVV
                    U32 funct6 = (inst >> 26) & 0x3F;
                    U32 vs2 = (inst >> 20) & 0x1F;
                    U32 vs1 = (inst >> 15) & 0x1F;
                    if (funct6 == 0x25) {
                        kprintf("vmul.vv\t%s, %s, %s [RVV 1.0]\n", rv64_vreg_name(rd), rv64_vreg_name(vs2), rv64_vreg_name(vs1));
                    } else if (funct6 == 0x00) {
                        kprintf("vredsum.vs\t%s, %s, %s [RVV 1.0]\n", rv64_vreg_name(rd), rv64_vreg_name(vs2), rv64_vreg_name(vs1));
                    } else if (funct6 == 0x10) {
                        kprintf("vmv.x.s\t%s, %s [RVV 1.0]\n", rv64_reg_name(rd), rv64_vreg_name(vs2));
                    } else {
                        kprintf("opmvv\tfunct6=0x%x\n", funct6);
                    }
                } else if (funct3 == 0x4) { // OPIVX
                    U32 funct6 = (inst >> 26) & 0x3F;
                    U32 vs2 = (inst >> 20) & 0x1F;
                    if (funct6 == 0x17) {
                        kprintf("vmv.v.x\t%s, %s [RVV 1.0]\n", rv64_vreg_name(rd), rv64_reg_name(rs1));
                    } else if (funct6 == 0x00) {
                        kprintf("vadd.vx\t%s, %s, %s [RVV 1.0]\n", rv64_vreg_name(rd), rv64_vreg_name(vs2), rv64_reg_name(rs1));
                    } else if (funct6 == 0x02) {
                        kprintf("vsub.vx\t%s, %s, %s [RVV 1.0]\n", rv64_vreg_name(rd), rv64_vreg_name(vs2), rv64_reg_name(rs1));
                    } else if (funct6 == 0x05) {
                        kprintf("vmin.vx\t%s, %s, %s [RVV 1.0]\n", rv64_vreg_name(rd), rv64_vreg_name(vs2), rv64_reg_name(rs1));
                    } else if (funct6 == 0x07) {
                        kprintf("vmax.vx\t%s, %s, %s [RVV 1.0]\n", rv64_vreg_name(rd), rv64_vreg_name(vs2), rv64_reg_name(rs1));
                    } else {
                        kprintf("opivx\tfunct6=0x%x\n", funct6);
                    }
                } else if (funct3 == 0x3) { // OPIVI
                    U32 funct6 = (inst >> 26) & 0x3F;
                    if (funct6 == 0x17) {
                        I32 simm5 = (I32)((inst >> 15) & 0x1F);
                        if (simm5 & 0x10) simm5 |= 0xFFFFFFE0;
                        kprintf("vmv.v.i\t%s, %d [RVV 1.0]\n", rv64_vreg_name(rd), simm5);
                    } else {
                        kprintf("opivi\tfunct6=0x%x\n", funct6);
                    }
                } else if (funct3 == 0x6) { // OPMVX
                    U32 funct6 = (inst >> 26) & 0x3F;
                    U32 vs2 = (inst >> 20) & 0x1F;
                    if (funct6 == 0x25) {
                        kprintf("vmul.vx\t%s, %s, %s [RVV 1.0]\n", rv64_vreg_name(rd), rv64_vreg_name(vs2), rv64_reg_name(rs1));
                    } else {
                        kprintf("opmvx\tfunct6=0x%x\n", funct6);
                    }
                } else {
                    kprintf("rvv\tfunct3=0x%x\n", funct3);
                }
                break;

            default:
                kprintf("inst    0x%08x\n", inst);
                break;
        }
    }
}
