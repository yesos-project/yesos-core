#ifndef HOLYQ_RV64_EMIT_H
#define HOLYQ_RV64_EMIT_H

#include "types.h"

/*
 * ==============================================================================
 * YESOS RISC-V 64-BIT (RV64GC) NATIVE MACHINE CODE EMITTER FOR HOLYQ JIT
 * Standard RISC-V LP64 ABI | RV64I + RV64M + Zba + Zbb Instructions
 * ==============================================================================
 */

// RV64 Standard Register Numbers
typedef enum {
    RV_REG_ZERO = 0,   // Hard-wired zero
    RV_REG_RA   = 1,   // Return address
    RV_REG_SP   = 2,   // Stack pointer
    RV_REG_GP   = 3,   // Global pointer
    RV_REG_TP   = 4,   // Thread pointer
    RV_REG_T0   = 5,   // Temporary 0 / Alternate Link
    RV_REG_T1   = 6,   // Temporary 1
    RV_REG_T2   = 7,   // Temporary 2
    RV_REG_S0   = 8,   // Saved register 0 / Frame pointer (fp)
    RV_REG_S1   = 9,   // Saved register 1
    RV_REG_A0   = 10,  // Function argument 0 / Return value 0
    RV_REG_A1   = 11,  // Function argument 1 / Return value 1
    RV_REG_A2   = 12,  // Function argument 2
    RV_REG_A3   = 13,  // Function argument 3
    RV_REG_A4   = 14,  // Function argument 4
    RV_REG_A5   = 15,  // Function argument 5
    RV_REG_A6   = 16,  // Function argument 6
    RV_REG_A7   = 17,  // Function argument 7
    RV_REG_S2   = 18,  // Saved register 2
    RV_REG_S3   = 19,  // Saved register 3
    RV_REG_S4   = 20,  // Saved register 4
    RV_REG_S5   = 21,  // Saved register 5
    RV_REG_S6   = 22,  // Saved register 6
    RV_REG_S7   = 23,  // Saved register 7
    RV_REG_S8   = 24,  // Saved register 8
    RV_REG_S9   = 25,  // Saved register 9
    RV_REG_S10  = 26,  // Saved register 10
    RV_REG_S11  = 27,  // Saved register 11
    RV_REG_T3   = 28,  // Temporary 3
    RV_REG_T4   = 29,  // Temporary 4
    RV_REG_T5   = 30,  // Temporary 5
    RV_REG_T6   = 31   // Temporary 6
} RVReg;

// Emitter Code Buffer Structure
typedef struct {
    U32* code;         // Pointer to allocated machine code buffer (32-bit aligned)
    size_t count;      // Current number of 32-bit instructions emitted
    size_t capacity;   // Capacity in 32-bit instructions
    U64 base_pc;       // Virtual execution address (PC) where code will run
} RV64EmitBuf;

// Buffer Management
void rv64_emit_init(RV64EmitBuf* buf, U32* mem, size_t capacity_insts, U64 base_pc);
void rv64_emit_u32(RV64EmitBuf* buf, U32 instr);

// ALU Immediate (RV64I / RV64M)
void rv64_emit_addi(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm);
void rv64_emit_addiw(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm);
void rv64_emit_slli(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 shamt);
void rv64_emit_srli(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 shamt);
void rv64_emit_srai(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 shamt);
void rv64_emit_andi(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm);
void rv64_emit_ori(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm);
void rv64_emit_xori(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm);
void rv64_emit_slti(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm);
void rv64_emit_sltiu(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 imm);

// ALU Reg-Reg (RV64I + RV64M)
void rv64_emit_add(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_sub(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_mul(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_div(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_divu(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_rem(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_remu(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_sll(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_srl(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_sra(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_and(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_or(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_xor(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_slt(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_sltu(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);

// RV64 Zba & Zbb Bitmanip Extensions
void rv64_emit_sh1add(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2); // rd = rs2 + (rs1 << 1)
void rv64_emit_sh2add(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2); // rd = rs2 + (rs1 << 2)
void rv64_emit_sh3add(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2); // rd = rs2 + (rs1 << 3)
void rv64_emit_min(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_max(RV64EmitBuf* buf, U8 rd, U8 rs1, U8 rs2);
void rv64_emit_clz(RV64EmitBuf* buf, U8 rd, U8 rs1);
void rv64_emit_ctz(RV64EmitBuf* buf, U8 rd, U8 rs1);
void rv64_emit_cpop(RV64EmitBuf* buf, U8 rd, U8 rs1);

// Upper Immediate & Memory (Loads/Stores)
void rv64_emit_lui(RV64EmitBuf* buf, U8 rd, U32 imm20);
void rv64_emit_auipc(RV64EmitBuf* buf, U8 rd, U32 imm20);
void rv64_emit_ld(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 offset);
void rv64_emit_sd(RV64EmitBuf* buf, U8 rs2, U8 rs1, I32 offset);
void rv64_emit_lw(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 offset);
void rv64_emit_sw(RV64EmitBuf* buf, U8 rs2, U8 rs1, I32 offset);

// Jumps, Calls, Returns & Branches
void rv64_emit_jalr(RV64EmitBuf* buf, U8 rd, U8 rs1, I32 offset);
void rv64_emit_jal(RV64EmitBuf* buf, U8 rd, I32 offset);
void rv64_emit_ret(RV64EmitBuf* buf);
void rv64_emit_nop(RV64EmitBuf* buf);
void rv64_emit_call(RV64EmitBuf* buf, U64 func_ptr);

// Branch Instructions
void rv64_emit_beq(RV64EmitBuf* buf, U8 rs1, U8 rs2, I32 offset);
void rv64_emit_bne(RV64EmitBuf* buf, U8 rs1, U8 rs2, I32 offset);
void rv64_emit_blt(RV64EmitBuf* buf, U8 rs1, U8 rs2, I32 offset);
void rv64_emit_bge(RV64EmitBuf* buf, U8 rs1, U8 rs2, I32 offset);
void rv64_emit_bltu(RV64EmitBuf* buf, U8 rs1, U8 rs2, I32 offset);
void rv64_emit_bgeu(RV64EmitBuf* buf, U8 rs1, U8 rs2, I32 offset);

// Backpatching Helpers
size_t rv64_emit_branch_placeholder(RV64EmitBuf* buf, U32 funct3, U8 rs1, U8 rs2);
void   rv64_patch_branch(RV64EmitBuf* buf, size_t branch_idx, size_t target_idx);
size_t rv64_emit_jal_placeholder(RV64EmitBuf* buf, U8 rd);
void   rv64_patch_jal(RV64EmitBuf* buf, size_t jal_idx, size_t target_idx);

// 64-Bit Immediate Synthesis
void rv64_emit_li64(RV64EmitBuf* buf, U8 rd, U64 imm64);

// Cache & Pipeline Flush
void rv64_emit_fence_i(RV64EmitBuf* buf);
void rv64_flush_icache(void* start, size_t bytes);

// RVV 1.0 Vector Element Widths (SEW)
typedef enum {
    RVV_SEW_E8  = 0,
    RVV_SEW_E16 = 1,
    RVV_SEW_E32 = 2,
    RVV_SEW_E64 = 3
} RVV_SEW;

// RVV 1.0 Vector Register Group Multipliers (LMUL)
typedef enum {
    RVV_LMUL_M1  = 0,
    RVV_LMUL_M2  = 1,
    RVV_LMUL_M4  = 2,
    RVV_LMUL_M8  = 3,
    RVV_LMUL_MF8 = 5,
    RVV_LMUL_MF4 = 6,
    RVV_LMUL_MF2 = 7
} RVV_LMUL;

// RVV 1.0 Vector Configuration
void rv64_emit_vsetvli(RV64EmitBuf* buf, U8 rd, U8 rs1, RVV_SEW sew, RVV_LMUL lmul, Bool ta, Bool ma);

// RVV 1.0 Vector Unit-Stride Loads and Stores
void rv64_emit_vle8(RV64EmitBuf* buf, U8 vd, U8 rs1);
void rv64_emit_vse8(RV64EmitBuf* buf, U8 vs3, U8 rs1);
void rv64_emit_vle16(RV64EmitBuf* buf, U8 vd, U8 rs1);
void rv64_emit_vse16(RV64EmitBuf* buf, U8 vs3, U8 rs1);
void rv64_emit_vle32(RV64EmitBuf* buf, U8 vd, U8 rs1);
void rv64_emit_vse32(RV64EmitBuf* buf, U8 vs3, U8 rs1);
void rv64_emit_vle64(RV64EmitBuf* buf, U8 vd, U8 rs1);
void rv64_emit_vse64(RV64EmitBuf* buf, U8 vs3, U8 rs1);

// RVV 1.0 Vector-Vector Arithmetic (vd = vs2 op vs1)
void rv64_emit_vadd_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1);
void rv64_emit_vsub_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1);
void rv64_emit_vmul_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1);
void rv64_emit_vand_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1);
void rv64_emit_vor_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1);
void rv64_emit_vxor_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1);
void rv64_emit_vmin_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1);
void rv64_emit_vmax_vv(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1);

// RVV 1.0 Vector-Scalar Arithmetic (vd = vs2 op rs1)
void rv64_emit_vadd_vx(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 rs1);
void rv64_emit_vsub_vx(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 rs1);
void rv64_emit_vmul_vx(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 rs1);
void rv64_emit_vmin_vx(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 rs1);
void rv64_emit_vmax_vx(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 rs1);

// RVV 1.0 Reductions and Moves
void rv64_emit_vredsum_vs(RV64EmitBuf* buf, U8 vd, U8 vs2, U8 vs1);
void rv64_emit_vmv_x_s(RV64EmitBuf* buf, U8 rd, U8 vs2);
void rv64_emit_vmv_v_x(RV64EmitBuf* buf, U8 vd, U8 rs1);
void rv64_emit_vmv_v_i(RV64EmitBuf* buf, U8 vd, I8 simm5);

// Telemetry & Mini-Disassembler
void rv64_disasm_print(const U32* code, size_t count, U64 base_addr);
const char* rv64_reg_name(U8 reg);
const char* rv64_vreg_name(U8 reg);

#endif // HOLYQ_RV64_EMIT_H
