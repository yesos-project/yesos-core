#ifndef HOLYQ_RV64_COMPILER_H
#define HOLYQ_RV64_COMPILER_H

#include "types.h"
#include "holyq_jit.h"
#include "holyq_rv64_emit.h"

/*
 * ==============================================================================
 * YESOS HOLYQ NATIVE RV64GC COMPILER ENGINE
 * Translates HolyQ Functions and Expressions into Executable RISC-V Machine Code
 * ==============================================================================
 */

// Compiles a complete HolyQ function into native RV64GC machine code in the JIT buffer
Bool holyq_rv64_compile_func(const char* func_source, const char* override_name, U32* out_code_size);

// Cell target: compile one function for a PMP cell (see include/cell.h).
// The generated code may only reference its own arena, its string pool and
// cell_rpc; calls to kernel functions and kernel globals are compile errors.
typedef struct {
    U32*   code;            // host buffer to emit into
    size_t capacity;        // in instructions
    U64    base_pc;         // address where the code executes in the cell
    char*  str_host;        // host pointer to the cell string pool
    U64    str_base;        // cell address of the string pool
    size_t str_cap;
    U64    rpc_addr;        // cell_rpc entry point
    U64    gfx_rect_addr;   // cell runtime drawing routines (canvas only)
    U64    gfx_clear_addr;
    U64    gfx_plot_addr;
    // Functions of the same cell program (multi-function packages). Calls to
    // them are emitted as fixed-size PC-relative calls so a sizing pass and
    // the final pass produce identical layouts.
    const char* const* fn_names;
    const U64*  fn_addrs;   // NULL during the sizing pass
    U32    fn_count;
    // outputs
    size_t str_used;
    U32    insts;
    Bool   error;
    char   error_msg[96];
} HolyQCellTarget;

// Compiles ONE function at target->code/base_pc. The string pool is shared
// across calls: the caller initialises str_used.
Bool holyq_rv64_compile_for_cell(const char* func_source, HolyQCellTarget* target);

// Compiles and evaluates an expression using native RV64GC JIT execution
Bool holyq_rv64_eval_expr_native(const char* expr, I64* out_result);

// Disassembles a compiled HolyQ function from RAM
void holyq_rv64_disasm_function(const char* func_name);

// Runs the comprehensive RV64GC JIT Hardware Benchmark Suite
void holyq_rv64_run_benchmark(void);

// Runs the RVV 1.0 Vector Auto-Vectorization Hardware Benchmark Suite
void holyq_rv64_run_rvv_benchmark(void);

#endif // HOLYQ_RV64_COMPILER_H
