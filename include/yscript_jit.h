#ifndef YSCRIPT_JIT_H
#define YSCRIPT_JIT_H

#include "types.h"

#define JIT_MAX_SYMBOLS     256
#define JIT_MAX_VARS        128
#define JIT_CODE_BUFFER_SZ  (1024 * 1024) // 1 MB Dedicated JIT Machine Code Buffer
#define JIT_NAME_LEN        64

typedef enum {
    VAR_I64,
    VAR_EML64,
    VAR_PTR,
    VAR_U0
} JITVarType;

typedef struct {
    char name[JIT_NAME_LEN];
    U64 address;
    JITVarType return_type;
    U8 param_count;
    U32 code_size; // Size in bytes if native JIT compiled
} JITSymbol;

typedef struct {
    char name[JIT_NAME_LEN];
    JITVarType type;
    U64 value; // 64-bit raw value or pointer
} JITVariable;

typedef struct {
    U8* code_buffer;
    size_t code_size;
    size_t code_capacity;
    
    JITSymbol symbols[JIT_MAX_SYMBOLS];
    U32 symbol_count;
    
    JITVariable variables[JIT_MAX_VARS];
    U32 variable_count;
    
    Bool error_flag;
    char last_error[128];
} JITContext;

// Initialization and Lifecycle
U0   yscript_jit_init(U0);
JITContext* yscript_jit_get_context(U0);

// Symbol Management (Registering Kernel Exports)
Bool yscript_jit_register_symbol(const char* name, void* fn_ptr, JITVarType ret_type, U8 params);
U64  yscript_jit_find_symbol(const char* name);

// Variable Management
Bool yscript_jit_set_var(const char* name, JITVarType type, U64 value);
Bool yscript_jit_get_var(const char* name, JITVariable* out_var);

// JIT Compilation & Live Execution
Bool yscript_jit_compile_and_run(const char* source);
Bool yscript_jit_compile_function(const char* func_source, const char* out_func_name);
I64  yscript_jit_eval_expression(const char* expr);

// Script Execution from RAM / Memory
Bool yscript_jit_exec_file(const char* filename);

// Demo & Benchmark
U0   yscript_jit_benchmark(U0);
U0   yscript_jit_rvv_benchmark(U0);
U0   yscript_jit_disasm(const char* func_name);

// Aliases for holyq_jit_*
#define holyq_jit_init               yscript_jit_init
#define holyq_jit_get_context        yscript_jit_get_context
#define holyq_jit_register_symbol    yscript_jit_register_symbol
#define holyq_jit_find_symbol        yscript_jit_find_symbol
#define holyq_jit_set_var            yscript_jit_set_var
#define holyq_jit_get_var            yscript_jit_get_var
#define holyq_jit_compile_and_run    yscript_jit_compile_and_run
#define holyq_jit_compile_function   yscript_jit_compile_function
#define holyq_jit_eval_expression    yscript_jit_eval_expression
#define holyq_jit_exec_file          yscript_jit_exec_file
#define holyq_jit_benchmark          yscript_jit_benchmark
#define holyq_jit_rvv_benchmark      yscript_jit_rvv_benchmark
#define holyq_jit_disasm             yscript_jit_disasm

#endif // YSCRIPT_JIT_H
