#include "holyq_jit.h"
#include "memory.h"
#include "kprintf.h"
#include "timer.h"
#include "speaker.h"
#include "ramfs.h"
#include "task.h"
#include "redsea_eml.h"
#include "vfs.h"
#include "ata.h"
#include "shell.h"
#include "holyq_rv64_compiler.h"
#include "virtio_net.h"
#include "pmp.h"
#include "app_registry.h"

static JITContext g_jit_ctx;

// User-defined HolyQ functions in RAM
#define JIT_MAX_USER_FUNCS     32
#define JIT_USER_FUNC_BODY_SZ  4096

typedef struct {
    char name[JIT_NAME_LEN];
    char body[JIT_USER_FUNC_BODY_SZ];
} JITUserFunc;

static JITUserFunc g_user_funcs[JIT_MAX_USER_FUNCS];
static U32 g_user_func_count = 0;

// Pre-allocated static buffers for script arrays and strings
#define JIT_MAX_BUFFERS   16
#define JIT_BUFFER_SIZE   256
static char g_jit_buffers[JIT_MAX_BUFFERS][JIT_BUFFER_SIZE];
static U32 g_jit_buffer_idx = 0;

static char g_jit_str_pool[8][256];
static int g_jit_str_idx = 0;

// Forward declarations
static I64 eval_expr(const char** p);
static Bool holyq_jit_exec_statement(const char* stmt);
static Bool holyq_jit_exec_statements(const char* script);

// Helper to append byte to JIT code buffer
static inline void emit_u8(U8 b) {
    if (g_jit_ctx.code_size < g_jit_ctx.code_capacity) {
        g_jit_ctx.code_buffer[g_jit_ctx.code_size++] = b;
    }
}

static inline void emit_u32(U32 d) {
    emit_u8((U8)(d & 0xFF));
    emit_u8((U8)((d >> 8) & 0xFF));
    emit_u8((U8)((d >> 16) & 0xFF));
    emit_u8((U8)((d >> 24) & 0xFF));
}

static inline __attribute__((unused)) void emit_u64(U64 q) {
    emit_u32((U32)(q & 0xFFFFFFFF));
    emit_u32((U32)((q >> 32) & 0xFFFFFFFF));
}

// Register symbols
Bool holyq_jit_register_symbol(const char* name, void* fn_ptr, JITVarType ret_type, U8 params) {
    if (!name || !fn_ptr || g_jit_ctx.symbol_count >= JIT_MAX_SYMBOLS) return FALSE;

    for (U32 i = 0; i < g_jit_ctx.symbol_count; i++) {
        if (StrCmp(g_jit_ctx.symbols[i].name, name) == 0) {
            g_jit_ctx.symbols[i].address = (U64)fn_ptr;
            g_jit_ctx.symbols[i].return_type = ret_type;
            g_jit_ctx.symbols[i].param_count = params;
            return TRUE;
        }
    }

    JITSymbol* s = &g_jit_ctx.symbols[g_jit_ctx.symbol_count++];
    StrNCpy(s->name, name, sizeof(s->name));
    s->address = (U64)fn_ptr;
    s->return_type = ret_type;
    s->param_count = params;
    return TRUE;
}

U64 holyq_jit_find_symbol(const char* name) {
    if (!name) return 0;
    for (U32 i = 0; i < g_jit_ctx.symbol_count; i++) {
        if (StrCmp(g_jit_ctx.symbols[i].name, name) == 0) {
            return g_jit_ctx.symbols[i].address;
        }
    }
    return 0;
}

Bool holyq_jit_set_var(const char* name, JITVarType type, U64 value) {
    if (!name || g_jit_ctx.variable_count >= JIT_MAX_VARS) return FALSE;

    for (U32 i = 0; i < g_jit_ctx.variable_count; i++) {
        if (StrCmp(g_jit_ctx.variables[i].name, name) == 0) {
            g_jit_ctx.variables[i].type = type;
            g_jit_ctx.variables[i].value = value;
            return TRUE;
        }
    }

    JITVariable* v = &g_jit_ctx.variables[g_jit_ctx.variable_count++];
    StrNCpy(v->name, name, sizeof(v->name));
    v->type = type;
    v->value = value;
    return TRUE;
}

Bool holyq_jit_get_var(const char* name, JITVariable* out_var) {
    if (!name || !out_var) return FALSE;
    for (U32 i = 0; i < g_jit_ctx.variable_count; i++) {
        if (StrCmp(g_jit_ctx.variables[i].name, name) == 0) {
            *out_var = g_jit_ctx.variables[i];
            return TRUE;
        }
    }
    return FALSE;
}

// Machine code lives in the PMP JIT arena (.jit): the only memory that is
// both writable and executable. The heap and .bss are never executable.
static U8 g_jit_code_arena[JIT_CODE_BUFFER_SZ] __attribute__((section(".jit"), aligned(4096)));

U0 holyq_jit_init(U0) {
    MemSet(&g_jit_ctx, 0, sizeof(JITContext));
    g_jit_ctx.code_capacity = JIT_CODE_BUFFER_SZ;
    g_jit_ctx.code_buffer = g_jit_code_arena;
    g_jit_ctx.code_size = 0;
    g_user_func_count = 0;
    g_jit_buffer_idx = 0;
    g_jit_str_idx = 0;

    // Core Kernel Exports & Aliases
    holyq_jit_register_symbol("kprintf", (void*)kprintf, VAR_U0, 1);
    holyq_jit_register_symbol("print", (void*)kprintf, VAR_U0, 1);
    holyq_jit_register_symbol("speaker_event", (void*)speaker_event, VAR_U0, 1);
    holyq_jit_register_symbol("SleepMS", (void*)SleepMS, VAR_U0, 1);
    holyq_jit_register_symbol("sleep", (void*)SleepMS, VAR_U0, 1);
    holyq_jit_register_symbol("Malloc", (void*)Malloc, VAR_PTR, 1);
    holyq_jit_register_symbol("Free", (void*)Free, VAR_U0, 1);

    holyq_jit_register_symbol("timer_get_uptime_ms", (void*)timer_get_uptime_ms, VAR_I64, 0);
    holyq_jit_register_symbol("timer_get_ticks", (void*)timer_get_ticks, VAR_I64, 0);

    // Storage Exports
    holyq_jit_register_symbol("redsea_eml_format", (void*)redsea_eml_format, VAR_I64, 2);
    holyq_jit_register_symbol("redsea_eml_mount", (void*)redsea_eml_mount, VAR_I64, 1);
    holyq_jit_register_symbol("redsea_eml_list_files", (void*)redsea_eml_list_files, VAR_U0, 0);
    holyq_jit_register_symbol("redsea_eml_list_free_extents", (void*)redsea_eml_list_free_extents, VAR_U0, 0);
    holyq_jit_register_symbol("ata_dump_telemetry", (void*)ata_dump_telemetry, VAR_U0, 0);
    holyq_jit_register_symbol("jit_bench", (void*)holyq_jit_benchmark, VAR_U0, 0);
    holyq_jit_register_symbol("holyq_jit_benchmark", (void*)holyq_jit_benchmark, VAR_U0, 0);
    holyq_jit_register_symbol("rvv_bench", (void*)holyq_rv64_run_rvv_benchmark, VAR_U0, 0);
    holyq_jit_register_symbol("holyq_rv64_run_rvv_benchmark", (void*)holyq_rv64_run_rvv_benchmark, VAR_U0, 0);
    holyq_jit_register_symbol("net_ping", (void*)net_ping, VAR_I64, 2);
    holyq_jit_register_symbol("net_telemetry", (void*)net_send_telemetry, VAR_I64, 2);
    holyq_jit_register_symbol("net_status", (void*)net_print_status, VAR_U0, 0);
    holyq_jit_register_symbol("net_bench", (void*)net_run_benchmark, VAR_U0, 0);

    // Locked PMP status/self-test (read-only: the layout cannot be changed)
    holyq_jit_register_symbol("pmp_dump_config", (void*)pmp_dump_config, VAR_U0, 0);
    holyq_jit_register_symbol("pmp_self_test", (void*)pmp_self_test, VAR_I64, 0);

#ifdef YESOS_WITH_PACKAGES
    // Dynamic App Registry & Package Mounting
    holyq_jit_register_symbol("app_registry_register", (void*)app_registry_register, VAR_I64, 3);
#endif

#ifdef __riscv
    kprintf("[JIT] HolyQ M-Mode Live JIT Compiler initialized (%u symbols registered).\n", g_jit_ctx.symbol_count);
#else
    kprintf("[JIT] HolyQ Ring-0 Live JIT Compiler initialized (%u symbols registered).\n", g_jit_ctx.symbol_count);
#endif
}

JITContext* holyq_jit_get_context(U0) {
    return &g_jit_ctx;
}

// Tokenizer & Parser Helpers
static const char* skip_whitespace(const char* p) {
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    return p;
}

static const char* skip_comments_and_whitespace(const char* p) {
    while (*p) {
        p = skip_whitespace(p);
        if (*p == '/' && *(p + 1) == '/') {
            p += 2;
            while (*p && *p != '\n') p++;
        } else if (*p == '/' && *(p + 1) == '*') {
            p += 2;
            while (*p && !(*p == '*' && *(p + 1) == '/')) p++;
            if (*p) p += 2;
        } else {
            break;
        }
    }
    return p;
}

static Bool is_digit(char c) {
    return c >= '0' && c <= '9';
}

static Bool is_hex_digit(char c) {
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int hex_val(char c) {
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return c - '0';
}

static Bool is_alpha(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static Bool is_alnum(char c) {
    return is_alpha(c) || is_digit(c);
}

static Bool match_keyword(const char** p, const char* kw) {
    const char* s = *p;
    size_t len = StrLen(kw);
    for (size_t i = 0; i < len; i++) {
        if (s[i] != kw[i]) return FALSE;
    }
    if (is_alnum(s[len])) return FALSE; // Must be full token
    *p += len;
    return TRUE;
}

static Bool extract_identifier(const char** p, char* out, int max_len) {
    const char* s = skip_whitespace(*p);
    if (!is_alpha(*s)) return FALSE;
    int idx = 0;
    while (is_alnum(*s)) {
        if (idx < max_len - 1) {
            out[idx++] = *s;
        }
        s++;
    }
    out[idx] = '\0';
    *p = s;
    return TRUE;
}

static Bool extract_block(const char** p, char* out, int max_len) {
    const char* s = skip_comments_and_whitespace(*p);
    if (*s != '{') return FALSE;
    s++; // Skip '{'
    int depth = 1;
    int idx = 0;
    while (*s && depth > 0) {
        if (*s == '{') depth++;
        else if (*s == '}') depth--;

        if (depth > 0) {
            if (idx < max_len - 1) {
                out[idx++] = *s;
            }
        }
        s++;
    }
    out[idx] = '\0';
    *p = s;
    return (depth == 0);
}

// Recursive Expression Evaluator with Operator Precedence
static I64 eval_primary(const char** p) {
    *p = skip_whitespace(*p);
    if (**p == '\0') return 0;

    // Parenthesized expression: ( expr )
    if (**p == '(') {
        (*p)++;
        I64 val = eval_expr(p);
        *p = skip_whitespace(*p);
        if (**p == ')') (*p)++;
        return val;
    }

    // String literal: "..."
    if (**p == '"') {
        (*p)++;
        int slot = g_jit_str_idx++ % 8;
        char* buf = g_jit_str_pool[slot];
        int bi = 0;
        while (**p && **p != '"' && bi < 254) {
            if (**p == '\\' && *(*p + 1) == 'n') {
                buf[bi++] = '\n';
                *p += 2;
            } else if (**p == '\\' && *(*p + 1) == 't') {
                buf[bi++] = '\t';
                *p += 2;
            } else if (**p == '\\' && *(*p + 1) == '"') {
                buf[bi++] = '"';
                *p += 2;
            } else {
                buf[bi++] = *(*p)++;
            }
        }
        buf[bi] = '\0';
        if (**p == '"') (*p)++;
        return (I64)(U64)buf;
    }

    // Hex literal: 0x...
    if (**p == '0' && (*(*p + 1) == 'x' || *(*p + 1) == 'X')) {
        *p += 2;
        I64 val = 0;
        while (is_hex_digit(**p)) {
            val = (val << 4) | hex_val(**p);
            (*p)++;
        }
        return val;
    }

    // Decimal literal
    if (is_digit(**p)) {
        I64 val = 0;
        while (is_digit(**p)) {
            val = val * 10 + (**p - '0');
            (*p)++;
        }
        return val;
    }

    // Prefix increment / decrement: ++var, --var
    if (**p == '+' && *(*p + 1) == '+') {
        *p += 2;
        char ident[64];
        if (extract_identifier(p, ident, 63)) {
            JITVariable var;
            if (holyq_jit_get_var(ident, &var)) {
                var.value++;
                holyq_jit_set_var(ident, var.type, var.value);
                return (I64)var.value;
            }
        }
        return 0;
    }
    if (**p == '-' && *(*p + 1) == '-') {
        *p += 2;
        char ident[64];
        if (extract_identifier(p, ident, 63)) {
            JITVariable var;
            if (holyq_jit_get_var(ident, &var)) {
                var.value--;
                holyq_jit_set_var(ident, var.type, var.value);
                return (I64)var.value;
            }
        }
        return 0;
    }

    // Identifier: variable or function call
    if (is_alpha(**p)) {
        char ident[64];
        extract_identifier(p, ident, 63);
        *p = skip_whitespace(*p);

        // Function call: ident(arg0, arg1, ...)
        if (**p == '(') {
            (*p)++;
            U64 args[8] = {0};
            int argc = 0;

            while (**p && **p != ')') {
                *p = skip_whitespace(*p);
                if (**p == ')') break;
                I64 arg_val = eval_expr(p);
                if (argc < 8) {
                    args[argc++] = (U64)arg_val;
                }
                *p = skip_whitespace(*p);
                if (**p == ',') (*p)++;
            }
            if (**p == ')') (*p)++;

            // 1. Check registered symbols and native JIT-compiled functions first
            U64 sym_addr = holyq_jit_find_symbol(ident);
            if (sym_addr != 0) {
                typedef U64 (*Fn8)(U64, U64, U64, U64, U64, U64, U64, U64);
                Fn8 fn = (Fn8)sym_addr;
                return (I64)fn(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7]);
            }

            // 2. Check user-defined script functions (interpreted fallback)
            for (U32 i = 0; i < g_user_func_count; i++) {
                if (StrCmp(g_user_funcs[i].name, ident) == 0) {
                    holyq_jit_exec_statements(g_user_funcs[i].body);
                    return 0;
                }
            }
            return 0;
        }

        // Postfix increment / decrement: var++, var--
        if (**p == '+' && *(*p + 1) == '+') {
            *p += 2;
            JITVariable var;
            if (holyq_jit_get_var(ident, &var)) {
                I64 old = (I64)var.value;
                holyq_jit_set_var(ident, var.type, var.value + 1);
                return old;
            }
            return 0;
        }
        if (**p == '-' && *(*p + 1) == '-') {
            *p += 2;
            JITVariable var;
            if (holyq_jit_get_var(ident, &var)) {
                I64 old = (I64)var.value;
                holyq_jit_set_var(ident, var.type, var.value - 1);
                return old;
            }
            return 0;
        }

        // Variable lookup
        JITVariable var;
        if (holyq_jit_get_var(ident, &var)) {
            return (I64)var.value;
        }
        return 0;
    }

    return 0;
}

static I64 eval_unary(const char** p) {
    *p = skip_whitespace(*p);
    if (**p == '-') { (*p)++; return -eval_unary(p); }
    if (**p == '+') { (*p)++; return eval_unary(p); }
    if (**p == '!') { (*p)++; return !eval_unary(p); }
    if (**p == '~') { (*p)++; return ~eval_unary(p); }
    return eval_primary(p);
}

static I64 eval_multiplicative(const char** p) {
    I64 left = eval_unary(p);
    while (1) {
        *p = skip_whitespace(*p);
        if (**p == '*' && *(*p + 1) != '=') {
            (*p)++;
            left *= eval_unary(p);
        } else if (**p == '/' && *(*p + 1) != '=') {
            (*p)++;
            I64 right = eval_unary(p);
            left = (right != 0) ? (left / right) : 0;
        } else if (**p == '%' && *(*p + 1) != '=') {
            (*p)++;
            I64 right = eval_unary(p);
            left = (right != 0) ? (left % right) : 0;
        } else {
            break;
        }
    }
    return left;
}

static I64 eval_additive(const char** p) {
    I64 left = eval_multiplicative(p);
    while (1) {
        *p = skip_whitespace(*p);
        if (**p == '+' && *(*p + 1) != '+' && *(*p + 1) != '=') {
            (*p)++;
            left += eval_multiplicative(p);
        } else if (**p == '-' && *(*p + 1) != '-' && *(*p + 1) != '=') {
            (*p)++;
            left -= eval_multiplicative(p);
        } else {
            break;
        }
    }
    return left;
}

static I64 eval_shift(const char** p) {
    I64 left = eval_additive(p);
    while (1) {
        *p = skip_whitespace(*p);
        if (**p == '<' && *(*p + 1) == '<') {
            *p += 2;
            left <<= eval_additive(p);
        } else if (**p == '>' && *(*p + 1) == '>') {
            *p += 2;
            left >>= eval_additive(p);
        } else {
            break;
        }
    }
    return left;
}

static I64 eval_relational(const char** p) {
    I64 left = eval_shift(p);
    while (1) {
        *p = skip_whitespace(*p);
        if (**p == '<' && *(*p + 1) == '=') {
            *p += 2;
            left = (left <= eval_shift(p));
        } else if (**p == '>' && *(*p + 1) == '=') {
            *p += 2;
            left = (left >= eval_shift(p));
        } else if (**p == '<' && *(*p + 1) != '<') {
            (*p)++;
            left = (left < eval_shift(p));
        } else if (**p == '>' && *(*p + 1) != '>') {
            (*p)++;
            left = (left > eval_shift(p));
        } else {
            break;
        }
    }
    return left;
}

static I64 eval_equality(const char** p) {
    I64 left = eval_relational(p);
    while (1) {
        *p = skip_whitespace(*p);
        if (**p == '=' && *(*p + 1) == '=') {
            *p += 2;
            left = (left == eval_relational(p));
        } else if (**p == '!' && *(*p + 1) == '=') {
            *p += 2;
            left = (left != eval_relational(p));
        } else {
            break;
        }
    }
    return left;
}

static I64 eval_bitwise_and(const char** p) {
    I64 left = eval_equality(p);
    while (1) {
        *p = skip_whitespace(*p);
        if (**p == '&' && *(*p + 1) != '&') {
            (*p)++;
            left &= eval_equality(p);
        } else {
            break;
        }
    }
    return left;
}

static I64 eval_bitwise_xor(const char** p) {
    I64 left = eval_bitwise_and(p);
    while (1) {
        *p = skip_whitespace(*p);
        if (**p == '^') {
            (*p)++;
            left ^= eval_bitwise_and(p);
        } else {
            break;
        }
    }
    return left;
}

static I64 eval_bitwise_or(const char** p) {
    I64 left = eval_bitwise_xor(p);
    while (1) {
        *p = skip_whitespace(*p);
        if (**p == '|' && *(*p + 1) != '|') {
            (*p)++;
            left |= eval_bitwise_xor(p);
        } else {
            break;
        }
    }
    return left;
}

static I64 eval_logical_and(const char** p) {
    I64 left = eval_bitwise_or(p);
    while (1) {
        *p = skip_whitespace(*p);
        if (**p == '&' && *(*p + 1) == '&') {
            *p += 2;
            I64 right = eval_bitwise_or(p);
            left = (left && right);
        } else {
            break;
        }
    }
    return left;
}

static I64 eval_logical_or(const char** p) {
    I64 left = eval_logical_and(p);
    while (1) {
        *p = skip_whitespace(*p);
        if (**p == '|' && *(*p + 1) == '|') {
            *p += 2;
            I64 right = eval_logical_and(p);
            left = (left || right);
        } else {
            break;
        }
    }
    return left;
}

static I64 eval_expr(const char** p) {
    return eval_logical_or(p);
}

I64 holyq_jit_eval_expression(const char* expr) {
    if (!expr) return 0;
    I64 native_res = 0;
    if (holyq_rv64_eval_expr_native(expr, &native_res)) {
        return native_res;
    }
    const char* p = expr;
    return eval_expr(&p);
}

Bool holyq_jit_compile_function(const char* func_source, const char* out_func_name) {
    U32 code_sz = 0;
    return holyq_rv64_compile_func(func_source, out_func_name, &code_sz);
}

U0 holyq_jit_benchmark(U0) {
    holyq_rv64_run_benchmark();
}

U0 holyq_jit_rvv_benchmark(U0) {
    holyq_rv64_run_rvv_benchmark();
}

void holyq_jit_disasm(const char* func_name) {
    holyq_rv64_disasm_function(func_name);
}

// Single Statement Executor
static Bool holyq_jit_exec_statement(const char* stmt) {
    if (!stmt) return FALSE;
    const char* p = skip_comments_and_whitespace(stmt);
    if (*p == '\0' || *p == ';') return TRUE;

    // Check for type declaration: I64, U64, EML64, I32, U32, I16, U16, I8, U8, Bool, char, U8, int, U0, void
    JITVarType var_type = VAR_I64;
    Bool is_decl = FALSE;

    if (match_keyword(&p, "I64") || match_keyword(&p, "int")) {
        var_type = VAR_I64; is_decl = TRUE;
    } else if (match_keyword(&p, "U64") || match_keyword(&p, "U32") || match_keyword(&p, "I32") || match_keyword(&p, "Bool")) {
        var_type = VAR_I64; is_decl = TRUE;
    } else if (match_keyword(&p, "EML64")) {
        var_type = VAR_EML64; is_decl = TRUE;
    } else if (match_keyword(&p, "char") || match_keyword(&p, "U8") || match_keyword(&p, "I8") || match_keyword(&p, "U16") || match_keyword(&p, "I16")) {
        var_type = VAR_I64; is_decl = TRUE;
    } else if (match_keyword(&p, "U0") || match_keyword(&p, "void")) {
        var_type = VAR_U0; is_decl = TRUE;
    }

    if (is_decl) {
        p = skip_whitespace(p);
        if (*p == '*') {
            var_type = VAR_PTR;
            p++;
        }
        char var_name[64];
        if (extract_identifier(&p, var_name, 63)) {
            p = skip_whitespace(p);
            // Array buffer: e.g. char buf[64];
            if (*p == '[') {
                p++;
                I64 arr_len = eval_expr(&p);
                p = skip_whitespace(p);
                if (*p == ']') p++;

                char* buf = g_jit_buffers[g_jit_buffer_idx++ % JIT_MAX_BUFFERS];
                MemSet(buf, 0, JIT_BUFFER_SIZE);
                holyq_jit_set_var(var_name, VAR_PTR, (U64)buf);
                (U0)arr_len;
                return TRUE;
            }
            if (*p == '=') {
                p++;
                I64 val = eval_expr(&p);
                holyq_jit_set_var(var_name, var_type, (U64)val);
                return TRUE;
            } else {
                holyq_jit_set_var(var_name, var_type, 0);
                return TRUE;
            }
        }
    }

    // Check for variable assignment: var = expr, var += expr, var -= expr, etc.
    const char* ident_start = p;
    char var_name[64];
    if (extract_identifier(&p, var_name, 63)) {
        p = skip_whitespace(p);
        if (*p == '=' && *(p + 1) != '=') {
            p++;
            I64 val = eval_expr(&p);
            holyq_jit_set_var(var_name, VAR_I64, (U64)val);
            return TRUE;
        } else if (*p == '+' && *(p + 1) == '=') {
            p += 2;
            I64 val = eval_expr(&p);
            JITVariable var;
            if (holyq_jit_get_var(var_name, &var)) {
                holyq_jit_set_var(var_name, var.type, var.value + val);
            }
            return TRUE;
        } else if (*p == '-' && *(p + 1) == '=') {
            p += 2;
            I64 val = eval_expr(&p);
            JITVariable var;
            if (holyq_jit_get_var(var_name, &var)) {
                holyq_jit_set_var(var_name, var.type, var.value - val);
            }
            return TRUE;
        } else if (*p == '*' && *(p + 1) == '=') {
            p += 2;
            I64 val = eval_expr(&p);
            JITVariable var;
            if (holyq_jit_get_var(var_name, &var)) {
                holyq_jit_set_var(var_name, var.type, var.value * val);
            }
            return TRUE;
        } else if (*p == '/' && *(p + 1) == '=') {
            p += 2;
            I64 val = eval_expr(&p);
            JITVariable var;
            if (holyq_jit_get_var(var_name, &var) && val != 0) {
                holyq_jit_set_var(var_name, var.type, var.value / val);
            }
            return TRUE;
        } else if (*p == '+' && *(p + 1) == '+') {
            JITVariable var;
            if (holyq_jit_get_var(var_name, &var)) {
                holyq_jit_set_var(var_name, var.type, var.value + 1);
            }
            return TRUE;
        } else if (*p == '-' && *(p + 1) == '-') {
            JITVariable var;
            if (holyq_jit_get_var(var_name, &var)) {
                holyq_jit_set_var(var_name, var.type, var.value - 1);
            }
            return TRUE;
        }
    }

    // Standalone expression or function call: evaluate directly
    p = ident_start;
    eval_expr(&p);
    return TRUE;
}

// Multi-statement & Control Flow Interpreter / JIT Dispatcher
static Bool holyq_jit_exec_statements(const char* script) {
    if (!script) return FALSE;
    const char* p = script;

    while (*p != '\0') {
        if (TaskIsBreakRequested()) {
            kprintf("\n[HOLYQ JIT] Interrupted by User Break (Ctrl+Alt+C).\n");
            TaskClearBreak();
            return FALSE;
        }

        p = skip_comments_and_whitespace(p);
        if (*p == '\0') break;

        // Skip standalone semicolons and stray braces
        if (*p == ';' || *p == '{' || *p == '}') {
            p++;
            continue;
        }

        // 1. Extern declarations: e.g. `extern U0 kprintf(U8* fmt, ...);`
        if (match_keyword(&p, "extern")) {
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // 2. Class declarations: e.g. `class CStar { ... };`
        if (match_keyword(&p, "class")) {
            while (*p && *p != '{' && *p != ';') p++;
            if (*p == '{') {
                char dummy[256];
                extract_block(&p, dummy, 255);
            }
            while (*p && *p != ';') p++;
            if (*p == ';') p++;
            continue;
        }

        // 3. For loop: `for (init; cond; step) { body }`
        if (match_keyword(&p, "for")) {
            p = skip_whitespace(p);
            if (*p == '(') p++;

            char init_stmt[128]; int ii = 0;
            while (*p && *p != ';' && ii < 127) init_stmt[ii++] = *p++;
            init_stmt[ii] = '\0';
            if (*p == ';') p++;

            char cond_expr[128]; int ci = 0;
            while (*p && *p != ';' && ci < 127) cond_expr[ci++] = *p++;
            cond_expr[ci] = '\0';
            if (*p == ';') p++;

            char step_stmt[128]; int si = 0;
            while (*p && *p != ')' && si < 127) step_stmt[si++] = *p++;
            step_stmt[si] = '\0';
            if (*p == ')') p++;

            char body[2048];
            if (extract_block(&p, body, 2047)) {
                holyq_jit_exec_statement(init_stmt);
                while (1) {
                    if (TaskIsBreakRequested()) {
                        TaskClearBreak();
                        break;
                    }
                    I64 cond_val = (cond_expr[0] != '\0') ? holyq_jit_eval_expression(cond_expr) : 1;
                    if (!cond_val) break;
                    holyq_jit_exec_statements(body);
                    holyq_jit_exec_statement(step_stmt);
                }
            }
            continue;
        }

        // 4. While loop: `while (cond) { body }`
        if (match_keyword(&p, "while")) {
            p = skip_whitespace(p);
            if (*p == '(') p++;

            char cond_expr[128]; int ci = 0;
            while (*p && *p != ')' && ci < 127) cond_expr[ci++] = *p++;
            cond_expr[ci] = '\0';
            if (*p == ')') p++;

            char body[2048];
            if (extract_block(&p, body, 2047)) {
                while (1) {
                    if (TaskIsBreakRequested()) {
                        TaskClearBreak();
                        break;
                    }
                    I64 cond_val = holyq_jit_eval_expression(cond_expr);
                    if (!cond_val) break;
                    holyq_jit_exec_statements(body);
                }
            }
            continue;
        }

        // 5. If-Else: `if (cond) { ... } else { ... }`
        if (match_keyword(&p, "if")) {
            p = skip_whitespace(p);
            if (*p == '(') p++;

            char cond_expr[128]; int ci = 0;
            while (*p && *p != ')' && ci < 127) cond_expr[ci++] = *p++;
            cond_expr[ci] = '\0';
            if (*p == ')') p++;

            char then_body[2048];
            if (extract_block(&p, then_body, 2047)) {
                p = skip_comments_and_whitespace(p);
                char else_body[2048];
                Bool has_else = FALSE;
                if (match_keyword(&p, "else")) {
                    has_else = extract_block(&p, else_body, 2047);
                }

                I64 cond_val = holyq_jit_eval_expression(cond_expr);
                if (cond_val) {
                    holyq_jit_exec_statements(then_body);
                } else if (has_else) {
                    holyq_jit_exec_statements(else_body);
                }
            }
            continue;
        }

        // 6. User Function Definition: e.g. `U0 Main() { ... }` or `I64 Func() { ... }`
        const char* probe = p;
        const char* func_start = p;
        Bool is_func_def = FALSE;
        if (match_keyword(&probe, "U0") || match_keyword(&probe, "I64") || match_keyword(&probe, "U64") || match_keyword(&probe, "EML64") || match_keyword(&probe, "void")) {
            probe = skip_whitespace(probe);
            if (*probe == '*') probe++;
            char fn_name[64];
            if (extract_identifier(&probe, fn_name, 63)) {
                probe = skip_whitespace(probe);
                if (*probe == '(') {
                    while (*probe && *probe != ')') probe++;
                    if (*probe == ')') probe++;
                    probe = skip_comments_and_whitespace(probe);
                    if (*probe == '{') {
                        is_func_def = TRUE;
                        p = probe;
                        char body[JIT_USER_FUNC_BODY_SZ];
                        if (extract_block(&p, body, JIT_USER_FUNC_BODY_SZ - 1)) {
                            // Compile natively to RV64GC machine code
                            holyq_jit_compile_function(func_start, fn_name);

                            int existing_idx = -1;
                            for (U32 f = 0; f < g_user_func_count; f++) {
                                if (StrCmp(g_user_funcs[f].name, fn_name) == 0) {
                                    existing_idx = (int)f;
                                    break;
                                }
                            }
                            int target_idx = (existing_idx >= 0) ? existing_idx : (int)g_user_func_count;
                            if (target_idx < JIT_MAX_USER_FUNCS) {
                                StrNCpy(g_user_funcs[target_idx].name, fn_name, sizeof(g_user_funcs[target_idx].name));
                                StrNCpy(g_user_funcs[target_idx].body, body, sizeof(g_user_funcs[target_idx].body));
                                if (existing_idx < 0) {
                                    g_user_func_count++;
                                }
                            }
                        }
                    }
                }
            }
        }
        if (is_func_def) continue;

        // 7. Regular statement up to ';'
        char stmt_buf[512];
        int si = 0;
        while (*p && *p != ';' && si < 510) {
            stmt_buf[si++] = *p++;
        }
        stmt_buf[si] = '\0';
        if (*p == ';') p++;

        holyq_jit_exec_statement(stmt_buf);
    }

    return TRUE;
}

// Live Execution Entry Points
Bool holyq_jit_compile_and_run(const char* source) {
    if (!source) return FALSE;
    return holyq_jit_exec_statements(source);
}

Bool holyq_jit_exec_file(const char* filename) {
    if (!filename) return FALSE;

    size_t sz = 0;
    Bool need_free = FALSE;
    U8* content = vfs_read_file(filename, &sz);
    if (content && sz > 0) {
        need_free = TRUE;
    } else {
        content = ramfs_read(filename, &sz);
    }

    if (!content || sz == 0) {
        kprintf("HolyQ JIT: Cannot open file '%s' from RamFS or RedSea-EML Disk.\n", filename);
        return FALSE;
    }

#ifdef __riscv
    kprintf("\n[HOLYQ JIT] Compiling and executing '%s' (%u bytes) in M-Mode...\n", filename, (U32)sz);
#else
    kprintf("\n[HOLYQ JIT] Compiling and executing '%s' (%u bytes) in Ring 0...\n", filename, (U32)sz);
#endif

    Bool success = holyq_jit_exec_statements((const char*)content);

    kprintf("[HOLYQ JIT] '%s' execution finished %s.\n\n", filename, success ? "successfully" : "with errors");
    if (success) speaker_event(BEEP_SUCCESS);

    if (need_free) {
        Free(content);
    }

    return success;
}

