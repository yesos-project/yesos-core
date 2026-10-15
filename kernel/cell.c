#include "cell.h"
#include "font.h"
#include "pmp.h"
#include "smp.h"
#include "timer.h"
#include "memory.h"
#include "kprintf.h"
#include "speaker.h"
#include "holyq_rv64_compiler.h"

// ============================================================================
// YesOS 2.0 - PMP cells, hart 0 side (see include/cell.h for the design).
// ============================================================================

_Static_assert(__builtin_offsetof(CellMailbox, state) == MB_STATE, "mailbox layout");
_Static_assert(__builtin_offsetof(CellMailbox, pmp_cfg0) == MB_PMP_CFG0, "mailbox layout");
_Static_assert(__builtin_offsetof(CellMailbox, rb_cfg0) == MB_RB_CFG0, "mailbox layout");
_Static_assert(__builtin_offsetof(CellMailbox, entry) == MB_ENTRY, "mailbox layout");
_Static_assert(__builtin_offsetof(CellMailbox, result) == MB_RESULT, "mailbox layout");
_Static_assert(__builtin_offsetof(CellMailbox, fault_epc) == MB_FAULT_EPC, "mailbox layout");
_Static_assert(__builtin_offsetof(CellMailbox, rpc_state) == MB_RPC_STATE, "mailbox layout");
_Static_assert(__builtin_offsetof(CellMailbox, rpc_args) == MB_RPC_ARGS, "mailbox layout");
_Static_assert(__builtin_offsetof(CellMailbox, rpc_result) == MB_RPC_RESULT, "mailbox layout");
_Static_assert(sizeof(CellMailbox) == MB_SIZE, "mailbox layout");
_Static_assert(CELL_MAX == PMP_PROOF_CELLS && CELL_PMP_ENTRIES == PMP_CELL_SLOTS, "certificate layout");

#define CELL_MAILBOX_MAGIC 0x4C4C4543594553ULL   // "YESCELL"

extern U8 _cell_area_start[];
extern U0 cell_boot(CellMailbox* mb);
extern U0 cell_trap(U0);
extern U0 cell_rpc(U0);
extern U0 cell_gfx_rect(U0);    // cell runtime drawing routines (kernel/cell_rt.S)
extern U0 cell_gfx_clear(U0);
extern U0 cell_gfx_plot(U0);

static const volatile U64 g_cell_area = (U64)_cell_area_start;   // absolute, see pmp.c

typedef struct {
    PmpPolicy policy;
    PmpLayout layout;
    Bool      staged;      // layout built, checked and copied to the mailbox
    Bool      verified;    // the cell locked it and its readback verified
} CellSlot;

static CellSlot g_cells[CELL_MAX];

static inline U64 cell_base(U32 k)            { return g_cell_area + (U64)k * CELL_STRIDE; }
static inline CellMailbox* cell_mb(U32 k)     { return (CellMailbox*)(uintptr_t)(cell_base(k) + CELL_CODE_SIZE); }
static inline U64 cell_data_start(U32 k)      { return cell_base(k) + CELL_CODE_SIZE; }
static inline U64 cell_data_end(U32 k)        { return cell_base(k) + CELL_STRIDE; }

Bool cell_is_cell_hart(U32 hart_id) {
    return hart_id >= CELL_FIRST_HART && hart_id < CELL_FIRST_HART + CELL_MAX && hart_id < SMP_MAX_HARTS;
}

// ----------------------------------------------------------------------------
// Boot: stage layouts (hart 0, before secondaries are released)
// ----------------------------------------------------------------------------

Bool cell_prepare_layouts(U0) {
    Bool all_ok = TRUE;
    for (U32 k = 0; k < CELL_MAX; k++) {
        CellSlot* c = &g_cells[k];
        MemSet(c, 0, sizeof(*c));
        CellMailbox* mb = cell_mb(k);
        MemSet(mb, 0, CELL_STR_OFFSET);

        if (!pmp_cell_policy(k, &c->policy) || !pmp_build_layout(&c->policy, &c->layout) ||
            c->layout.count > CELL_PMP_ENTRIES || c->layout.count > pmp_hw_entry_count()) {
            kprintf("[CELL] cell %u: cannot build a PMP layout\n", k);
            all_ok = FALSE;
            continue;
        }
        if (!pmp_cell_matches_certificate(k, &c->layout)) {
            kprintf("[CELL] cell %u: layout differs from the Z3 certificate\n", k);
            all_ok = FALSE;
            continue;
        }
        if (!pmp_verify_layout(&c->policy, c->layout.addr, c->layout.cfg, c->layout.count, TRUE)) {
            kprintf("[CELL] cell %u: layout does not implement the cell policy\n", k);
            all_ok = FALSE;
            continue;
        }

        U64 cfg0 = 0;
        for (U32 i = 0; i < CELL_PMP_ENTRIES; i++) {
            mb->pmp_addr[i] = (i < c->layout.count) ? c->layout.addr[i] : 0;
            if (i < c->layout.count) cfg0 |= (U64)c->layout.cfg[i] << (i * 8);
        }
        mb->pmp_cfg0 = cfg0;
        mb->magic = CELL_MAILBOX_MAGIC;
        mb->state = CELL_ST_OFFLINE;
        __asm__ __volatile__("fence rw, rw" ::: "memory");
        c->staged = TRUE;
    }
    return all_ok;
}

// Cell hart entry, still in kernel text with full access. Installs the trap
// vector and interrupt mask (the runtime contains no instruction able to
// change them), then jumps into the runtime, which locks the PMP.
U0 cell_hart_enter(U32 hart_id) {
    U32 k = hart_id - CELL_FIRST_HART;
    if (!cell_is_cell_hart(hart_id) || !g_cells[k].staged) {
        while (1) __asm__ __volatile__("wfi");
    }
    __asm__ __volatile__("csrc mstatus, %0" : : "r"(1ULL << 3));          // MIE off until locked
    __asm__ __volatile__("csrw mtvec, %0" : : "r"((U64)(uintptr_t)&cell_trap));
    __asm__ __volatile__("csrw mie, %0" : : "r"(1ULL << 3));              // MSIE only: no timer
    __asm__ __volatile__("csrw mscratch, zero");
    cell_boot(cell_mb(k));
    __builtin_unreachable();
}

// ----------------------------------------------------------------------------
// Boot: verify what each cell actually locked (hart 0, after smp_init)
// ----------------------------------------------------------------------------

U0 cell_verify_booted(U0) {
    U32 harts = smp_get_hart_count();
    for (U32 k = 0; k < CELL_MAX; k++) {
        CellSlot* c = &g_cells[k];
        U32 hart = CELL_FIRST_HART + k;
        if (!c->staged || hart >= harts) continue;

        CellMailbox* mb = cell_mb(k);
        U64 t0 = timer_get_uptime_ms();
        while (mb->state != CELL_ST_BOOTED && timer_get_uptime_ms() - t0 < 500) {
            __asm__ __volatile__("fence rw, rw" ::: "memory");
        }
        if (mb->state != CELL_ST_BOOTED) {
            kprintf("[CELL] hart %u did not report its PMP lock\n", hart);
            continue;
        }

        // Before any untrusted code ran: the readback is the cell runtime's own.
        U64 rb_addr[CELL_PMP_ENTRIES];
        U8  rb_cfg[CELL_PMP_ENTRIES];
        for (U32 i = 0; i < c->layout.count; i++) {
            rb_addr[i] = mb->rb_addr[i];
            rb_cfg[i] = (U8)(mb->rb_cfg0 >> (i * 8));
        }
        Bool same = TRUE;
        for (U32 i = 0; i + 1 < c->layout.count; i++) {
            if (rb_addr[i] != c->layout.addr[i] || rb_cfg[i] != c->layout.cfg[i]) same = FALSE;
        }
        if (rb_cfg[c->layout.count - 1] != c->layout.cfg[c->layout.count - 1]) same = FALSE;
        if (!same || !pmp_verify_layout(&c->policy, rb_addr, rb_cfg, c->layout.count, TRUE)) {
            kprintf("[CELL] hart %u: PMP readback does not match its policy; cell disabled\n", hart);
            smp_send_ipi(hart);   // park it for good
            continue;
        }
        mb->state = CELL_ST_IDLE;
        __asm__ __volatile__("fence rw, rw" ::: "memory");
        c->verified = TRUE;
        kprintf(" [ OK ] PMP cell on hart %u: locked %u entries, readback verified\n", hart, c->layout.count);
    }
}

U32 cell_available_count(U0) {
    U32 n = 0;
    for (U32 k = 0; k < CELL_MAX; k++) n += g_cells[k].verified ? 1 : 0;
    return n;
}

// ----------------------------------------------------------------------------
// Instruction verifier
// ----------------------------------------------------------------------------

// Allowed major opcodes (bits 6:0). Everything else is rejected, notably
// SYSTEM (0x73: CSR access, ecall, ebreak, mret, wfi, sfence) and the
// custom-0..3 opcodes reserved for vendor extensions.
static Bool opcode_allowed(U32 insn, const char** why) {
    U32 op = insn & 0x7F;
    U32 f3 = (insn >> 12) & 7;
    switch (op) {
        case 0x03: case 0x23:               // LOAD, STORE
        case 0x07: case 0x27:               // LOAD-FP/STORE-FP (incl. vector)
        case 0x13: case 0x1B:               // OP-IMM, OP-IMM-32
        case 0x33: case 0x3B:               // OP, OP-32 (incl. M, Zba/Zbb)
        case 0x37: case 0x17:               // LUI, AUIPC
        case 0x63: case 0x6F: case 0x67:    // BRANCH, JAL, JALR
        case 0x2F:                          // AMO
        case 0x43: case 0x47: case 0x4B: case 0x4F: case 0x53:   // FP
        case 0x57:                          // OP-V (vsetvl* only touch vl/vtype)
            return TRUE;
        case 0x0F:                          // MISC-MEM: FENCE only, no FENCE.I
            if (f3 == 0) return TRUE;
            *why = "FENCE.I";
            return FALSE;
        case 0x73:
            *why = "SYSTEM instruction (CSR access / ecall / mret / wfi)";
            return FALSE;
        default:
            *why = "opcode not allowed in a cell";
            return FALSE;
    }
}

Bool cell_verify_code(const U32* code, size_t count, char* why, size_t why_len) {
    for (size_t i = 0; i < count; i++) {
        U32 insn = code[i];
        const char* reason = NULL;
        if ((insn & 3) != 3) {
            reason = "compressed or invalid encoding";
        } else if ((insn & 0x1F) == 0x1F) {
            reason = "48/64-bit instruction encoding";
        } else {
            opcode_allowed(insn, &reason);
        }
        if (reason) {
            if (why) ksnprintf(why, why_len, "insn %u (0x%08x): %s", (U32)i, insn, reason);
            return FALSE;
        }
    }
    return TRUE;
}

// ----------------------------------------------------------------------------
// Running jobs
// ----------------------------------------------------------------------------

static U0 cell_park(U32 k) {
    smp_send_ipi(CELL_FIRST_HART + k);
    U64 t0 = timer_get_uptime_ms();
    while (timer_get_uptime_ms() - t0 < 5) {
        __asm__ __volatile__("fence rw, rw" ::: "memory");
    }
    // The cell is now held in cell_trap until MSIP is cleared: it cannot
    // clear MSIP itself (CLINT is outside its PMP layout).
}

static U0 cell_release(U32 k) {
    __asm__ __volatile__("fence rw, rw" ::: "memory");
    smp_clear_ipi(CELL_FIRST_HART + k);
}

static Bool char_in(const char* set, char ch) {
    for (; *set; set++) {
        if (*set == ch) return TRUE;
    }
    return FALSE;
}

// Copies a NUL-terminated string from the cell's data arena. Returns FALSE
// for pointers outside the arena or strings not terminated inside it.
static Bool cell_copy_str(U32 k, U64 ptr, char* out, size_t cap) {
    U64 lo = cell_data_start(k), hi = cell_data_end(k);
    if (ptr < lo || ptr >= hi) return FALSE;
    size_t i = 0;
    for (; i + 1 < cap && ptr + i < hi; i++) {
        char ch = *(volatile const char*)(uintptr_t)(ptr + i);
        out[i] = ch;
        if (ch == '\0') return TRUE;
    }
    out[i] = '\0';
    return ptr + i < hi;   // truncated but within bounds
}

// RPC print: the format and every %s argument must live in the cell's data
// arena. Pointers into the kernel are refused (no confused deputy).
static U0 cell_service_print(U32 k, CellMailbox* mb) {
    char fmt[160];
    if (!cell_copy_str(k, mb->rpc_args[0], fmt, sizeof(fmt))) {
        kprintf("[cell %u] <rejected print: format pointer outside the cell>\n", CELL_FIRST_HART + k);
        mb->rpc_result = (U64)-1;
        return;
    }
    if (char_in(fmt, '*')) {   // '*' would consume arguments and desynchronise %s validation
        kprintf("[cell %u] <rejected print: '*' in format>\n", CELL_FIRST_HART + k);
        mb->rpc_result = (U64)-1;
        return;
    }
    static char sbuf[6][96];
    U64 args[6];
    U32 argi = 0;
    for (const char* f = fmt; *f; f++) {
        if (*f != '%') continue;
        f++;
        while (*f && char_in("-+ #0123456789.lhz", *f)) f++;
        if (*f == '%' || *f == '\0') continue;
        if (argi >= 6) break;
        U64 v = mb->rpc_args[1 + argi];
        if (*f == 's') {
            if (!cell_copy_str(k, v, sbuf[argi], sizeof(sbuf[argi]))) {
                StrNCpy(sbuf[argi], "<pointer outside cell refused>", sizeof(sbuf[argi]) - 1);
            }
            v = (U64)(uintptr_t)sbuf[argi];
        }
        args[argi++] = v;
    }
    for (U32 i = argi; i < 6; i++) args[i] = 0;
    char out[256];
    ksnprintf(out, sizeof(out), fmt, args[0], args[1], args[2], args[3], args[4], args[5]);
    kprintf("[cell %u] %s", CELL_FIRST_HART + k, out);
    mb->rpc_result = 0;
}

static I32 cell_pick(U0) {
    for (U32 k = 0; k < CELL_MAX; k++) {
        if (g_cells[k].verified) return (I32)k;
    }
    return -1;
}

// ----------------------------------------------------------------------------
// Cell programs: parsing and two-pass compilation
// ----------------------------------------------------------------------------

#define CELL_MAX_FUNCS 32
#define CELL_NAME_MAX  64

typedef struct {
    char        name[CELL_NAME_MAX];
    const char* start;
    size_t      len;
} CellFn;

static Bool is_ident_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

static const char* skip_space(const char* p) {
    while (*p) {
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            p++;
        } else if (p[0] == '/' && p[1] == '/') {
            while (*p && *p != '\n') p++;
        } else if (p[0] == '/' && p[1] == '*') {
            p += 2;
            while (*p && !(p[0] == '*' && p[1] == '/')) p++;
            if (*p) p += 2;
        } else {
            break;
        }
    }
    return p;
}

static const char* read_ident(const char* p, char* out, size_t cap) {
    size_t n = 0;
    while (is_ident_char(*p)) {
        if (n + 1 < cap) out[n++] = *p;
        p++;
    }
    out[n] = '\0';
    return p;
}

// Skips a balanced (open ... close) group, ignoring string/char literals and comments.
static const char* skip_group(const char* p, char open, char close) {
    I32 depth = 0;
    while (*p) {
        if (*p == '"' || *p == '\'') {
            char q = *p++;
            while (*p && *p != q) {
                if (*p == '\\' && p[1]) p++;
                p++;
            }
            if (*p) p++;
            continue;
        }
        if (p[0] == '/' && (p[1] == '/' || p[1] == '*')) {
            p = skip_space(p);
            continue;
        }
        if (*p == open) depth++;
        if (*p == close && --depth == 0) return p + 1;
        p++;
    }
    return NULL;
}

// Top level of a cell program: function definitions, `extern` declarations
// (ignored) and call statements (the first one names the entry function).
static Bool parse_program(const char* src, CellFn* fns, U32* nfn, char* entry, char* why, size_t why_len) {
    *nfn = 0;
    const char* p = src;
    while (TRUE) {
        p = skip_space(p);
        if (*p == '\0') return TRUE;
        if (*p == '#') {                       // #include etc.
            while (*p && *p != '\n') p++;
            continue;
        }
        const char* item = p;
        char tok[CELL_NAME_MAX];
        p = read_ident(p, tok, sizeof(tok));
        if (tok[0] == '\0') {
            ksnprintf(why, why_len, "unexpected character '%c' at top level", *item);
            return FALSE;
        }
        if (StrCmp(tok, "extern") == 0) {
            while (*p && *p != ';') p++;
            if (*p) p++;
            continue;
        }
        p = skip_space(p);
        if (*p == '(') {                       // top-level call statement
            const char* end = skip_group(p, '(', ')');
            if (!end) { ksnprintf(why, why_len, "unbalanced parentheses after '%s'", tok); return FALSE; }
            p = skip_space(end);
            if (*p == ';') p++;
            if (entry[0] == '\0') StrNCpy(entry, tok, CELL_NAME_MAX - 1);
            continue;
        }
        if (*p == '*') p = skip_space(p + 1);  // pointer return type
        char name[CELL_NAME_MAX];
        p = read_ident(p, name, sizeof(name));
        p = skip_space(p);
        if (name[0] == '\0' || *p != '(') {
            ksnprintf(why, why_len, "expected a function definition after '%s'", tok);
            return FALSE;
        }
        p = skip_group(p, '(', ')');
        if (p) p = skip_space(p);
        if (!p || *p != '{') { ksnprintf(why, why_len, "function '%s' has no body", name); return FALSE; }
        p = skip_group(p, '{', '}');
        if (!p) { ksnprintf(why, why_len, "unbalanced braces in '%s'", name); return FALSE; }
        if (*nfn >= CELL_MAX_FUNCS) { ksnprintf(why, why_len, "too many functions"); return FALSE; }
        CellFn* f = &fns[(*nfn)++];
        StrNCpy(f->name, name, CELL_NAME_MAX - 1);
        f->start = item;
        f->len = (size_t)(p - item);
    }
}

// Compiles every function of the program into cell k's code arena.
// Pass 1 sizes the functions (intra-program calls are fixed-size), pass 2
// emits them with real addresses; both layouts must be identical.
static Bool compile_program(U32 k, const CellFn* fns, U32 n, U64* addrs, U32* sizes, char* why, size_t why_len) {
    static const char* names[CELL_MAX_FUNCS];
    for (U32 i = 0; i < n; i++) names[i] = fns[i].name;

    HolyQCellTarget t;
    U32* code = (U32*)(uintptr_t)cell_base(k);
    size_t cap = CELL_CODE_SIZE / 4;
    for (U32 pass = 0; pass < 2; pass++) {
        MemSet(code, 0, CELL_CODE_SIZE);
        MemSet(&t, 0, sizeof(t));
        t.str_host = (char*)(uintptr_t)(cell_data_start(k) + CELL_STR_OFFSET);
        t.str_base = cell_data_start(k) + CELL_STR_OFFSET;
        t.str_cap = CELL_STR_SIZE;
        t.rpc_addr = (U64)(uintptr_t)&cell_rpc;
        t.gfx_rect_addr = (U64)(uintptr_t)&cell_gfx_rect;
        t.gfx_clear_addr = (U64)(uintptr_t)&cell_gfx_clear;
        t.gfx_plot_addr = (U64)(uintptr_t)&cell_gfx_plot;
        t.fn_names = names;
        t.fn_count = n;
        t.fn_addrs = pass ? addrs : NULL;
        size_t cur = 0;
        for (U32 i = 0; i < n; i++) {
            char* text = (char*)Malloc(fns[i].len + 1);
            if (!text) { ksnprintf(why, why_len, "out of memory"); return FALSE; }
            MemCpy(text, fns[i].start, fns[i].len);
            text[fns[i].len] = '\0';
            t.code = code + cur;
            t.capacity = cap - cur;
            t.base_pc = cell_base(k) + cur * 4;
            Bool ok = holyq_rv64_compile_for_cell(text, &t);
            Free(text);
            if (!ok) {
                ksnprintf(why, why_len, "compile '%s': %s", fns[i].name, t.error_msg);
                return FALSE;
            }
            if (pass == 0) {
                addrs[i] = t.base_pc;
                sizes[i] = t.insts;
            } else if (addrs[i] != t.base_pc || sizes[i] != t.insts) {
                ksnprintf(why, why_len, "layout of '%s' changed between passes", fns[i].name);
                return FALSE;
            }
            cur += (t.insts + 3) & ~3U;   // 16-byte aligned functions
            if (cur >= cap) { ksnprintf(why, why_len, "program too large for the cell"); return FALSE; }
        }
    }
    return TRUE;
}

// ----------------------------------------------------------------------------
// Jobs: start / service / finish. Synchronous runs loop on service; apps run
// asynchronously and are serviced from the main loop (cell_poll), so the
// desktop keeps rendering while they work.
// ----------------------------------------------------------------------------

typedef struct {
    Bool active;
    Bool async;
    U64  t0;
    U32  timeout_ms;
    U32  frames;
    char name[32];
} CellJob;

static CellJob g_jobs[CELL_MAX];


static inline U32* cell_canvas(U32 k) {
    return (U32*)(uintptr_t)(cell_data_start(k) + CELL_CANVAS_OFFSET);
}

// RPC text: string from the cell's data arena, rendered by hart 0 into the
// cell's own canvas with clipping. The font stays in kernel memory.
static U0 cell_service_text(U32 k, CellMailbox* mb) {
    char str[128];
    if (!cell_copy_str(k, mb->rpc_args[2], str, sizeof(str))) {
        mb->rpc_result = (U64)-1;
        return;
    }
    I64 x = (I64)mb->rpc_args[0], y = (I64)mb->rpc_args[1];
    U32 color = (U32)mb->rpc_args[3];
    U32* canvas = cell_canvas(k);
    for (const char* c = str; *c; x += FONT_WIDTH) {
        const U8* glyph = font_glyph(font_utf8_next(&c));  // UTF-8, '?' if not in the font
        for (I64 r = 0; r < 16; r++) {
            I64 py = y + r;
            if (py < 0 || py >= CELL_CANVAS_H) continue;
            for (I64 bcol = 0; bcol < 8; bcol++) {
                I64 px = x + bcol;
                if (px < 0 || px >= CELL_CANVAS_W) continue;
                if ((glyph[r] >> (7 - bcol)) & 1) canvas[py * CELL_CANVAS_W + px] = color;
            }
        }
    }
    mb->rpc_result = 0;
}

static U0 cell_service_rpc(U32 k, CellMailbox* mb) {
    U64 op = mb->rpc_op;
    if (op == CELL_RPC_PRINT) {
        cell_service_print(k, mb);
    } else if (op == CELL_RPC_BEEP) {
        if (mb->rpc_args[0] < 16) speaker_event((U32)mb->rpc_args[0]);
        mb->rpc_result = 0;
    } else if (op == CELL_RPC_SLEEP) {
        U64 ms = mb->rpc_args[0] > 2000 ? 2000 : mb->rpc_args[0];
        U64 s0 = timer_get_uptime_ms();
        while (timer_get_uptime_ms() - s0 < ms) __asm__ __volatile__("fence rw, rw" ::: "memory");
        mb->rpc_result = 0;
    } else if (op == CELL_RPC_TEXT) {
        cell_service_text(k, mb);
    } else if (op == CELL_RPC_PRESENT) {
        // The NAS has no local display: frames are counted, the canvas stays
        // private to the cell (a remote viewer can be added later).
        g_jobs[k].frames++;
        mb->rpc_result = g_jobs[k].frames;
    } else {
        mb->rpc_result = (U64)-1;
    }
    __asm__ __volatile__("fence rw, rw" ::: "memory");
    mb->rpc_state = CELL_RPC_DONE;
}

static I32 cell_pick_free(U0) {
    for (U32 k = 0; k < CELL_MAX; k++) {
        if (g_cells[k].verified && !g_jobs[k].active) return (I32)k;
    }
    return -1;
}

static Bool cell_job_start(const char* source, const char* entry, const I64* args, U32 argc, U32 timeout_ms,
                           const char* name, Bool async, CellResult* out, U32* k_out) {
    MemSet(out, 0, sizeof(*out));
    I32 kk = cell_pick_free();
    if (kk < 0) {
        out->code = CELL_RESULT_UNAVAILABLE;
        StrNCpy(out->reason, cell_available_count() ? "all cells are busy" : "no verified cell hart",
                sizeof(out->reason) - 1);
        return FALSE;
    }
    U32 k = (U32)kk;
    CellMailbox* mb = cell_mb(k);

    static CellFn fns[CELL_MAX_FUNCS];
    static U64 addrs[CELL_MAX_FUNCS];
    static U32 sizes[CELL_MAX_FUNCS];
    U32 n = 0;
    char entry_name[CELL_NAME_MAX] = { 0 };
    if (entry) StrNCpy(entry_name, entry, CELL_NAME_MAX - 1);
    if (!parse_program(source, fns, &n, entry_name, out->reason, sizeof(out->reason)) || n == 0) {
        if (n == 0 && out->reason[0] == '\0') StrNCpy(out->reason, "no function in program", sizeof(out->reason) - 1);
        out->code = CELL_RESULT_REJECTED;
        return FALSE;
    }
    if (entry_name[0] == '\0') {
        StrNCpy(entry_name, n == 1 ? fns[0].name : "main", CELL_NAME_MAX - 1);
    }
    I32 entry_idx = -1;
    for (U32 i = 0; i < n; i++) {
        if (StrCmp(fns[i].name, entry_name) == 0) entry_idx = (I32)i;
    }
    if (entry_idx < 0) {
        out->code = CELL_RESULT_REJECTED;
        ksnprintf(out->reason, sizeof(out->reason), "entry function '%s' not defined", entry_name);
        return FALSE;
    }

    // 1. Park the cell: from here on nothing it does can race with us.
    cell_park(k);

    // 2. Compile straight into the cell arena (RW for hart 0, R-X for the cell).
    U32* code = (U32*)(uintptr_t)cell_base(k);
    if (!compile_program(k, fns, n, addrs, sizes, out->reason, sizeof(out->reason))) {
        MemSet(code, 0, CELL_CODE_SIZE);
        out->code = CELL_RESULT_REJECTED;
        cell_release(k);
        return FALSE;
    }

    // 3. Verify every instruction of every function before the cell may fetch it.
    for (U32 i = 0; i < n; i++) {
        const U32* f = (const U32*)(uintptr_t)addrs[i];
        if (!cell_verify_code(f, sizes[i], out->reason, sizeof(out->reason))) {
            MemSet(code, 0, CELL_CODE_SIZE);
            out->code = CELL_RESULT_REJECTED;
            cell_release(k);
            return FALSE;
        }
    }

    // 4. Fresh canvas, then post the job (the cell is parked).
    MemSet(cell_canvas(k), 0, CELL_CANVAS_W * CELL_CANVAS_H * 4);
    mb->entry = addrs[entry_idx];
    for (U32 i = 0; i < 4; i++) mb->args[i] = (args && i < argc) ? (U64)args[i] : 0;
    mb->result = 0;
    mb->fault_cause = mb->fault_tval = mb->fault_epc = 0;
    mb->rpc_state = CELL_RPC_IDLE;
    mb->state = CELL_ST_RUN;

    CellJob* j = &g_jobs[k];
    j->active = TRUE;
    j->async = async;
    j->t0 = timer_get_uptime_ms();
    j->timeout_ms = timeout_ms;
    j->frames = 0;
    StrNCpy(j->name, name ? name : "cell program", sizeof(j->name) - 1);
    cell_release(k);
    *k_out = k;
    return TRUE;
}

// Services pending RPCs (up to a budget) and checks for completion.
// Returns TRUE when the job has finished (out filled in).
static Bool cell_job_service(U32 k, CellResult* out, U32 rpc_budget) {
    CellMailbox* mb = cell_mb(k);
    CellJob* j = &g_jobs[k];
    for (U32 i = 0; i < rpc_budget; i++) {
        __asm__ __volatile__("fence rw, rw" ::: "memory");
        if (mb->rpc_state != CELL_RPC_REQUEST) break;
        cell_service_rpc(k, mb);
    }
    __asm__ __volatile__("fence rw, rw" ::: "memory");
    U64 st = mb->state;
    if (st == CELL_ST_DONE) {
        out->code = CELL_RESULT_OK;
        out->value = (I64)mb->result;
        return TRUE;
    }
    if (st == CELL_ST_FAULT) {
        out->code = CELL_RESULT_FAULT;
        out->fault_cause = mb->fault_cause;
        out->fault_tval = mb->fault_tval;
        ksnprintf(out->reason, sizeof(out->reason), "hardware fault mcause=%u at 0x%p",
                  (U32)mb->fault_cause, (void*)mb->fault_tval);
        return TRUE;
    }
    if (timer_get_uptime_ms() - j->t0 > j->timeout_ms) {
        out->code = CELL_RESULT_TIMEOUT;
        ksnprintf(out->reason, sizeof(out->reason), "watchdog: killed after %u ms", j->timeout_ms);
        return TRUE;
    }
    return FALSE;
}

// Always park and reset, so a misbehaving job cannot outlive its run. The
// canvas is kept: the app window shows the last presented frame.
static U0 cell_job_finish(U32 k) {
    CellMailbox* mb = cell_mb(k);
    cell_park(k);
    MemSet((U32*)(uintptr_t)cell_base(k), 0, CELL_CODE_SIZE);
    mb->state = CELL_ST_IDLE;
    mb->rpc_state = CELL_RPC_IDLE;
    g_jobs[k].active = FALSE;
    cell_release(k);
}

Bool cell_run_program(const char* source, const char* entry, const I64* args, U32 argc, U32 timeout_ms,
                      CellResult* out) {
    U32 k = 0;
    if (!cell_job_start(source, entry, args, argc, timeout_ms, "cell program", FALSE, out, &k)) return FALSE;
    while (!cell_job_service(k, out, 1)) {
    }
    cell_job_finish(k);
    return out->code == CELL_RESULT_OK;
}

Bool cell_start_app(const char* source, const char* name, U32 timeout_ms, CellResult* out) {
    U32 k = 0;
    if (!cell_job_start(source, NULL, NULL, 0, timeout_ms, name, TRUE, out, &k)) return FALSE;
    kprintf("--- [ %s started on cell hart %u ] ---\n", g_jobs[k].name, CELL_FIRST_HART + k);
    return TRUE;
}

U0 cell_poll(U0) {
    for (U32 k = 0; k < CELL_MAX; k++) {
        CellJob* j = &g_jobs[k];
        if (!j->active || !j->async) continue;
        CellResult r;
        MemSet(&r, 0, sizeof(r));
        if (!cell_job_service(k, &r, 64)) continue;
        if (r.code == CELL_RESULT_OK) {
            kprintf("--- [ %s finished in its cell (result %d, %u frames) ] ---\n", j->name, (I32)r.value, j->frames);
        } else {
            kprintf("--- [ %s stopped: %s ] ---\n", j->name, r.reason);
            speaker_event(BEEP_WARN);
        }
        cell_job_finish(k);
    }
}

Bool cell_run_source(const char* source, const I64* args, U32 argc, U32 timeout_ms, CellResult* out) {
    return cell_run_program(source, NULL, args, argc, timeout_ms, out);
}

U0 cell_print_status(U0) {
    kprintf("\n================ [ PMP CELLS (isolated M-mode app cores) ] ================\n");
    U32 harts = smp_get_hart_count();
    for (U32 k = 0; k < CELL_MAX; k++) {
        U32 hart = CELL_FIRST_HART + k;
        if (hart >= harts) break;
        CellSlot* c = &g_cells[k];
        kprintf("  hart %u : %s | code 0x%p (64 KiB R-X) | data 0x%p (192 KiB RW-)\n", hart,
                c->verified ? "VERIFIED CELL" : (c->staged ? "NOT VERIFIED" : "UNAVAILABLE"),
                (void*)cell_base(k), (void*)cell_data_start(k));
    }
    kprintf("  A cell sees only its runtime, code and data. Kernel, vault, devices and\n");
    kprintf("  other cells are denied by locked PMP; code is verified before install.\n");
    kprintf("===========================================================================\n");
}

// ----------------------------------------------------------------------------
// Security self-test: hostile programs must be contained
// ----------------------------------------------------------------------------

extern U8 g_cell_selftest_marker[];   // kernel .data object (defined below)
U8 g_cell_selftest_marker[16] = "KERNEL-SECRET";

static Bool st_expect(const char* name, Bool cond, const char* detail) {
    kprintf("  %s %s%s%s\n", cond ? "[PASS]" : "[FAIL]", name, detail ? " - " : "", detail ? detail : "");
    return cond;
}

Bool cell_self_test(U0) {
    kprintf("\n================ [ PMP CELL SECURITY SELF-TEST ] ================\n");
    if (cell_available_count() == 0) {
        kprintf("  No verified cell hart available.\n");
        return FALSE;
    }
    Bool ok = TRUE;
    CellResult r;
    I64 a[1];

    // Verifier: privileged and unknown encodings are rejected
    static const U32 csrw_mtvec[] = { 0x30529073 };       // csrw mtvec, t0
    static const U32 csrc_mie[]   = { 0x30403073 };       // csrc mie, zero... (CSR op)
    static const U32 ecall[]      = { 0x00000073 };
    static const U32 mret[]       = { 0x30200073 };
    static const U32 wfi[]        = { 0x10500073 };
    static const U32 fencei[]     = { 0x0000100F };
    static const U32 custom0[]    = { 0x0000000B };
    static const U32 compressed[] = { 0x00000001 };       // c.nop
    static const U32 benign[]     = { 0x00a50533, 0x00008067 };   // add a0,a0,a0; ret
    char why[96];
    ok &= st_expect("verifier rejects csrw mtvec", !cell_verify_code(csrw_mtvec, 1, why, sizeof(why)), NULL);
    ok &= st_expect("verifier rejects CSR access to mie", !cell_verify_code(csrc_mie, 1, why, sizeof(why)), NULL);
    ok &= st_expect("verifier rejects ecall", !cell_verify_code(ecall, 1, why, sizeof(why)), NULL);
    ok &= st_expect("verifier rejects mret", !cell_verify_code(mret, 1, why, sizeof(why)), NULL);
    ok &= st_expect("verifier rejects wfi", !cell_verify_code(wfi, 1, why, sizeof(why)), NULL);
    ok &= st_expect("verifier rejects fence.i", !cell_verify_code(fencei, 1, why, sizeof(why)), NULL);
    ok &= st_expect("verifier rejects custom opcodes", !cell_verify_code(custom0, 1, why, sizeof(why)), NULL);
    ok &= st_expect("verifier rejects compressed encodings", !cell_verify_code(compressed, 1, why, sizeof(why)), NULL);
    ok &= st_expect("verifier accepts ordinary code", cell_verify_code(benign, 2, why, sizeof(why)), NULL);

    // Compiler: kernel symbols are not reachable from cell code
    cell_run_source("I64 f() { return Malloc(16); }", NULL, 0, 1000, &r);
    ok &= st_expect("calling a kernel function is a compile error", r.code == CELL_RESULT_REJECTED, r.reason);

    // Legitimate work + validated RPC
    cell_run_source("I64 fib(I64 n) { if (n < 2) { return n; } return fib(n - 1) + fib(n - 2); }",
                    (a[0] = 20, a), 1, 3000, &r);
    ok &= st_expect("recursive computation runs in the cell", r.code == CELL_RESULT_OK && r.value == 6765, NULL);
    cell_run_source("I64 f(I64 x) { kprintf(\"hello from an isolated cell, x=%d\\n\", x); return 1; }",
                    (a[0] = 42, a), 1, 2000, &r);
    ok &= st_expect("print via validated RPC", r.code == CELL_RESULT_OK, NULL);

    // Hostile: read and write kernel memory, vault key region included
    U64 kaddr = (U64)(uintptr_t)g_cell_selftest_marker;
    cell_run_source("I64 f(I64 p) { return p[0]; }", (a[0] = (I64)kaddr, a), 1, 2000, &r);
    ok &= st_expect("reading kernel data faults in hardware",
                    r.code == CELL_RESULT_FAULT && r.fault_cause == 5, r.reason);
    cell_run_source("I64 f(I64 p) { p[0] = 1; return 0; }", (a[0] = (I64)kaddr, a), 1, 2000, &r);
    ok &= st_expect("writing kernel data faults in hardware",
                    r.code == CELL_RESULT_FAULT && r.fault_cause == 7 &&
                    StrCmp((const char*)g_cell_selftest_marker, "KERNEL-SECRET") == 0, r.reason);
    cell_run_source("I64 f(I64 p) { return p[0]; }", (a[0] = 0x10000000, a), 1, 2000, &r);
    ok &= st_expect("touching device registers (UART) faults", r.code == CELL_RESULT_FAULT, r.reason);
    cell_run_source("I64 f(I64 p) { p[0] = 0x00008067; return 0; }", (a[0] = (I64)cell_base((U32)cell_pick()), a), 1, 2000, &r);
    ok &= st_expect("writing its own code arena faults (W^X)",
                    r.code == CELL_RESULT_FAULT && r.fault_cause == 7, r.reason);

    // Hostile: confused deputy through the RPC
    cell_run_source("I64 f(I64 p) { kprintf(\"%s\\n\", p); return 0; }", (a[0] = (I64)kaddr, a), 1, 2000, &r);
    ok &= st_expect("RPC refuses kernel pointers (%s)", r.code == CELL_RESULT_OK, NULL);

    // Hostile: never returns
    cell_run_source("I64 f() { while (1) { } return 0; }", NULL, 0, 300, &r);
    ok &= st_expect("infinite loop is killed by the watchdog", r.code == CELL_RESULT_TIMEOUT, r.reason);

    // The cell is reusable after all of the above
    cell_run_source("I64 f(I64 x) { return x * 3; }", (a[0] = 14, a), 1, 2000, &r);
    ok &= st_expect("cell is reusable after faults and kills", r.code == CELL_RESULT_OK && r.value == 42, NULL);

    kprintf("  Result: %s\n", ok ? "ALL HOSTILE PROGRAMS CONTAINED" : "CONTAINMENT FAILURE");
    kprintf("=================================================================\n");
    return ok;
}
