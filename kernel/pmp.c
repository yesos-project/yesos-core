#include "pmp.h"
#include "trap.h"
#include "memory.h"
#include "kprintf.h"
#include "cell.h"

// Linker-provided policy boundaries (see linker_*.ld)
extern U8 _kernel_start[], _text_end[], _rodata_end[], _jit_start[], _jit_end[], _ram_end[];
extern U8 _pmp_null_end[], _pmp_mmio_start[], _pmp_mmio_end[];
extern U8 _cell_text_start[], _cell_text_end[], _cell_area_start[];
extern U8 _keyvault_start[], _keyvault_end[];

// Linker symbols are read through 64-bit absolute constants: some targets
// place windows (e.g. MMIO above 3 GiB on the K1) out of PC-relative reach.
enum { SYM_KSTART, SYM_TEXT_END, SYM_RODATA_END, SYM_JIT_START, SYM_JIT_END, SYM_RAM_END,
       SYM_NULL_END, SYM_MMIO_START, SYM_MMIO_END, SYM_CELL_TEXT_START, SYM_CELL_TEXT_END,
       SYM_CELL_AREA_START, SYM_KV_START, SYM_KV_END, SYM_COUNT };
static const volatile U64 g_pmp_sym[SYM_COUNT] = {  // volatile: keep the indirection
    (U64)_kernel_start, (U64)_text_end, (U64)_rodata_end, (U64)_jit_start, (U64)_jit_end,
    (U64)_ram_end, (U64)_pmp_null_end, (U64)_pmp_mmio_start, (U64)_pmp_mmio_end,
    (U64)_cell_text_start, (U64)_cell_text_end, (U64)_cell_area_start,
    (U64)_keyvault_start, (U64)_keyvault_end,
};

// Build-time certificate (zero until tools/pmp_prover.py patches it).
__attribute__((section(".pmp_proof"), used, aligned(8)))
const volatile PmpProof g_pmp_proof = { 0 };

#define PMP_PA_BITS_MAX 56

static PmpPolicy       g_kpolicy;
static PmpLayout       g_layout;
static U32             g_hw_entries = 0;
static U32             g_pa_bits = PMP_PA_BITS_MAX;
static PmpState        g_state = PMP_STATE_UNCONFIGURED;
static volatile U32    g_locked_harts = 0;

// ----------------------------------------------------------------------------
// CSR access by runtime index (CSR numbers are immediates)
// ----------------------------------------------------------------------------

#define PMPADDR_CASE(n) \
    case n: if (write) __asm__ __volatile__("csrw pmpaddr" #n ", %0" : : "r"(val)); \
            else __asm__ __volatile__("csrr %0, pmpaddr" #n : "=r"(val)); break;

static U64 pmpaddr_access(U32 idx, Bool write, U64 val) {
    switch (idx) {
        PMPADDR_CASE(0)  PMPADDR_CASE(1)  PMPADDR_CASE(2)  PMPADDR_CASE(3)
        PMPADDR_CASE(4)  PMPADDR_CASE(5)  PMPADDR_CASE(6)  PMPADDR_CASE(7)
        PMPADDR_CASE(8)  PMPADDR_CASE(9)  PMPADDR_CASE(10) PMPADDR_CASE(11)
        PMPADDR_CASE(12) PMPADDR_CASE(13) PMPADDR_CASE(14) PMPADDR_CASE(15)
        default: break;
    }
    return val;
}

static U64 pmpcfg_read(U32 reg) {
    U64 v = 0;
    if (reg == 0) __asm__ __volatile__("csrr %0, pmpcfg0" : "=r"(v));
    else          __asm__ __volatile__("csrr %0, pmpcfg2" : "=r"(v));
    return v;
}

static U0 pmpcfg_write(U32 reg, U64 v) {
    if (reg == 0) __asm__ __volatile__("csrw pmpcfg0, %0" : : "r"(v));
    else          __asm__ __volatile__("csrw pmpcfg2, %0" : : "r"(v));
}

static U8 cfg_read(U32 idx) {
    return (U8)(pmpcfg_read(idx < 8 ? 0 : 2) >> ((idx % 8) * 8));
}

static U0 pmp_halt(const char* why) {
    kprintf("\n[PMP] FATAL: %s\n", why);
    kprintf("[PMP] Refusing to run with an unverified memory protection layout. Hart halted.\n");
    __asm__ __volatile__("csrc mstatus, %0" : : "r"(1ULL << 3));
    while (1) {
        __asm__ __volatile__("wfi");
    }
}

// ----------------------------------------------------------------------------
// Policy and layout
// ----------------------------------------------------------------------------

static U0 policy_add(PmpPolicy* p, U64 start, U64 end, U8 perm, const char* name) {
    if (p->count < PMP_POLICY_MAX && end > start) {
        p->r[p->count++] = (PmpPolicyRegion){ start, end, perm, name };
    }
}

// Sorts and validates a policy: 4 KiB alignment, no overlap, no reserved
// W-without-R encoding, and W+X only in the kernel JIT arena.
static Bool policy_finalize(PmpPolicy* p) {
    for (U32 i = 1; i < p->count; i++) {
        PmpPolicyRegion r = p->r[i];
        I32 j = (I32)i - 1;
        while (j >= 0 && p->r[j].start > r.start) {
            p->r[j + 1] = p->r[j];
            j--;
        }
        p->r[j + 1] = r;
    }
    for (U32 i = 0; i < p->count; i++) {
        const PmpPolicyRegion* r = &p->r[i];
        if ((r->start | r->end) & 0xFFF) {
            kprintf("[PMP] policy region %s is not 4 KiB aligned\n", r->name);
            return FALSE;
        }
        if (i > 0 && r->start < p->r[i - 1].end) {
            kprintf("[PMP] policy regions %s and %s overlap\n", p->r[i - 1].name, r->name);
            return FALSE;
        }
        if ((r->perm & PMP_W) && !(r->perm & PMP_R)) return FALSE;
        if ((r->perm & PMP_W) && (r->perm & PMP_X) && StrCmp(r->name, "jit-arena") != 0) return FALSE;
    }
    return TRUE;
}

static Bool build_kernel_policy(PmpPolicy* p) {
    p->count = 0;
    policy_add(p, 0, g_pmp_sym[SYM_NULL_END], 0, "null-guard");
    policy_add(p, g_pmp_sym[SYM_MMIO_START], g_pmp_sym[SYM_MMIO_END], PMP_R | PMP_W, "mmio");
    policy_add(p, g_pmp_sym[SYM_KSTART], g_pmp_sym[SYM_TEXT_END], PMP_R | PMP_X, "kernel-text");
    policy_add(p, g_pmp_sym[SYM_TEXT_END], g_pmp_sym[SYM_RODATA_END], PMP_R, "rodata");
    policy_add(p, g_pmp_sym[SYM_RODATA_END], g_pmp_sym[SYM_JIT_START], PMP_R | PMP_W, "data-bss-stacks");
    policy_add(p, g_pmp_sym[SYM_JIT_START], g_pmp_sym[SYM_JIT_END], PMP_R | PMP_W | PMP_X, "jit-arena");
    policy_add(p, g_pmp_sym[SYM_KV_START], g_pmp_sym[SYM_KV_END], 0, "key-vault");   // key hart only
    policy_add(p, g_pmp_sym[SYM_KV_END], g_pmp_sym[SYM_RAM_END], PMP_R | PMP_W, "heap");
    return policy_finalize(p);
}

// Key hart: kernel code and data, its private key vault, the heap (request
// buffers). No devices, no JIT arena: it never touches hardware or runs
// generated code.
Bool pmp_keyhart_policy(PmpPolicy* p) {
    p->count = 0;
    policy_add(p, 0, g_pmp_sym[SYM_NULL_END], 0, "null-guard");
    policy_add(p, g_pmp_sym[SYM_KSTART], g_pmp_sym[SYM_TEXT_END], PMP_R | PMP_X, "kernel-text");
    policy_add(p, g_pmp_sym[SYM_TEXT_END], g_pmp_sym[SYM_RODATA_END], PMP_R, "rodata");
    policy_add(p, g_pmp_sym[SYM_RODATA_END], g_pmp_sym[SYM_JIT_START], PMP_R | PMP_W, "data-bss-stacks");
    policy_add(p, g_pmp_sym[SYM_KV_START], g_pmp_sym[SYM_KV_END], PMP_R | PMP_W, "key-vault");
    policy_add(p, g_pmp_sym[SYM_KV_END], g_pmp_sym[SYM_RAM_END], PMP_R | PMP_W, "heap");
    return policy_finalize(p);
}

U64 pmp_symbol_keyvault_start(U0) { return g_pmp_sym[SYM_KV_START]; }
U64 pmp_symbol_keyvault_end(U0)   { return g_pmp_sym[SYM_KV_END]; }

Bool pmp_cell_policy(U32 cell, PmpPolicy* p) {
    if (cell >= CELL_MAX) return FALSE;
    U64 base = g_pmp_sym[SYM_CELL_AREA_START] + (U64)cell * CELL_STRIDE;
    p->count = 0;
    policy_add(p, g_pmp_sym[SYM_CELL_TEXT_START], g_pmp_sym[SYM_CELL_TEXT_END], PMP_R | PMP_X, "cell-runtime");
    policy_add(p, base, base + CELL_CODE_SIZE, PMP_R | PMP_X, "cell-code");
    policy_add(p, base + CELL_CODE_SIZE, base + CELL_STRIDE, PMP_R | PMP_W, "cell-data");
    return policy_finalize(p);
}

// TOR chain over the sorted policy, explicit locked NONE entries for gaps,
// and a final locked NAPOT entry denying the whole address space.
Bool pmp_build_layout(const PmpPolicy* p, PmpLayout* l) {
    MemSet(l, 0, sizeof(*l));
    U64 cur = 0;
    for (U32 i = 0; i < p->count; i++) {
        const PmpPolicyRegion* r = &p->r[i];
        if (r->start > cur) {
            if (l->count >= PMP_MAX_ENTRIES) return FALSE;
            l->addr[l->count] = r->start >> 2;
            l->cfg[l->count] = PMP_L | PMP_A_TOR;
            l->count++;
        }
        if (l->count >= PMP_MAX_ENTRIES) return FALSE;
        l->addr[l->count] = r->end >> 2;
        l->cfg[l->count] = PMP_L | PMP_A_TOR | r->perm;
        l->count++;
        cur = r->end;
    }
    if (l->count >= PMP_MAX_ENTRIES) return FALSE;
    l->addr[l->count] = (1ULL << (PMP_PA_BITS_MAX - 2)) - 1;   // NAPOT: entire space
    l->cfg[l->count] = PMP_L | PMP_A_NAPOT;
    l->count++;
    return TRUE;
}

// ----------------------------------------------------------------------------
// Arithmetic verification: exact sweep over all elementary intervals
// ----------------------------------------------------------------------------

typedef struct {
    Bool active;
    U64  lo, hi;   // [lo, hi)
} PmpRange;

static PmpRange decode_entry(const U64* addr, const U8* cfg, U32 i, U64 limit) {
    PmpRange r = { FALSE, 0, 0 };
    U8 a = cfg[i] & PMP_A_MASK;
    if (a == PMP_A_TOR) {
        r.lo = (i == 0) ? 0 : (addr[i - 1] << 2);
        r.hi = addr[i] << 2;
    } else if (a == PMP_A_NA4) {
        r.lo = addr[i] << 2;
        r.hi = r.lo + 4;
    } else if (a == PMP_A_NAPOT) {
        U64 y = addr[i];
        U64 t = y ^ (y + 1);                 // trailing ones plus first zero
        r.lo = (y & ~t) << 2;
        r.hi = (t >= (limit >> 3)) ? limit : r.lo + ((t + 1) << 2);
    } else {
        return r;
    }
    if (r.hi > limit) r.hi = limit;
    r.active = r.lo < r.hi;
    return r;
}

static U8 policy_perm_at(const PmpPolicy* p, U64 a) {
    for (U32 i = 0; i < p->count; i++) {
        if (a >= p->r[i].start && a < p->r[i].end) return p->r[i].perm;
    }
    return 0;
}

static U0 add_point(U64* pts, U32* n, U32 cap, U64 v, U64 limit) {
    if (v > limit || *n >= cap) return;
    for (U32 i = 0; i < *n; i++) {
        if (pts[i] == v) return;
    }
    pts[(*n)++] = v;
}

// Returns TRUE iff, for every address below 2^pa_bits, the effective M-mode
// permissions of (addr, cfg) equal the policy and come from a locked entry.
static Bool verify_semantics(const PmpPolicy* p, const U64* addr, const U8* cfg, U32 count, U32 pa_bits,
                             Bool verbose) {
    U64 limit = 1ULL << pa_bits;
    PmpRange ranges[PMP_MAX_ENTRIES];
    U64 pts[2 * PMP_MAX_ENTRIES + 2 * PMP_POLICY_MAX + 2];
    if (count > PMP_MAX_ENTRIES) return FALSE;
    U32 n = 0;
    U32 cap = sizeof(pts) / sizeof(pts[0]);

    add_point(pts, &n, cap, 0, limit);
    add_point(pts, &n, cap, limit, limit);
    for (U32 i = 0; i < count; i++) {
        ranges[i] = decode_entry(addr, cfg, i, limit);
        if (ranges[i].active) {
            add_point(pts, &n, cap, ranges[i].lo, limit);
            add_point(pts, &n, cap, ranges[i].hi, limit);
        }
    }
    for (U32 i = 0; i < p->count; i++) {
        add_point(pts, &n, cap, p->r[i].start < limit ? p->r[i].start : limit, limit);
        add_point(pts, &n, cap, p->r[i].end < limit ? p->r[i].end : limit, limit);
    }
    for (U32 i = 1; i < n; i++) {          // sort breakpoints
        U64 v = pts[i];
        I32 j = (I32)i - 1;
        while (j >= 0 && pts[j] > v) {
            pts[j + 1] = pts[j];
            j--;
        }
        pts[j + 1] = v;
    }

    // Permissions are constant inside each [pts[k], pts[k+1]) because no
    // entry or policy boundary lies strictly inside it: checking its first
    // address checks the whole interval.
    for (U32 k = 0; k + 1 < n; k++) {
        U64 a = pts[k];
        I32 match = -1;
        for (U32 i = 0; i < count; i++) {
            if (ranges[i].active && a >= ranges[i].lo && a < ranges[i].hi) {
                match = (I32)i;
                break;
            }
        }
        if (match < 0 || !(cfg[match] & PMP_L)) {
            if (verbose) {
                kprintf("[PMP] [0x%p, 0x%p) not governed by a locked entry (M-mode would be unrestricted)\n",
                        (void*)a, (void*)pts[k + 1]);
            }
            return FALSE;
        }
        U8 hw = cfg[match] & (PMP_R | PMP_W | PMP_X);
        U8 want = policy_perm_at(p, a);
        if (hw != want) {
            if (verbose) {
                kprintf("[PMP] [0x%p, 0x%p): hardware %c%c%c != policy %c%c%c\n",
                        (void*)a, (void*)pts[k + 1],
                        (hw & PMP_R) ? 'R' : '-', (hw & PMP_W) ? 'W' : '-', (hw & PMP_X) ? 'X' : '-',
                        (want & PMP_R) ? 'R' : '-', (want & PMP_W) ? 'W' : '-', (want & PMP_X) ? 'X' : '-');
            }
            return FALSE;
        }
    }
    return TRUE;
}

// ----------------------------------------------------------------------------
// Programming and readback
// ----------------------------------------------------------------------------

static U32 probe_entry_count(U0) {
    U32 n = 0;
    for (U32 i = 0; i < PMP_MAX_ENTRIES; i++) {
        trap_probe_begin();
        U64 before = pmpaddr_access(i, FALSE, 0);
        pmpaddr_access(i, TRUE, ~0ULL);
        U64 v = pmpaddr_access(i, FALSE, 0);
        pmpaddr_access(i, TRUE, before);
        if (trap_probe_end() || v == 0) break;
        if (i == 0) {
            // Implemented physical address bits: pmpaddr holds PA[pa_bits-1:2]
            U32 bits = 0;
            while (bits < 64 && (v >> bits) & 1) bits++;
            g_pa_bits = bits + 2;
            if (g_pa_bits > PMP_PA_BITS_MAX) g_pa_bits = PMP_PA_BITS_MAX;
        }
        n++;
    }
    return n;
}

// Programs `l` on the calling hart and verifies the readback against `p`
// without printing (usable on harts that cannot reach the UART once locked).
Bool pmp_lock_layout_silent(const PmpPolicy* p, const PmpLayout* l) {
    for (U32 i = 0; i < l->count; i++) {
        pmpaddr_access(i, TRUE, l->addr[i]);
    }
    U64 cfg0 = 0, cfg2 = 0;
    for (U32 i = 0; i < l->count; i++) {
        if (i < 8) cfg0 |= (U64)l->cfg[i] << (i * 8);
        else       cfg2 |= (U64)l->cfg[i] << ((i - 8) * 8);
    }
    // Higher-priority entries (pmpcfg0) first: the locked catch-all may sit
    // in pmpcfg2, and enabling it alone would deny M-mode its own code.
    pmpcfg_write(0, cfg0);
    if (l->count > 8) pmpcfg_write(2, cfg2);
    __asm__ __volatile__("fence rw, rw" ::: "memory");

    U64 rb_addr[PMP_MAX_ENTRIES];
    U8  rb_cfg[PMP_MAX_ENTRIES];
    for (U32 i = 0; i < l->count; i++) {
        rb_addr[i] = pmpaddr_access(i, FALSE, 0);
        rb_cfg[i] = cfg_read(i);
        if (rb_cfg[i] != l->cfg[i] || (i + 1 < l->count && rb_addr[i] != l->addr[i])) return FALSE;
    }
    return verify_semantics(p, rb_addr, rb_cfg, l->count, g_pa_bits, FALSE);
}

static U0 program_and_verify(U32 hart_id) {
    const PmpLayout* l = &g_layout;

    // Addresses first, then configuration bytes: setting L freezes an entry.
    for (U32 i = 0; i < l->count; i++) {
        pmpaddr_access(i, TRUE, l->addr[i]);
    }
    U64 cfg0 = 0, cfg2 = 0;
    for (U32 i = 0; i < l->count; i++) {
        if (i < 8) cfg0 |= (U64)l->cfg[i] << (i * 8);
        else       cfg2 |= (U64)l->cfg[i] << ((i - 8) * 8);
    }
    // Higher-priority entries (pmpcfg0) first: the locked catch-all may sit
    // in pmpcfg2, and enabling it alone would deny M-mode its own code.
    pmpcfg_write(0, cfg0);
    if (l->count > 8) pmpcfg_write(2, cfg2);
    __asm__ __volatile__("fence rw, rw" ::: "memory");

    // Readback: PMP CSRs are WARL, the hardware may have adjusted values.
    U64 rb_addr[PMP_MAX_ENTRIES];
    U8  rb_cfg[PMP_MAX_ENTRIES];
    for (U32 i = 0; i < l->count; i++) {
        rb_addr[i] = pmpaddr_access(i, FALSE, 0);
        rb_cfg[i] = cfg_read(i);
    }
    for (U32 i = 0; i < l->count; i++) {
        Bool catch_all = (i == l->count - 1);
        if (rb_cfg[i] != l->cfg[i] || (!catch_all && rb_addr[i] != l->addr[i])) {
            kprintf("[PMP] hart %u entry %u readback addr=0x%p cfg=0x%x, expected addr=0x%p cfg=0x%x\n",
                    hart_id, i, (void*)rb_addr[i], rb_cfg[i], (void*)l->addr[i], l->cfg[i]);
            pmp_halt("PMP registers did not accept the proven layout");
        }
    }
    if (!verify_semantics(&g_kpolicy, rb_addr, rb_cfg, l->count, g_pa_bits, TRUE)) {
        pmp_halt("hardware PMP semantics differ from the policy");
    }
    __atomic_fetch_add(&g_locked_harts, 1, __ATOMIC_SEQ_CST);
}

U32 pmp_locked_hart_count(U0) {
    return __atomic_load_n(&g_locked_harts, __ATOMIC_SEQ_CST);
}

static const char* proof_status(U0) {
    if (g_pmp_proof.magic != PMP_PROOF_MAGIC) return NULL;
    return (const char*)g_pmp_proof.prover;
}

U0 pmp_init(U0) {
    kprintf("[PMP] Building locked M-mode memory protection layout...\n");

    g_hw_entries = probe_entry_count();
    if (!build_kernel_policy(&g_kpolicy)) pmp_halt("invalid PMP policy (alignment, overlap or W+X outside JIT)");
    if (!pmp_build_layout(&g_kpolicy, &g_layout)) pmp_halt("PMP policy needs more than 16 entries");
    if (g_layout.count > g_hw_entries) {
        kprintf("[PMP] layout needs %u entries, hardware implements %u\n", g_layout.count, g_hw_entries);
        pmp_halt("not enough PMP entries on this hart");
    }

    // The layout must be bit-identical to the one proven at build time.
    Bool proven = FALSE;
    if (g_pmp_proof.magic == PMP_PROOF_MAGIC) {
        if (g_pmp_proof.version != PMP_PROOF_VERSION || g_pmp_proof.count != g_layout.count) {
            pmp_halt("build-time PMP certificate does not match this kernel");
        }
        for (U32 i = 0; i < g_layout.count; i++) {
            if (g_pmp_proof.addr[i] != g_layout.addr[i] || g_pmp_proof.cfg[i] != g_layout.cfg[i]) {
                kprintf("[PMP] entry %u: kernel 0x%p/0x%x, certificate 0x%p/0x%x\n", i,
                        (void*)g_layout.addr[i], g_layout.cfg[i],
                        (void*)g_pmp_proof.addr[i], g_pmp_proof.cfg[i]);
                pmp_halt("kernel PMP layout differs from the proven layout");
            }
        }
        proven = TRUE;
    } else {
        kprintf("[PMP] WARNING: no build-time proof certificate (Z3 prover not run).\n");
    }

    // Verify the intended layout before locking anything (cheap sanity check
    // of the generator itself, at full 56-bit address width).
    if (!verify_semantics(&g_kpolicy, g_layout.addr, g_layout.cfg, g_layout.count, PMP_PA_BITS_MAX, TRUE)) {
        pmp_halt("generated PMP layout does not implement the policy");
    }

    program_and_verify(0);
    g_state = proven ? PMP_STATE_LOCKED_PROVEN : PMP_STATE_LOCKED_VERIFIED;

    kprintf(" [ OK ] PMP locked on hart 0: %u/%u entries, %u-bit PA, %s\n",
            g_layout.count, g_hw_entries, g_pa_bits,
            proven ? "Z3-proven + boot-verified" : "boot-verified");
}

U0 pmp_init_secondary(U32 hart_id) {
    if (g_state == PMP_STATE_UNCONFIGURED) {
        pmp_halt("secondary hart started before hart 0 prepared the PMP layout");
    }
    program_and_verify(hart_id);
}

Bool pmp_verify_layout(const PmpPolicy* p, const U64* addr, const U8* cfg, U32 count, Bool verbose) {
    return verify_semantics(p, addr, cfg, count, g_pa_bits, verbose);
}

U32 pmp_hw_entry_count(U0) {
    return g_hw_entries;
}

Bool pmp_keyhart_matches_certificate(const PmpLayout* l) {
    if (g_pmp_proof.magic != PMP_PROOF_MAGIC) return TRUE;   // no certificate: runtime checks only
    if (g_pmp_proof.kh_count != l->count) return FALSE;
    for (U32 i = 0; i < l->count; i++) {
        if (g_pmp_proof.kh_addr[i] != l->addr[i] || g_pmp_proof.kh_cfg[i] != l->cfg[i]) return FALSE;
    }
    return TRUE;
}

Bool pmp_cell_matches_certificate(U32 cell, const PmpLayout* l) {
    if (g_pmp_proof.magic != PMP_PROOF_MAGIC) return TRUE;   // no certificate: runtime checks only
    if (cell >= g_pmp_proof.cell_count || g_pmp_proof.cell_entries != l->count) return FALSE;
    for (U32 i = 0; i < l->count; i++) {
        if (g_pmp_proof.cell_addr[cell][i] != l->addr[i] || g_pmp_proof.cell_cfg[cell][i] != l->cfg[i]) {
            return FALSE;
        }
    }
    return TRUE;
}

PmpState pmp_get_state(U0) {
    return g_state;
}

U0 pmp_dump_config(U0) {
    static const char* const amode[] = { "OFF", "TOR", "NA4", "NAPOT" };
    kprintf("\n================ [ RISC-V PMP (LOCKED, M-MODE ENFORCED) ] ================\n");
    kprintf("  State        : %s\n",
            g_state == PMP_STATE_LOCKED_PROVEN ? "LOCKED - Z3-proven at build + verified at boot" :
            g_state == PMP_STATE_LOCKED_VERIFIED ? "LOCKED - verified at boot (no build proof)" : "NOT CONFIGURED");
    kprintf("  Certificate  : %s\n", proof_status() ? proof_status() : "absent");
    kprintf("  Entries      : %u used / %u implemented, %u-bit physical addresses\n",
            g_layout.count, g_hw_entries, g_pa_bits);
    kprintf("  Harts locked : %u (each verified its own registers)\n", pmp_locked_hart_count());
    kprintf("  Policy:\n");
    for (U32 i = 0; i < g_kpolicy.count; i++) {
        const PmpPolicyRegion* r = &g_kpolicy.r[i];
        kprintf("    [0x%p, 0x%p) %c%c%c  %s\n", (void*)r->start, (void*)r->end,
                (r->perm & PMP_R) ? 'R' : '-', (r->perm & PMP_W) ? 'W' : '-', (r->perm & PMP_X) ? 'X' : '-',
                r->name);
    }
    kprintf("    everything else       ---  denied (locked catch-all)\n");
    kprintf("  Hardware registers (this hart):\n");
    for (U32 i = 0; i < g_layout.count; i++) {
        U8 c = cfg_read(i);
        kprintf("    pmp%-2u addr=0x%p cfg=0x%02x %-5s %c%c%c %s\n", i, (void*)pmpaddr_access(i, FALSE, 0), c,
                amode[(c & PMP_A_MASK) >> 3],
                (c & PMP_R) ? 'R' : '-', (c & PMP_W) ? 'W' : '-', (c & PMP_X) ? 'X' : '-',
                (c & PMP_L) ? "LOCKED" : "unlocked");
    }
    kprintf("==========================================================================\n");
}

// ----------------------------------------------------------------------------
// Self-test: deliberate faults, recovered through the trap probe
// ----------------------------------------------------------------------------

#define RISCV_RET 0x00008067u

static U32 g_pmp_jit_probe[4] __attribute__((section(".jit"), aligned(16)));
static U32 g_pmp_data_probe[4] __attribute__((aligned(16)));
static const U32 g_pmp_rodata_probe[4] __attribute__((aligned(16))) = { RISCV_RET, 0, 0, 0 };

// A function in .text that only returns (target for the "execute code" probe).
__attribute__((naked, noinline)) static U0 pmp_text_ret(U0) {
    __asm__ __volatile__("ret");
}

static Bool probe_load(U64 addr) {
    trap_probe_begin();
    U64 v;
    __asm__ __volatile__("ld %0, 0(%1)" : "=r"(v) : "r"(addr) : "memory");
    (U0)v;
    return trap_probe_end();
}

Bool pmp_probe_load(U64 addr) {
    return probe_load(addr);
}

static Bool probe_store(U64 addr) {
    trap_probe_begin();
    U32 v = 0;
    __asm__ __volatile__("lw %0, 0(%1)\n\tsw %0, 0(%1)" : "+r"(v) : "r"(addr) : "memory");
    return trap_probe_end();
}

// Calls `addr` as a function. If the fetch faults, the trap probe resumes at
// the return address, so control comes back here either way.
static Bool probe_exec(U64 addr) {
    trap_probe_begin();
    __asm__ __volatile__("jalr ra, 0(%0)" : : "r"(addr) : "ra", "memory");
    return trap_probe_end();
}

static Bool expect(const char* what, Bool faulted, Bool should_fault) {
    Bool ok = (faulted == should_fault);
    kprintf("  %s %-46s %s\n", ok ? "[PASS]" : "[FAIL]", what,
            faulted ? "-> access fault" : "-> allowed");
    return ok;
}

Bool pmp_self_test(U0) {
    kprintf("\n================ [ PMP SELF-TEST (deliberate faults) ] ================\n");
    if (g_state == PMP_STATE_UNCONFIGURED) {
        kprintf("  PMP not configured.\n");
        return FALSE;
    }
    Bool ok = TRUE;

    U32* heap_code = (U32*)Malloc(64);
    if (!heap_code) return FALSE;
    heap_code[0] = RISCV_RET;
    g_pmp_data_probe[0] = RISCV_RET;
    g_pmp_jit_probe[0] = RISCV_RET;
    __asm__ __volatile__("fence.i" ::: "memory");

    ok &= expect("read  NULL page (0x0)", probe_load(0), TRUE);
    ok &= expect("write kernel code", probe_store((U64)(uintptr_t)&pmp_init & ~7ULL), TRUE);
    ok &= expect("write read-only data", probe_store((U64)(uintptr_t)g_pmp_rodata_probe), TRUE);
    ok &= expect("execute read-only data", probe_exec((U64)(uintptr_t)g_pmp_rodata_probe), TRUE);
    ok &= expect("execute .data/.bss", probe_exec((U64)(uintptr_t)g_pmp_data_probe), TRUE);
    ok &= expect("execute heap", probe_exec((U64)(uintptr_t)heap_code), TRUE);
    ok &= expect("execute NULL page", probe_exec(0), TRUE);
    ok &= expect("read beyond end of RAM", probe_load(g_pmp_sym[SYM_RAM_END]), TRUE);
    ok &= expect("read the key vault (key hart only)", probe_load(g_pmp_sym[SYM_KV_START]), TRUE);
    ok &= expect("write heap", probe_store((U64)(uintptr_t)heap_code), FALSE);
    ok &= expect("write .data/.bss", probe_store((U64)(uintptr_t)g_pmp_data_probe), FALSE);
    ok &= expect("execute JIT arena", probe_exec((U64)(uintptr_t)g_pmp_jit_probe), FALSE);
    ok &= expect("execute kernel code", probe_exec((U64)(uintptr_t)&pmp_text_ret), FALSE);

    Free(heap_code);
    kprintf("  Result: %s\n", ok ? "ALL PROBES MATCH THE POLICY" : "MISMATCH - PMP NOT ENFORCING POLICY");
    kprintf("=======================================================================\n");
    return ok;
}
