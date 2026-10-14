#ifndef PMP_H
#define PMP_H

#include "types.h"

/*
 * YesOS 2.0 - RISC-V Physical Memory Protection (PMP), locked in M-mode
 *
 * Every hart programs the same layout with the L (lock) bit set, so the rules
 * bind Machine mode itself and cannot be changed again until reset:
 *
 *   [0, null_end)            ---   NULL guard
 *   [mmio_start, mmio_end)   RW-   device registers (never executable)
 *   [kernel_start, text_end) R-X   kernel code (immutable)
 *   [text_end, rodata_end)   R--   read-only data
 *   [rodata_end, jit_start)  RW-   data, BSS, hart stacks
 *   [jit_start, jit_end)     RWX   JIT arena (only W+X region)
 *   [jit_end, ram_end)       RW-   heap and free RAM
 *   everything else          ---   explicit locked catch-all
 *
 * The layout is verified twice by independent implementations:
 *   - build time: tools/pmp_prover.py proves with Z3 that the hardware
 *     semantics of the generated registers equal the policy for every
 *     address and access type, then writes a certificate into .pmp_proof;
 *   - boot time:  each hart reads the registers back (they are WARL) and
 *     sweeps every elementary address interval comparing hardware semantics
 *     against the policy. Any mismatch halts the hart.
 */

#define PMP_R       0x01
#define PMP_W       0x02
#define PMP_X       0x04
#define PMP_A_MASK  0x18
#define PMP_A_OFF   0x00
#define PMP_A_TOR   0x08
#define PMP_A_NA4   0x10
#define PMP_A_NAPOT 0x18
#define PMP_L       0x80

#define PMP_MAX_ENTRIES 16

#define PMP_PROOF_MAGIC   0x56504D50u  // "PMPV"
#define PMP_PROOF_VERSION 3u
#define PMP_PROOF_CELLS   5            // == CELL_MAX
#define PMP_CELL_SLOTS    8            // == CELL_PMP_ENTRIES

// Certificate patched into the .pmp_proof section by tools/pmp_prover.py.
// Layout must match the struct.pack format used by the prover.
typedef struct __attribute__((packed)) {
    U32  magic;
    U32  version;
    U32  count;                                    // kernel layout entries
    U32  cell_count;
    U64  addr[PMP_MAX_ENTRIES];
    U8   cfg[PMP_MAX_ENTRIES];
    U32  cell_entries;                             // entries per cell layout
    U32  reserved;
    U64  cell_addr[PMP_PROOF_CELLS][PMP_CELL_SLOTS];
    U8   cell_cfg[PMP_PROOF_CELLS][PMP_CELL_SLOTS];
    U32  kh_count;                                 // key hart layout entries
    U32  reserved2;
    U64  kh_addr[PMP_MAX_ENTRIES];
    U8   kh_cfg[PMP_MAX_ENTRIES];
    char prover[32];
} PmpProof;

#define PMP_POLICY_MAX 8

typedef struct {
    U64         start;
    U64         end;
    U8          perm;
    const char* name;
} PmpPolicyRegion;

// Sorted, non-overlapping regions; anything outside them is denied.
typedef struct {
    PmpPolicyRegion r[PMP_POLICY_MAX];
    U32             count;
} PmpPolicy;

typedef struct {
    U32 count;
    U64 addr[PMP_MAX_ENTRIES];
    U8  cfg[PMP_MAX_ENTRIES];
} PmpLayout;

typedef enum {
    PMP_STATE_UNCONFIGURED = 0,
    PMP_STATE_LOCKED_PROVEN,      // build-time Z3 proof + boot verification
    PMP_STATE_LOCKED_VERIFIED,    // boot verification only (no certificate)
} PmpState;

// Hart 0: probes entries, builds and checks the layout, locks and verifies.
// Halts the hart if anything does not verify.
U0       pmp_init(U0);

// Secondary harts: lock the layout prepared by hart 0 and verify it.
U0       pmp_init_secondary(U32 hart_id);

PmpState pmp_get_state(U0);
U32      pmp_locked_hart_count(U0);   // harts that locked and verified the layout
U0       pmp_dump_config(U0);

// Generic layout machinery (shared with kernel/cell.c)
Bool     pmp_cell_policy(U32 cell, PmpPolicy* out);
Bool     pmp_build_layout(const PmpPolicy* p, PmpLayout* out);
Bool     pmp_verify_layout(const PmpPolicy* p, const U64* addr, const U8* cfg, U32 count, Bool verbose);
Bool     pmp_cell_matches_certificate(U32 cell, const PmpLayout* l);
Bool     pmp_keyhart_policy(PmpPolicy* out);
Bool     pmp_keyhart_matches_certificate(const PmpLayout* l);
Bool     pmp_lock_layout_silent(const PmpPolicy* p, const PmpLayout* l);
U64      pmp_symbol_keyvault_start(U0);
U64      pmp_symbol_keyvault_end(U0);
U32      pmp_hw_entry_count(U0);

// Runs fault probes against the locked layout (write to code, execute data,
// NULL access, ...). Returns TRUE when every probe behaves as the policy says.
Bool     pmp_self_test(U0);

#endif // PMP_H
