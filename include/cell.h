#ifndef CELL_H
#define CELL_H

/*
 * YesOS 2.0 - PMP cells: hardware-isolated application cores, all in M-mode.
 *
 * A cell is a hart that, before running any untrusted code, locks a PMP
 * layout (L bit) that only lets it see:
 *   - the cell runtime (.cell_text)            R-X
 *   - its own code arena                       R-X  (written only by hart 0)
 *   - its own data arena (mailbox, strings, stack)  RW-
 * Everything else - kernel, vault key, devices, other cells - is denied by
 * hardware even though the cell runs in Machine mode.
 *
 * The PMP cannot protect CSRs, so code is only installed after the
 * instruction verifier (kernel/cell.c) proves it contains no SYSTEM-class
 * instruction (CSR access, ecall, mret, wfi, ...). Together:
 *   PMP        -> the cell cannot leave its memory,
 *   W^X        -> the cell cannot create instructions,
 *   verifier   -> the instructions it has cannot touch control state.
 * mtvec/mie are set by the kernel before locking; the runtime contains no
 * instruction that could redirect traps or mask the kill interrupt.
 *
 * This header is shared with kernel/cell_rt.S (assembler).
 */

#define CELL_FIRST_HART   3          // harts >= 3 become cells (hart 2: key hart)
#define CELL_MAX          5          // up to 8 harts
#define CELL_STRIDE       0x80000    // 512 KiB per cell
#define CELL_CODE_SIZE    0x10000    // 64 KiB code arena (R-X for the cell)
#define CELL_DATA_SIZE    (CELL_STRIDE - CELL_CODE_SIZE)
#define CELL_STR_OFFSET   0x1000     // string pool inside the data arena
#define CELL_STR_SIZE     0x2000
// Private 320x240 32bpp canvas inside the data arena. The cell draws only
// here; the NAS build has no local display, so presents are only counted.
#define CELL_CANVAS_OFFSET 0x4000
#define CELL_CANVAS_W     320
#define CELL_CANVAS_H     240
#define CELL_PMP_ENTRIES  8          // mailbox slots for the cell layout

// Mailbox lives at the start of the cell's data arena. It is writable by the
// cell: hart 0 treats every field as untrusted input.
#define MB_MAGIC          0
#define MB_STATE          8
#define MB_PMP_ADDR       16          // 8 x U64
#define MB_PMP_CFG0       80
#define MB_RB_ADDR        88          // 8 x U64 readback
#define MB_RB_CFG0        152
#define MB_ENTRY          160
#define MB_ARGS           168         // 4 x U64
#define MB_RESULT         200
#define MB_FAULT_CAUSE    208
#define MB_FAULT_TVAL     216
#define MB_FAULT_EPC      224
#define MB_RPC_STATE      232
#define MB_RPC_OP         240
#define MB_RPC_ARGS       248         // 7 x U64
#define MB_RPC_RESULT     304
#define MB_SIZE           312

#define CELL_ST_OFFLINE   0
#define CELL_ST_BOOTED    1           // PMP locked, readback published
#define CELL_ST_IDLE      2
#define CELL_ST_RUN       3           // job posted by hart 0
#define CELL_ST_RUNNING   4
#define CELL_ST_DONE      5
#define CELL_ST_FAULT     6
#define CELL_ST_KILLED    7

#define CELL_RPC_IDLE     0
#define CELL_RPC_REQUEST  1
#define CELL_RPC_DONE     2
#define CELL_RPC_PRINT    1           // a0 = format (in cell data), a1..a6 = args
#define CELL_RPC_BEEP     2           // a0 = earcon id (0..15); no-op on the NAS
#define CELL_RPC_SLEEP    3           // a0 = milliseconds (capped)
#define CELL_RPC_TEXT     4           // a0 = x, a1 = y, a2 = string (in cell data), a3 = color
#define CELL_RPC_PRESENT  5           // frame done (counted; no local display)

#ifndef __ASSEMBLER__

#include "types.h"

typedef struct {
    U64          magic;
    volatile U64 state;
    U64          pmp_addr[CELL_PMP_ENTRIES];
    U64          pmp_cfg0;
    U64          rb_addr[CELL_PMP_ENTRIES];
    U64          rb_cfg0;
    U64          entry;
    U64          args[4];
    U64          result;
    U64          fault_cause;
    U64          fault_tval;
    U64          fault_epc;
    volatile U64 rpc_state;
    U64          rpc_op;
    U64          rpc_args[7];
    U64          rpc_result;
} CellMailbox;

typedef enum {
    CELL_RESULT_OK = 0,
    CELL_RESULT_FAULT,          // hardware fault (e.g. PMP access fault)
    CELL_RESULT_TIMEOUT,        // killed by the watchdog
    CELL_RESULT_REJECTED,       // compile error or verifier rejection
    CELL_RESULT_UNAVAILABLE,    // no verified cell hart
} CellResultCode;

typedef struct {
    CellResultCode code;
    I64            value;
    U64            fault_cause;
    U64            fault_tval;
    char           reason[96];
} CellResult;

// Boot (hart 0, from pmp_init): build, check and stage every cell layout.
Bool  cell_prepare_layouts(U0);
// Secondary hart entry for cell harts (kernel text, before locking). Never returns.
U0    cell_hart_enter(U32 hart_id) __attribute__((noreturn));
Bool  cell_is_cell_hart(U32 hart_id);
// Boot (hart 0, after smp_init): verify each cell's PMP readback.
U0    cell_verify_booted(U0);

// Instruction verifier. Returns TRUE if `count` instructions are allowed in a cell.
Bool  cell_verify_code(const U32* code, size_t count, char* why, size_t why_len);

// Compiles a HolyQ program in cell mode (one or more functions; `extern`
// declarations are ignored), verifies it and runs its entry function on a
// cell. Entry: `entry` if given, else the first top-level call statement
// (e.g. "PlayHolyChords();"), else "main", else the only function.
Bool  cell_run_program(const char* source, const char* entry, const I64* args, U32 argc,
                       U32 timeout_ms, CellResult* out);
Bool  cell_run_source(const char* source, const I64* args, U32 argc, U32 timeout_ms, CellResult* out);
// Starts a program asynchronously (apps). Its RPCs, frames and completion are
// handled by cell_poll() from the main loop.
Bool  cell_start_app(const char* source, const char* name, U32 timeout_ms, CellResult* out);
U0    cell_poll(U0);

U32   cell_available_count(U0);
U0    cell_print_status(U0);
Bool  cell_self_test(U0);

#endif // __ASSEMBLER__
#endif // CELL_H
