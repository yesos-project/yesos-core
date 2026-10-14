#ifndef TRAP_H
#define TRAP_H

#include "types.h"

typedef struct TrapFrame {
    U64 ra;
    U64 t0;
    U64 t1;
    U64 t2;
    U64 s0;
    U64 s1;
    U64 a0;
    U64 a1;
    U64 a2;
    U64 a3;
    U64 a4;
    U64 a5;
    U64 a6;
    U64 a7;
    U64 s2;
    U64 s3;
    U64 s4;
    U64 s5;
    U64 s6;
    U64 s7;
    U64 s8;
    U64 s9;
    U64 s10;
    U64 s11;
    U64 t3;
    U64 t4;
    U64 t5;
    U64 t6;
    U64 gp;
    U64 tp;
    U64 mepc;
    U64 mcause;
    U64 mtval;
    U64 mstatus;
    U64 sp;
    U64 vtype;
    U64 vl;
    U64 vstart;
    U64 vcsr;
    U64 pad;
} TrapFrame;

U0 trap_init(U0);
U0 trap_dispatch(TrapFrame* tf);

// Runtime probing (see kernel/trap.c). trap_probe_end() returns TRUE if an
// illegal-instruction or access-fault exception occurred since
// trap_probe_begin(); execution resumed after the faulting instruction.
U0   trap_probe_begin(U0);
Bool trap_probe_end(U0);

#endif // TRAP_H
