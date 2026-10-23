<div align="center">

# YesOS core

**The shared kernel of YesOS: bare-metal RISC-V in Machine mode,<br>
isolated by a PMP layout that every build proves with Z3.**

<img alt="RISC-V RV64GCV" src="https://img.shields.io/badge/RISC--V-RV64GCV-283272?logo=riscv&logoColor=white">
<img alt="Machine mode only" src="https://img.shields.io/badge/runs%20in-Machine%20mode-4a5568">
<img alt="PMP proven with Z3" src="https://img.shields.io/badge/PMP-proven%20with%20Z3-6b46c1">
<img alt="No floating point" src="https://img.shields.io/badge/floating%20point-none%2C%20checked-2f855a">
<img alt="License MIT" src="https://img.shields.io/badge/license-MIT-2b6cb0">

[Products](#products) · [What it provides](#1-what-the-core-provides) · [Design choices](#2-design-choices) · [Build a product](#3-building-a-product-on-the-core) · [Security](#4-security-architecture) · [Limits](#8-honest-limits)

</div>

---

The core of YesOS: a bare-metal operating system for RISC-V RV64GCV that runs
entirely in Machine mode, isolated by a **locked, Z3-proven PMP**. There is no
Linux, no libc and no binary blob.

### Products

Every YesOS product includes this repository as its `core` git submodule and
selects only the parts it needs, so each image contains nothing else:

| Product | Repository | What it adds |
|---|---|---|
| [YesOS NAS](https://github.com/yesos-project/yesos-nas) | `yesos-nas` | file services (WebDAV, NAS protocol), web panel, accounts, snapshots, replication |
| [YesOS Security](https://github.com/yesos-project/yesos-security) | `yesos-security` | invisible bridge firewall between the ONT and the router |
| [YesOS Desktop](https://github.com/yesos-project/yesos-desktop) | `yesos-desktop` | the core, HD Audio, a desktop of overlapping windows (console, file browser, text viewer), virtio keyboard and tablet; features are added one at a time |

## 1. What the core provides

| Area | Files |
| :--- | :--- |
| Boot, traps, memory, SMP | `boot/boot_rv64.S`, `kernel/trap*.{c,S}`, `kernel/memory.c`, `kernel/smp.c`, `kernel/task*.{c,S}` |
| PMP and Z3 prover | `kernel/pmp.c`, `tools/pmp_prover.py` (+ `make prover-setup`) |
| Cells | `kernel/cell.c`, `kernel/cell_rt.S` |
| Key hart and integrity | `kernel/keyhart.c`, `kernel/keyhart_vkey.S`, `tools/check_keyhart_vector.py`, `tools/image_hash.py` |
| Build checks | `tools/pmp_prover.py` (Z3), `tools/check_keyhart_vector.py`, `tools/check_no_fp.py`, `tools/check_symbols.py`, `tools/image_hash.py` |
| Drivers | `drivers/pci.c` (PCIe enumeration, one BAR allocator), `drivers/virtio_blk.c`, `drivers/ata.c` (block front end), `drivers/virtio_net.c` (up to 3 NICs, ARP/IPv4/UDP/ICMP), `drivers/serial.c`, `drivers/timer.c`, `drivers/earcon.c` |
| Storage | `kernel/redsea_eml.c` (RedSea v4), `kernel/barrett_poly.c` (RedSea's checksum), `kernel/vfs.c`, `kernel/ramfs.c`, `kernel/lz4.c` |
| Security services | `kernel/entropy.c`, `kernel/security_pin.c` (console PIN), `kernel/firewall.c` (RFC 1918 filter of the system's own stack), `kernel/netcfg.c` (static address) |
| HolyQ | `kernel/holyq_*.c` (JIT for the console, compiler for cell programs) |
| Shell | `shell/shell.c` (serial console; UTF-8 input, so accented letters and ñ can be typed; line editing with arrows, Home, End, Delete and a 16-command history in module `lineedit`, none of it for hidden input) |
| Font (module `gfx`) | `fonts/yesos-8x16.txt` → `graphics/font_data.c` (`tools/gen_font.py`): 8x16, 151 glyphs: printable ASCII, the Latin-1 letters and signs of Spanish and the Western languages' accented vowels, and €; used by cell text and the Desktop screen |
| Rust | `rust/` (crate `yesos_core`: allocator, crypto + DRBG, packet filter; optional DNS engine and frame parser) |
| Optional modules | `vault` (`kernel/vault.c`, `kernel/vault_shell.c`), `packages` (`kernel/app_registry.c`, `kernel/ypkg.c`, `apps/`), `dns` (`kernel/dnsblock.c` + `rust/src/dns.rs`) |
| Host tools | `tools/redsea_fsck.py`, `tools/redsea_injector.py`, `tools/deploy_app.py`, `tools/yesos_harness.py` (QEMU test harness), `tools/dns_wire.py` |

## 2. Design choices

| Choice | What it means in practice | How it is enforced |
|---|---|---|
| **Machine mode only** | No S-mode, no U-mode, no page tables, no OpenSBI. Isolation comes from the PMP with the L bit, which binds M-mode itself until reset. | Z3 proof at build time, readback sweep at boot (section 4). |
| **Integer-only kernel** | No floating-point instruction anywhere in the image; fractions use fixed point. Kernel behaviour never depends on FPU rounding modes or IEEE 754 corner cases. | `tools/check_no_fp.py` disassembles every image and deletes it if it finds one (compressed forms included). |
| **Untrusted code on its own core** | Apps run in PMP cells on dedicated harts, never on the kernel hart. | Per-cell PMP proof, instruction verifier, watchdog. |
| **A key that never touches memory** | The vault key lives only in vector registers of the key hart. | `tools/check_keyhart_vector.py` walks the call graph at every build. |
| **Hardware checksum on every file** | RedSea stores 32 bits of a 64-bit polynomial checksum per file, computed by Barrett reduction with the Zbc carry-less multiply (`clmul`): crc = (crc ^ w) x^64 mod P per 64-bit word, P the CRC-64-ECMA polynomial. A code of its own, not the standard CRC-64/XZ or ECMA-182. | `kernel/barrett_poly.c`; `tools/test_checksum.py` checks it against a bit-by-bit reference and `tools/redsea_fsck.py`; checked by `fsck` and the RedSea tests. |
| **No libc, no blobs** | C freestanding, Rust `no_std` and assembly. The only outside code is Rust crates (RustCrypto, rustls) built from source at versions pinned in `Cargo.lock`. | The image hash is checked at boot and re-verified by the integrity monitor. |

Two precise notes on the integer-only rule: the boot code resets the FP status
register (`fcsr`) and leaves the FPU enabled, and the cell instruction verifier
still accepts FP opcodes, although nothing in YesOS generates them.

### How it compares (design, not performance)

| | YesOS | Linux | seL4 | Zephyr | TempleOS |
|---|---|---|---|---|---|
| Kernel privilege on RISC-V | M-mode only | S-mode (firmware in M-mode) | S-mode (firmware in M-mode) | M-mode (optional U-mode threads) | x86-64 ring 0 only (no RISC-V) |
| Isolation | Locked PMP; untrusted code on separate harts (cells) | MMU, processes | MMU, capabilities | PMP (userspace, stack guards), optional | None, by design |
| Formal verification | PMP layout proven with Z3 at every build (not the kernel code) | None for the kernel as a whole | Functional correctness of the kernel, on supported configurations | None | None |
| Floating point in the kernel | None (checked at every build) | Not in general kernel code | None | Optional | Used (F64) |
| Userspace | None (cells instead) | Yes | Yes (user-level servers) | Optional user threads | None |
| Real hardware | Not yet (QEMU only) | Yes | Yes | Yes | x86-64 PCs |

This table compares designs, not speed. A performance comparison needs real
boards: QEMU does not model cycle timing, so cycle counts measured in it would
mean nothing. Benchmarks will be published with their method and scripts once
YesOS runs on an Orange Pi RV2.

### Measured today (QEMU `virt`)

| | |
|---|---|
| Image code size (`.text`) | core self-test 339 KiB, Desktop 289 KiB, Security 355 KiB, NAS 752 KiB |
| PMP entries used (kernel hart) | 9 of 16 |
| Floating-point instructions in the image | 0 (`tools/check_no_fp.py`) |
| Test suites | core 9, NAS 9, Security 1 (64 checks), Desktop 7 (17 + 38 + 23 + 35 + 35 + 30 + 24 checks), all run under QEMU |

### Experimental work in `yesos-lab`

The old, larger YesOS tree (`yesos-lab`) holds work that is not in the products
yet and will come to YesOS Desktop one piece at a time, each with tests:

- **EML**, an integer-only number system and math library. Its core type
  (`eml64_t`) stores the base-2 logarithm of a value in Q32 fixed point:
  multiplication and division become integer addition and subtraction,
  while addition and subtraction need a polynomial approximation. Around it
  sit Clifford S³ rotors, min-plus tropical algebra, an FFT and more. It is
  used by the lab's 3D pipeline and demos. Measured and then rewritten in
  the lab: every operation now reaches the format's limit of 33.5 bits
  (better than float32), where subtraction, exp, ln and sin had 13–17 bits;
  sin costs 255 instructions on RISC-V (it was 1405). Addition still costs
  about 29 times the instructions of fixed point (145 against 5), so on a
  core with a hardware multiplier it is a library for log, exp, power and
  trigonometry without floating point, not a general numeric base; no
  product uses it yet.
  The lab's audio code labelled "EML" (resampler, dither, limiter) is plain
  fixed-point code that uses none of this number system. It was measured
  once in YesOS Desktop (commit `d900e40` there) and taken out again.
- **A Pisano-period counter on the audio ring:** next to the HDA DMA ring
  (a plain power-of-two buffer) runs a Fibonacci counter that wraps after
  exactly one Pisano period, π(2^N) = 3·2^(N-1) steps. Today it is only reported
  in telemetry; the samples themselves are placed linearly.
- The graphical desktop (DolDoc window manager, 3D pipeline).

None of this is claimed as a YesOS feature until it is in a product with tests
that measure it.

## 3. Building a product on the core

A product repository looks like this:

```text
yesos-<product>/
  core/          this repository (git submodule)
  src/ include/  the product's C code
  rust/          the product's Rust staticlib "yesos", depending on core/rust
  tools/         its tests and host tools
  Makefile
```

Its `Makefile` names its parts and includes `core/core.mk`:

```make
PRODUCT = security
CORE_MODULES = dns                  # optional core modules: vault packages dns gfx lineedit
FORBIDDEN_SYMBOLS = hda_ audio_ display_ input_ terminal_ wav_ desktop_ surf_ files_   # never link the Desktop's code
PRODUCT_C_SRCS = $(wildcard src/*.c)
include core/core.mk                # yesos.elf: compile, link, prove
```

| Module | What it adds | Products |
|---|---|---|
| `vault` | encrypted `/vault`, key in the key hart | NAS |
| `packages` | `.ypk` apps run in PMP cells | NAS |
| `dns` | DNS filter (engine in Rust) | Security |
| `gfx` | the 8x16 font and the cells' text call (refused without it) | Desktop |
| `lineedit` | console line editing and history (without it: type and backspace only) | Desktop |

A product gets only what it names, and less code is less attack surface:
NAS and Security have no font, no line editor and none of the Desktop's
drivers. `tools/check_symbols.py` enforces it on every build: the image is
deleted if it contains a symbol of an unselected module or one of the
product's `FORBIDDEN_SYMBOLS`.

The core calls the product at fixed points (`include/product.h`):
`PRODUCT_NAME`, `product_early_init()` (after the network drivers),
`product_init()` (after file systems, entropy and vault),
`product_boot_summary()` and `product_poll()` (main loop). The product plugs
its services into the core without the core knowing them:

| Hook | Header | Used for |
|---|---|---|
| `net_register_udp(port, fn)` (port 0 sees every datagram first) | `virtio_net.h` | NAS protocol, DNS |
| `net_register_tcp(fn)` | `virtio_net.h` | the NAS's TCP/TLS/HTTP stack |
| `net_set_bridge(ops)` | `virtio_net.h` | the Security bridge |
| `net_set_telemetry(on)` | `virtio_net.h` | lab telemetry (off by default) |
| `shell_register(ext)` (commands, help, hidden prompts) | `shell.h` | product console commands |
| `netcfg_on_change(fn)` | `netcfg.h` | follow a new address (DNS upstream) |
| `kprintf_set_hook(fn)` (every character the console writes, the shell's echo included) | `kprintf.h` | Desktop's console on the screen |

`make` in a product links `yesos.elf` and fails, deleting it, if the PMP
layout cannot be proven, the key hart can reach a vector instruction outside
`keyhart_vkey.S`, or it contains a floating-point instruction or a forbidden
symbol. Measured code size (`.text`): NAS 752 KiB, Security 355 KiB,
Desktop 289 KiB.

In this repository, `make` builds the core self-test image (core + vault +
packages + dns, `selftest/`) and `make test` runs the core's suites on it:

```bash
git clone https://github.com/yesos-project/yesos-core && cd yesos-core
sudo apt install -y git make clang lld llvm qemu-system-misc python3 python3-venv python3-cryptography
#   Arch: sudo pacman -S git make clang lld llvm qemu-system-riscv python python-cryptography
# Rust from https://rustup.rs, then:
rustup target add riscv64gc-unknown-none-elf
make prover-setup        # once: Z3 in tools/.venv
make                     # yesos.elf: links, proves the PMP layout, checks the key hart, hashes the image
make test                # test_pmp, test_cells, test_integrity, test_packages, test_dns, test_timer, test_pci, test_line_edit, test_checksum
make run                 # serial console in the terminal (Ctrl-A X to quit)
```

Tested with clang 23, QEMU 11.1, Rust 1.99 and Python 3.14. The QEMU CPU must
support RVV 1.0 and Zkr (`-cpu rv64,v=true,vext_spec=v1.0,zkr=true`), so an old
distribution QEMU may be too old.

## 4. Security architecture

This section describes what the code actually enforces today. Items marked
**pending** are known gaps, not features.

### Encrypted vault (`/vault`, module `vault`) — `kernel/vault.c`
- Every file under `/vault` is encrypted individually with **XChaCha20-Poly1305** (random 192-bit nonce per write). The file's path is authenticated as associated data, so ciphertexts cannot be swapped or renamed undetected.
- A random 256-bit data key is wrapped with a key derived from the vault passphrase using **Argon2id** (8 MiB, t=3, 128-bit random salt) and stored in `SYS/VAULT.HDR`. Changing the passphrase re-wraps the key without re-encrypting files.
- Plaintext never reaches the disk: RedSea refuses any write under `vault/` that is not flagged as ciphertext. The data key lives only in RAM while the vault is unlocked and is wiped on `vault lock`.
- Five wrong passphrases trigger a 30 s lockout.
- Algorithms come from the audited RustCrypto crates (`chacha20poly1305`, `argon2`, `chacha20`, `blake2`) in `rust/src/crypto.rs`; nothing is hand-rolled.

```text
vault init      create the vault (hidden passphrase prompt)
vault unlock    load the data key        vault lock     wipe it from RAM
vault passwd    change the passphrase    vault status   show state
```

### Entropy — `kernel/entropy.c`
- The DRBG (ChaCha20 with fast key erasure) is seeded from the RISC-V **Zkr `seed` CSR**, probed at runtime, plus timing jitter and a seed persisted in `SYS/RNG.SEED` that is replaced on every boot.
- `make run` enables Zkr in QEMU (`zkr=true`). On boards without Zkr (e.g. JH7110) the system warns that keys are generated from a weak source.
- Built without the `vault` module, `/vault` stays forbidden: every access fails, nothing is ever written there in clear.

### Console PIN
- `pin set <6 digits>` enables `lock`: until the Master PIN is entered, the console accepts only the PIN, echoed as `*`.
- The PIN is stored as an Argon2id hash with a random salt and compared in constant time.

### Locked, proven PMP (all in M-mode) — `kernel/pmp.c`, `tools/pmp_prover.py`
Every hart programs the same PMP layout with the **L bit set**, which makes the rules bind Machine mode itself and freezes them until reset:

```text
[0, 64K)                ---  NULL guard
[64K, RAM base)         RW-  device registers (never executable)
kernel .text            R-X  immutable code
.rodata                 R--  read-only data
.data/.bss/stacks       RW-  never executable
.jit arena              RWX  the only writable+executable memory (HolyQ JIT)
heap .. end of RAM      RW-  never executable
everything else         ---  explicit locked catch-all (M-mode would otherwise allow it)
```

The layout is checked by two independent implementations:
- **Build time:** `tools/pmp_prover.py` reads the linked ELF, generates the registers and uses the **Z3** SMT solver to prove, for *every* physical address and access type, that the hardware semantics equal the policy, plus invariants (W^X outside the JIT, immutable code, NULL guard, no address left to M-mode's default-allow). A mutation self-test checks that the prover rejects 7 deliberately broken layouts. The certificate is written into the ELF (`.pmp_proof`); a kernel whose layout cannot be proven is deleted by `make`. Install the prover once with `make prover-setup`.
- **Boot time:** each hart writes the layout, reads it back (PMP registers may silently adjust values) and sweeps every elementary address interval comparing hardware semantics with the policy. The kernel also refuses a layout that differs from the certificate. Any mismatch halts the hart.

`pmp` shows the state; `pmp test` runs 12 deliberate faults (write code, execute data/heap, NULL, beyond RAM) and checks each against the policy. `python3 tools/test_pmp.py` boots QEMU and verifies all of it.

**Limits:** the PMP does not stop the kernel from *reading* its own data and does not cover device DMA. HolyQ typed at the console still runs on hart 0 with full privileges (by design); untrusted code runs in PMP cells (below). The Orange Pi RV2 layout needs 9 entries; the X60's PMP entry count still has to be measured on the board.

### PMP cells: isolated application cores, still in M-mode — `kernel/cell.c`, `kernel/cell_rt.S`
Harts 3 and up (hart 3 in QEMU, harts 3-7 on an 8-core board) become **cells**. Before running anything untrusted, a cell locks its own PMP layout, which only lets it see:

```text
cell runtime (.cell_text)   R-X   loop, trap handler, RPC stub
its code arena (64 KiB)     R-X   written only by hart 0
its data arena (192 KiB)    RW-   mailbox, strings, stack
everything else             ---   kernel, vault key, devices, other cells
```

The PMP cannot protect CSRs, so three mechanisms work together:
- **PMP** (Z3-proven per cell, read back and verified by hart 0): the cell cannot leave its memory.
- **W^X**: code is not writable by the cell and data is not executable, so it cannot create instructions.
- **Instruction verifier**: hart 0 installs code only if it contains no SYSTEM-class instruction (CSR access, `ecall`, `mret`, `wfi`), no `fence.i`, no vendor/custom or compressed encodings. `mtvec`/`mie` are set by the kernel before locking, and the runtime contains no instruction that could change them, so the kill interrupt cannot be masked.

Hart 0 parks a cell by holding its software interrupt pending (the cell cannot reach the CLINT to clear it), compiles HolyQ in *cell mode* straight into the arena (kernel functions and globals are compile errors; strings go to the cell's own pool; `kprintf` becomes an RPC whose format and `%s` pointers must lie inside the cell), verifies it, releases the cell and enforces a watchdog. The mailbox is treated as untrusted input.

```text
cell                  status of each cell hart
cell run <f.HQ> [n]   compile the file's function in cell mode and run it isolated
cell test             19 checks: verifier rejections, legit work + RPC, and hostile
                      programs (read/write kernel data, touch the UART, write own
                      code, kernel pointer through print, infinite loop) contained
```

`python3 tools/test_cells.py` boots QEMU and runs all of it.

**Packages run in cells (module `packages`).** Installed applications (`pkg install <file.ypk>`, `pkg run <app>`) are untrusted code and always run in a cell — never on hart 0; if no cell is available they refuse to start. A cell program may contain several functions (compiled in two passes with fixed-size PC-relative calls, so forward references work), `extern` declarations are ignored, and the entry is the first top-level call statement (e.g. `PlayHolyChords();`), else `main`. Services available through validated RPCs: `kprintf`/`print`, `speaker_event`/`beep` (ids 0-15) and `SleepMS`/`sleep` (max 2 s per call); anything else is a compile error. Package runs have a 30 s watchdog. The installer treats the file as hostile: sizes are checked against the file (64-bit arithmetic, 16 MiB cap), text fields are forced to be NUL-terminated, names are restricted to `[A-Za-z0-9_.-]` (no `/`), the entry point must be one of the package files, and files are no longer copied into the RamFS namespace. `python3 tools/test_packages.py` installs and runs HolySynth, a multi-function program, hostile packages (kernel read, kernel call, infinite loop) and a malformed package.

**Graphics.** A cell still owns a private 320x240 32bpp canvas inside its data arena (`gfx_clear`, `gfx_rect`, `gfx_plot` run in the cell runtime with clipping; `gfx_text` is a validated RPC; `gfx_present()` publishes a frame). Without a display, presented frames are only counted; showing them is a job for YesOS Desktop.

Console HolyQ (`run <file.HQ>`) still runs on hart 0 by design.

### Key hart: vault key custody (HSM-like) — `kernel/keyhart.c`
Hart 2 is the **key hart**. Its locked PMP layout includes a private `.keyvault` region (vault data key, Argon2 working memory and its own stack) that every other hart's locked layout denies — proven by Z3 for the kernel harts, every cell and the key hart itself. The key hart has no access to device registers or the JIT arena and never runs generated code.

Hart 0 asks it, through a mailbox, to create/unwrap/re-wrap the key and to seal/open vault files; it never receives the key. The key hart only accepts buffers in ordinary kernel data or heap (never its own vault or devices). `keyhart test` checks that hart 0 faults when reading the key slot and the Argon2 memory, that such buffers are refused, and that seal/open works with the private key.

**Key in registers only** (`kernel/keyhart_vkey.S`): the vault key lives exclusively in vector registers of the key hart (`v30`/`v31`) and is never stored to memory. XChaCha20 and HChaCha20 run in scalar registers with key words extracted from the vector registers; only ciphertext/plaintext and the per-message Poly1305 one-time key are written to (private) RAM, and every register that held key-derived data is zeroed afterwards. Wrapping and unwrapping go directly between registers and the header ciphertext. At boot the key hart runs a known-answer test against RustCrypto (seal, open, tamper rejection, key wrap, unwrap into registers) and refuses to serve if anything differs; existing vault files stay compatible. `keyhart test` also scans the whole private RAM and the mailbox for the key (0 occurrences expected) and checks that the Argon2 memory was wiped.

Because clang emits vector instructions even for plain C struct copies, `keyhart.c` is built without the V extension and `tools/check_keyhart_vector.py` walks the call graph of the linked kernel from the key hart's loop on every build: any reachable vector instruction outside `keyhart_vkey.S`, or any indirect call, fails the build.

**What this does and does not give:** Machine-mode code on hart 0 (a bug, a malicious console script) can no longer *extract* the vault key; once the vault is locked it cannot decrypt anything. While unlocked it can still *request* decryptions. The key does not reside in RAM, so reading memory physically does not reveal it; the Argon2-derived KEK touches private RAM briefly during unlock (then wiped), and a new key touches it briefly at creation.

### Integrity monitor (key hart) — `include/integrity.h`, `tools/image_hash.py`
The PMP makes kernel code and read-only data immutable *for software*, but hardware faults and DMA do not go through the PMP. The key hart watches for that:
- **Boot:** recomputes BLAKE2b-256 of `.text || .rodata` and compares it with the hash written into the `.integrity` section at build time (`tools/image_hash.py`). This detects a corrupted image; it is not a signature (whoever can rewrite the image can rewrite the hash).
- **Runtime:** once the entropy pool is seeded it draws a private MAC key, takes a keyed BLAKE2b-256 baseline of every 64 KiB chunk of code and read-only data, and re-verifies one chunk every ~2 ms in its idle time (a full pass about every 150 ms in QEMU). On a mismatch it **locks the vault and wipes the key by itself**, and hart 0 reports the exact chunk.
- `integrity` shows the state. `python3 tools/test_integrity.py` flips one bit of read-only data from outside the guest through QEMU's gdbstub (bypassing the PMP like a real fault) and checks detection, chunk localisation and vault lock-down, then boots a kernel image corrupted on disk and checks the boot-time detection.

Limits: only code and read-only data are covered (mutable data changes legitimately); the MAC key lives in the key hart's private RAM, which DMA could still read. Detection of Rowhammer-style access patterns with hardware performance counters needs real cache events, which QEMU does not model; it is left for the Orange Pi RV2.

## 5. Storage: RedSea

### File system check (`fsck`)
`redsea_eml_fsck` (console `fsck` / `fsck quick`; panel *Discos* → *Comprobar ahora*; the structural part runs at every mount) checks:
- **Structure:**
  - the superblock;
  - every directory entry: name, bounds, and size compared with its sectors;
  - duplicate names;
  - overlapping extents (identical extents shared by snapshots are allowed);
  - snapshot files being read-only;
  - the free map: inside the data area, sorted, never covering used sectors, and its total;
  - lost sectors (neither used nor free).
- **Data:** every file is read and its checksum compared with the stored one: the low 32 bits of the kernel's Barrett checksum (see above), or the old checksum of files injected by earlier host tools.

`tools/redsea_fsck.py <image>` runs the same checks on an image from the PC, with a table-driven port of the kernel CRC. `tools/redsea_injector.py` now stores the kernel CRC as well.

### Power-cut safety
RedSea keeps no free map on disk (it is rebuilt from the directory at mount), so the on-disk state is just data, directory and superblock. Every change follows one order, so that a power cut at any moment leaves either the old or the new state:
- **New data never overwrites live data.** It always goes to a free extent; the low-space in-place overwrite was removed. Then comes a barrier.
- **Directory update:** the change is one sector, followed by a barrier before any freed space can be reused.
- **Deletes:** a delete writes two sectors with a barrier between them. A cut in between leaves the moved entry twice, byte-identical, and mount completes the delete.
- **Snapshots:** a snapshot is valid only while its manifest exists. Create writes the manifest last; delete removes it first. At boot, snapshot folders without a manifest (an interrupted create or delete) are removed. An interrupted restore leaves each file either restored or untouched.
- **Superblock:** mount corrects a file count left behind.
- **Barriers:** they are virtio `FLUSH` commands. The driver now negotiates `VIRTIO_BLK_F_FLUSH`, so the device may cache writes and RedSea orders them. Without the feature, the device works write-through.

### RedSea v4: a 16384-entry directory
v3 held 1024 directory entries in total, and every snapshot uses one per file. v4 has 16384 entries in a 4 MiB directory.
- **Migration:** v3 (and v2) volumes are migrated automatically on first mount with the same crash-safe recipe: the new directory goes to a free extent, then a barrier, then the single-sector superblock switch. It needs 4 MiB of contiguous free space.
- **Free slots:** they are normal now. A delete clears one slot (one atomic sector, nothing moves), new entries reuse the first free slot, and the in-memory index is the on-disk slot. Mount still repairs the identical duplicates an interrupted pre-v4 delete could leave.
- **Speed:** everything that compared all entries with each other now sorts instead (heapsort, O(n log n)): duplicate names and overlaps in fsck and at mount, the free map, and per-snapshot reference counts. The directory is read and written in 64 KiB chunks.
- **Snapshot operations in bulk:**
  - Creating one links by index, with one barrier before the manifest.
  - Deleting one removes the manifest first, then clears all its slots in a single pass. An extent is freed only when every entry referencing it is gone.
- **Measured under QEMU with 15,000 entries:**

  | Operation | Time |
  |---|---|
  | Boot | under 1 s |
  | Full fsck (every CRC) | 1.5 s |
  | Snapshot of 5000 files | 0.2–0.4 s |
  | Snapshot list | 0.2 s |
  | Snapshot delete | 0.1 s |


The tests that exercise RedSea through real use (`test_fs_model`, `test_crash`,
`test_redsea_v4`, `test_disk_stress`) drive it through WebDAV and snapshots,
so they live in `yesos-nas`.

## 6. DNS filter engine (module `dns`) — `rust/src/dns.rs`, `kernel/dnsblock.c`

A Pi-hole style filter: blocked names get `0.0.0.0` / `::` (other types: no
data), everything else is forwarded to an upstream on the LAN and cached. Used
by YesOS Security (to answer DNS it intercepts on the bridge) and by the core
self-test image (on UDP 53).

- **Lists:** hosts files (`0.0.0.0 domain`), one domain per line, or `||domain^`, kept in `SYS/DNSLIST/<name>.txt` (copy them onto the disk, e.g. with `tools/redsea_injector.py`, then `dns list add <name>`). Up to 8 lists. Each domain is a keyed SipHash value (8 bytes) in a sorted array; 100,000 domains load in about 0.3 s.
- **Rules:** a blocked domain blocks its subdomains; the allowlist always wins; personal block list; each list and the whole filter can be switched off; `dns test <domain>` says which rule applies.
- **Encrypted DNS:** `use-application-dns.net` gets NXDOMAIN (Firefox keeps the system DNS); an optional list blocks well-known DoH/DoT providers.
- **Upstream:** up to 4 servers on the LAN (never the Internet), primary first, a retry moves to the next. Random ID and source port per attempt; an answer is accepted only from the server asked, on that port, with that ID and question. EDNS clamped to 1232 bytes. SERVFAIL after 3 attempts. `dns upstream auto` follows the gateway.
- **Cache:** up to 4096 answers, TTLs honoured (max one day), negative answers cached with the SOA minimum (max one hour), the client's own spelling kept (0x20).
- **Abuse:** RFC 1918 clients only, 1000 queries per minute each (20,000 for queries intercepted from a router); malformed packets get FORMERR or are dropped, and are counted.
- **Privacy:** `dns log` shows the last queries, kept in RAM only (the last 1000); `dns log off` clears it and stops recording.

`python3 tools/test_dns.py` (55 checks, console-driven, with a fake upstream on
the host that records every forwarded query): forwarding, cache, negative
cache, 0x20, EDNS clamp, list formats and refusals, subdomains, A/AAAA/other
types, allowlist precedence, lists and filter on/off, canary, DoH list, forged
answers, dead upstream, failover, 334 malformed packets, `dns log`, a
100,000-domain list, persistence, the rate limit and fsck.

## 7. Console commands (core)

```text
Files       ls/dir [path]  cd  pwd  tree  cat  write <path> <text>  mkdir  rm
Storage     disk  disk cat|save|rm|verify <name>  disk free  disk bench  format ERASE-ALL
Check       fsck [quick]   (structure + every file's CRC)
Console     pin [status|set|change]  lock
Network     net  ping [ip]  net bench  net ip <a.b.c.d/nn> [gw <ip>] | default   firewall [status|audit]
Isolation   pmp  pmp test  cell  cell test  cell run <f.HQ> [n]  keyhart test  integrity
HolyQ       run <f.HQ>  jit <code>  jit bench|rvv|disasm <fn>   (console: full privileges)
System      sysinfo  mem  hardening  smp  uptime  tasks  ata  pci  clear  reboot  poweroff
Modules     vault [status|init|unlock|lock|passwd]   pkg [list|install|run|remove]
            dns [status|log|on|off|flush|test <d>|allow|block|unallow|unblock <d>|upstream <ip>...|auto|doh|list add|on|off|delete]
```

## 8. Honest limits

- The PMP does not stop the kernel from reading its own data and does not cover device DMA.
- Only virtio devices (QEMU) are supported; the Orange Pi RV2 still needs drivers for its real storage and network.
- No wall clock; times are uptime, read from the CLINT `mtime` counter (`python3 tools/test_timer.py` compares it with the host clock, idle and under load). Its rate is QEMU's 10 MHz: the boards' timebases are not handled yet.
- The RedSea directory holds 16384 entries in total.
- No performance benchmarks yet: QEMU does not model cycles, so they wait for real hardware.
- Without Zkr (e.g. JH7110) keys come from a weak source, and the system says so.

## 9. Support YesOS

YesOS is developed in the open and funded by donations. They pay for
development time and for real RISC-V boards, so the missing storage and
network drivers can be written and tested outside the emulator.

[Donate on Liberapay](https://liberapay.com/yesos-project/donate)

## 10. License
MIT. In memory of Terry A. Davis (1969–2018).

YesOS is inspired by his TempleOS (its HolyC became HolyQ here, and the RedSea
filesystem) and is not affiliated with it.
