# =============================================================================
# YesOS core. Products (yesos-nas, yesos-security, yesos-desktop) include this
# repository as the `core` submodule and build with core.mk. Here, `make`
# builds the core self-test image (core + every optional module, no product) and
# `make test` runs the core's own suites on it.
# =============================================================================
PRODUCT = selftest
CORE = .
CORE_MODULES = vault packages dns gfx lineedit
PRODUCT_C_SRCS = selftest/product_selftest.c
RUST_DIR = selftest/rust
DISK_MB = 64

include core.mk

run: $(ELF) yesos_disk.img
	qemu-system-riscv64 $(QEMU_CPU) $(QEMU_DISK) -kernel $(ELF) -nographic

TESTS = test_pmp test_cells test_integrity test_packages test_dns test_timer test_pci test_line_edit
test: $(ELF) yesos_disk.img
	@fail=0; for t in $(TESTS); do echo "== $$t"; python3 tools/$$t.py || fail=1; done; exit $$fail

.PHONY: run test
