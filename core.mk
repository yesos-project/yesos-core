# =============================================================================
# YesOS core build rules - included by every product's Makefile.
#
# The product sets, before `include core/core.mk`:
#   PRODUCT          its name (nas, security, desktop, selftest)
#   PRODUCT_C_SRCS   its C files (paths relative to the product root)
#   CORE_MODULES     optional core modules it needs: vault packages dns
#   CORE             path of the core (default: core, the git submodule)
#   RUST_DIR         its Rust crate (default: rust), a staticlib named "yesos"
#                    that depends on $(CORE)/rust
#
# Result: yesos.elf, linked from the core, the chosen modules and the product
# only, then proven (PMP layout, key-hart vector check, no floating point,
# image hash). An image
# never contains code of a module or product that was not selected.
# =============================================================================

CORE ?= core
RUST_DIR ?= rust
ELF = yesos.elf
OBJ_DIR = build

CC = clang --target=riscv64-unknown-elf
CFLAGS = -march=rv64gcv_zba_zbb_zbc_zbs -mabi=lp64d -mcmodel=medany -ffreestanding -fno-stack-protector -fno-pie -nostdlib -O2 -Wall -Wextra -fno-vectorize -fno-slp-vectorize -I$(CORE)/include -Iinclude
AS = clang --target=riscv64-unknown-elf
ASFLAGS = -march=rv64gcv_zba_zbb_zbc_zbs -mabi=lp64d -mcmodel=medany -c -I$(CORE)/include
LD = ld.lld
LINKER_SCRIPT = $(CORE)/linker_rv64.ld
LDFLAGS = -m elf64lriscv --nostdlib -static

CARGO ?= cargo
RUST_TARGET = riscv64gc-unknown-none-elf
RUST_LIB = $(RUST_DIR)/target/$(RUST_TARGET)/release/libyesos.a
export PATH := $(HOME)/.cargo/bin:$(PATH)

# Developer-only: the UNAUTHENTICATED remote shell / HolyQ eval / package
# install commands (products that have the NAS command protocol). Never on a
# device attached to a real network.   make DEV_REMOTE=1 run
ifeq ($(DEV_REMOTE),1)
CFLAGS += -DYESOS_DEV_REMOTE
endif

# ---- core sources -------------------------------------------------------------
CORE_ASM_SRCS = $(addprefix $(CORE)/, boot/boot_rv64.S kernel/trap_rv64.S kernel/task_asm_rv64.S \
                kernel/cell_rt.S kernel/keyhart_vkey.S)

CORE_C_SRCS = $(addprefix $(CORE)/, \
         kernel/main.c kernel/kprintf.c kernel/memory.c kernel/pmp.c kernel/smp.c \
         kernel/trap.c kernel/task.c kernel/lz4.c kernel/barrett_poly.c \
         kernel/ramfs.c kernel/redsea_eml.c kernel/vfs.c \
         kernel/holyq_jit.c kernel/holyq_rv64_emit.c kernel/holyq_rv64_compiler.c \
         kernel/firewall.c kernel/security_pin.c kernel/netcfg.c \
         kernel/entropy.c kernel/cell.c kernel/keyhart.c \
         drivers/serial.c drivers/earcon.c drivers/timer.c drivers/ata.c drivers/pci.c drivers/virtio_blk.c drivers/virtio_net.c \
         graphics/font_data.c graphics/font.c shell/shell.c)

# Optional core modules
CORE_vault_SRCS    = $(CORE)/kernel/vault.c $(CORE)/kernel/vault_shell.c   # encrypted /vault, key in the key hart
CORE_packages_SRCS = $(CORE)/kernel/app_registry.c $(CORE)/kernel/ypkg.c   # .ypk apps run in PMP cells
CORE_dns_SRCS      = $(CORE)/kernel/dnsblock.c                              # DNS filter (engine in Rust)

C_SRCS = $(CORE_C_SRCS) $(foreach mod,$(CORE_MODULES),$(CORE_$(mod)_SRCS)) $(PRODUCT_C_SRCS)
CFLAGS += $(foreach mod,$(CORE_MODULES),-DYESOS_WITH_$(shell echo $(mod) | tr a-z A-Z))

OBJS = $(patsubst %.S,$(OBJ_DIR)/%.o,$(CORE_ASM_SRCS)) $(patsubst %.c,$(OBJ_DIR)/%.o,$(C_SRCS))
INCLUDES = $(wildcard $(CORE)/include/*.h include/*.h)

# ---- proofs -------------------------------------------------------------------
# Build-time PMP proof (Z3). Run `make prover-setup` once. A kernel whose PMP
# layout cannot be proven is deleted, never left behind.
PMP_PYTHON ?= $(CORE)/tools/.venv/bin/python
define PMP_PROVE
	@if [ -x $(PMP_PYTHON) ]; then \
		$(PMP_PYTHON) $(CORE)/tools/pmp_prover.py $(1) --self-test || { rm -f $(1); exit 1; }; \
	else \
		echo "WARNING: Z3 prover not installed (make prover-setup); $(1) boots with runtime PMP verification only"; \
	fi
	@python3 $(CORE)/tools/check_keyhart_vector.py $(1) || { rm -f $(1); exit 1; }
	@python3 $(CORE)/tools/check_no_fp.py $(1) || { rm -f $(1); exit 1; }
	@python3 $(CORE)/tools/image_hash.py $(1) || { rm -f $(1); exit 1; }
endef

# ---- rules --------------------------------------------------------------------
all: $(ELF)

RUST_SRCS = $(shell find $(RUST_DIR)/src $(CORE)/rust/src -type f 2>/dev/null) $(RUST_DIR)/Cargo.toml $(CORE)/rust/Cargo.toml

$(RUST_LIB): $(RUST_SRCS)
	@echo "Compiling the Rust part of YesOS $(PRODUCT)..."
	$(CARGO) build --manifest-path $(RUST_DIR)/Cargo.toml --target $(RUST_TARGET) --release
	@touch $@   # cargo leaves the library alone when only unused sources changed

$(OBJ_DIR)/%.o: %.S
	@mkdir -p $(dir $@)
	$(AS) $(ASFLAGS) $< -o $@

# The key hart keeps the vault key in vector registers: its C code must never
# be compiled with vector instructions (clang uses RVV even for struct copies).
$(OBJ_DIR)/$(CORE)/kernel/keyhart.o: CFLAGS += -march=rv64gc_zba_zbb_zbc_zbs

$(OBJ_DIR)/%.o: %.c $(INCLUDES)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(ELF): $(OBJS) $(RUST_LIB) $(LINKER_SCRIPT)
	$(LD) -T $(LINKER_SCRIPT) $(LDFLAGS) -o $(ELF) $(OBJS) $(RUST_LIB)
	$(call PMP_PROVE,$(ELF))
	@echo "=================================================="
	@echo "✅ YesOS $(PRODUCT) build complete: $(ELF)"
	@echo "=================================================="

# Boards (same objects, board linker script, raw binary for U-Boot)
yesos_orangepi_rv2.elf: $(OBJS) $(RUST_LIB) $(CORE)/linker_orangepi_rv2.ld
	$(LD) -T $(CORE)/linker_orangepi_rv2.ld $(LDFLAGS) -o $@ $(OBJS) $(RUST_LIB)
	$(call PMP_PROVE,$@)

yesos_jh7110.elf: $(OBJS) $(RUST_LIB) $(CORE)/linker_jh7110.ld
	$(LD) -T $(CORE)/linker_jh7110.ld $(LDFLAGS) -o $@ $(OBJS) $(RUST_LIB)
	$(call PMP_PROVE,$@)

%.bin: %.elf
	llvm-objcopy -O binary $< $@

orangepi-rv2: yesos_orangepi_rv2.bin
jh7110: yesos_jh7110.bin

# ---- QEMU ---------------------------------------------------------------------
QEMU_CPU = -machine virt -smp 4 -cpu rv64,v=true,vext_spec=v1.0,vlen=128,zba=true,zbb=true,zbc=true,zbs=true,zkr=true -m 512M -bios none
QEMU_DISK = -drive file=yesos_disk.img,if=none,format=raw,id=hd0 -device virtio-blk-pci,drive=hd0,id=blk0

# A fresh, empty RedSea disk (a product with its own disk recipe sets CUSTOM_DISK = 1).
DISK_MB ?= 64
ifneq ($(CUSTOM_DISK),1)
yesos_disk.img:
	python3 -c "import sys; sys.path.insert(0, '$(CORE)/tools'); import redsea_injector as r; r.format_disk('yesos_disk.img', total_mb=$(DISK_MB))"
endif

prover-setup:
	python3 -m venv $(CORE)/tools/.venv
	$(CORE)/tools/.venv/bin/pip install z3-solver

clean:
	rm -rf $(OBJ_DIR) $(ELF) yesos_orangepi_rv2.elf yesos_orangepi_rv2.bin yesos_jh7110.elf yesos_jh7110.bin
	$(CARGO) clean --manifest-path $(RUST_DIR)/Cargo.toml 2>/dev/null || true

.PHONY: all prover-setup clean orangepi-rv2 jh7110
