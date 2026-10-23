# YesOS on a board (Orange Pi RV2, JH7110)

**Status: not ready.** YesOS runs today under QEMU only. Its block and network
drivers are virtio; the boards' real storage (SD/eMMC, NVMe) and Ethernet
controllers have no driver yet, so an image booted on a board reaches the
console but has neither disk nor network. Porting those drivers is the next
step once the hardware is available.

**The JH7110 image does not boot at all.** Its U74 cores have no vector
extension and no Zbc, but the image is built with both: clang emits vector
instructions for struct copies throughout the core, the trap handler saves
the vector CSRs, the key hart keeps the vault key in vector registers and
RedSea's checksum uses `clmul`. In QEMU with a U74-like CPU (no V, no Zbc) the
boot stops after its first line. A JH7110 build needs its own `-march`, a
trap handler without vector CSRs, another home for the vault key and a
scalar checksum.

## Building a board image

Every product (`yesos-nas`, `yesos-security`, `yesos-desktop`) can build one,
from the same objects as `yesos.elf` with the board's linker script:

```bash
make orangepi-rv2     # yesos_orangepi_rv2.elf + .bin (load address 0x01400000)
make jh7110           # yesos_jh7110.elf + .bin (load address 0x40200000)
```

The PMP proof, the key-hart vector check and the image hash run on board
images too. The Orange Pi RV2 layout needs 9 PMP entries; the X60 core's entry
count still has to be measured on the board.

| | Orange Pi RV2 | StarFive VisionFive 2 (JH7110) |
| :--- | :--- | :--- |
| SoC | SpacemiT Ky X1, 8 cores | JH7110, 4 x SiFive U74 |
| Vector (RVV 1.0) | yes | no: the current image does not boot (see above) |
| Ethernet | 2 x Gigabit | 2 x Gigabit |
| Zkr (hardware entropy) | to be checked | no: keys from a weak source (YesOS warns) |
| U-Boot load address | `0x01400000` | `0x40200000` |
| CLINT and timebase | to do: `include/clint.h` has QEMU's (`0x02000000`, 10 MHz); upstream Linux puts the K1 CLINT at `0xE4000000` | to do: same, values not checked yet |

## Booting with U-Boot

### From a microSD card
1. Format a MicroSD card with an initial FAT32 boot partition.
2. Copy `yesos_orangepi_rv2.bin` (or `yesos_jh7110.bin`) to the boot partition.
3. Connect a USB-UART adapter (3.3V) to the board's serial debug pins (115200 baud, 8N1).
4. Power on the board and interrupt U-Boot countdown (press any key).
5. Load and execute:
   ```text
   # For Orange Pi RV2:
   U-Boot # fatload mmc 1:1 0x01400000 yesos_orangepi_rv2.bin
   U-Boot # go 0x01400000

   # For StarFive JH7110:
   StarFive # fatload mmc 1:1 0x40200000 yesos_jh7110.bin
   StarFive # go 0x40200000
   ```

### Over TFTP
```text
# Orange Pi RV2:
U-Boot # tftpboot 0x01400000 yesos_orangepi_rv2.bin
U-Boot # go 0x01400000
```

---

## Where each product goes

```text
fiber ─► [ONT] ─► [YesOS Security] ─► [router] ─► the house
                                                    └── [YesOS NAS]  (one cable to a LAN port)
```

See each product's README.
