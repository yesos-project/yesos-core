#!/usr/bin/env python3
"""
RedSea-EML Disk Image Injector & Manager for YesOS 2.0
Allows formatting, listing, injecting, and synchronizing curated files into yesos_disk.img
"""

import sys
import os
import re
import struct
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

REDSEA_MAGIC_1 = 0x52454453  # "REDS"
REDSEA_MAGIC_2 = 0x454D4C32  # "EML2"

REDSEA_FLAG_USED        = 0x0001
REDSEA_FLAG_READONLY    = 0x0002
REDSEA_FLAG_BOOT_KERNEL = 0x0004
REDSEA_FLAG_DIR         = 0x0008

MBR_TEMPLATE = bytes([
    0xFA, 0x31, 0xC0, 0x8E, 0xD8, 0x8E, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0xFB, 0xBE, 0x4D, 0x7C,
    0xE8, 0x22, 0x00, 0x30, 0xE4, 0xB2, 0x80, 0xCD, 0x13, 0xBE, 0x3D, 0x7C, 0xB4, 0x42, 0xB2, 0x80,
    0xCD, 0x13, 0x72, 0x11, 0xBE, 0x81, 0x7C, 0xE8, 0x0B, 0x00, 0xE4, 0x92, 0x0C, 0x02, 0xE6, 0x92,
    0xFA, 0xEB, 0x00, 0xAC, 0x08, 0xC0, 0x74, 0x06, 0xB4, 0x0E, 0xCD, 0x10, 0xEB, 0xF5, 0xC3, 0x10,
    0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x59,
    0x65, 0x73, 0x4F, 0x53, 0x20, 0x32, 0x2E, 0x30, 0x20, 0x4D, 0x42, 0x52, 0x20, 0x42, 0x6F, 0x6F,
    0x74, 0x6C, 0x6F, 0x61, 0x64, 0x65, 0x72, 0x2E, 0x2E, 0x2E, 0x0D, 0x0A, 0x00, 0x4B, 0x65, 0x72,
    0x6E, 0x65, 0x6C, 0x20, 0x4C, 0x6F, 0x61, 0x64, 0x65, 0x64, 0x2E, 0x0D, 0x0A, 0x00, 0x00, 0x00
]) + b'\x00' * (510 - 78) + b'\x55\xAA'

def kernel_crc32(data: bytes) -> int:
    """CRC stored by the kernel: low 32 bits of its Barrett CRC64 (see redsea_fsck.py)."""
    from redsea_fsck import kernel_crc64
    return kernel_crc64(data) & 0xFFFFFFFF


def euler_log_crc(data: bytes) -> int:
    hash_val = 0x5A5A5A5A
    for b in data:
        hash_val = (((hash_val << 5) & 0xFFFFFFFF) ^ (hash_val >> 27) ^ b) & 0xFFFFFFFF
    return hash_val

SB_FMT = '<IIIIQQQQQQ32s416s'
# Directory entry layouts: v2 = 64 bytes / 32-byte names, v3 = 256 bytes / 224-byte names
ENTRY_LAYOUT = {2: (64, 32), 3: (256, 224), 4: (256, 224)}
V3_DIR_SECTORS = 512
V4_DIR_SECTORS = 8192     # 16384 entries


def read_superblock(f):
    f.seek(512)
    raw = f.read(512)
    if len(raw) < 512:
        raise ValueError("disk image too small")
    fields = struct.unpack(SB_FMT, raw)
    sb = dict(zip(["m1", "m2", "ver", "sec_sz", "total_sec", "root_lba", "root_sec", "data_lba",
                   "free_ptr", "total_files", "label", "res"], fields))
    if sb["m1"] != REDSEA_MAGIC_1 or sb["m2"] != REDSEA_MAGIC_2:
        raise ValueError("not a RedSea-EML volume")
    if sb["ver"] not in ENTRY_LAYOUT:
        raise ValueError(f"unsupported RedSea version {sb['ver']}")
    return sb


def write_superblock(f, sb):
    f.seek(512)
    f.write(struct.pack(SB_FMT, sb["m1"], sb["m2"], sb["ver"], sb["sec_sz"], sb["total_sec"], sb["root_lba"],
                        sb["root_sec"], sb["data_lba"], sb["free_ptr"], sb["total_files"], sb["label"], sb["res"]))


def read_entries(f, sb):
    size, name_len = ENTRY_LAYOUT[sb["ver"]]
    f.seek(sb["root_lba"] * 512)
    out = []
    for _ in range(sb["total_files"]):
        name_raw, start, cnt, bsz, flags, crc = struct.unpack(f"<{name_len}sQQQII", f.read(size))
        out.append({"name": name_raw.split(b"\x00")[0].decode("ascii", errors="ignore"),
                    "start": start, "count": cnt, "size": bsz, "flags": flags, "crc": crc})
    return out


def first_free_lba(sb, entries):
    """Allocates after every used sector (the kernel does not maintain free_lba_ptr)."""
    end = sb["data_lba"]
    if sb["root_lba"] >= sb["data_lba"]:                 # directory relocated by v2 -> v3 migration
        end = max(end, sb["root_lba"] + sb["root_sec"])
    for e in entries:
        if e["flags"] & REDSEA_FLAG_USED and e["count"]:
            end = max(end, e["start"] + e["count"])
    return end


def format_disk(disk_path, total_mb=256, label="YESOS_EML_ROOT"):
    total_bytes = total_mb * 1024 * 1024
    total_sec = total_bytes // 512
    print(f"Formatting '{disk_path}' ({total_mb} MB, {total_sec} sectors) with RedSea-EML v4...")
    with open(disk_path, 'wb') as f:
        f.seek(total_bytes - 1)
        f.write(b'\x00')
    with open(disk_path, 'r+b') as f:
        f.seek(0)
        f.write(MBR_TEMPLATE)
        root_dir_lba = 16
        data_area_lba = root_dir_lba + V4_DIR_SECTORS
        lbl_bytes = label.encode('ascii')[:31].ljust(32, b'\x00')
        write_superblock(f, {"m1": REDSEA_MAGIC_1, "m2": REDSEA_MAGIC_2, "ver": 4, "sec_sz": 512,
                             "total_sec": total_sec, "root_lba": root_dir_lba, "root_sec": V4_DIR_SECTORS,
                             "data_lba": data_area_lba, "free_ptr": data_area_lba, "total_files": 0,
                             "label": lbl_bytes, "res": b'\x00' * 416})
        f.seek(root_dir_lba * 512)
        f.write(b'\x00' * (V4_DIR_SECTORS * 512))
    kernel_stub = b"YESOS_2.0_KERNEL_CORE_RING0_LONGMODE\x00" + b"\x90" * (64 * 1024 - 37)
    inject_bytes(disk_path, kernel_stub, "KERNEL.BIN", flags=(REDSEA_FLAG_USED | REDSEA_FLAG_BOOT_KERNEL | REDSEA_FLAG_READONLY))
    print(f"✅ Formatted '{disk_path}' successfully with volume '{label}'.")


def list_files(disk_path):
    if not os.path.exists(disk_path):
        print(f"Error: Disk image '{disk_path}' not found.")
        return
    with open(disk_path, 'rb') as f:
        try:
            sb = read_superblock(f)
        except ValueError as e:
            print(f"Error: {e}")
            return
        entries = read_entries(f, sb)
    vol_name = sb["label"].split(b'\x00')[0].decode('ascii', errors='ignore')
    print(f"\n================ [ REDSEA-EML v{sb['ver']} DISK: '{vol_name}' ] ================")
    print(f"Total Sectors: {sb['total_sec']} ({sb['total_sec'] * 512 // (1024 * 1024)} MB) | Files: {sb['total_files']}")
    print("------------------------------------------------------------------")
    for e in entries:
        print(f"  {e['name']:<40} {e['size']:<12} LBA {e['start']:<10} {e['count']:<8} 0x{e['crc']:08X}")
    print("------------------------------------------------------------------\n")


def inject_bytes(disk_path, file_data: bytes, target_name: str, flags=REDSEA_FLAG_USED) -> bool:
    if not os.path.exists(disk_path):
        print(f"Error: Disk image '{disk_path}' not found.")
        return False
    target_name = target_name.upper().strip()
    with open(disk_path, 'r+b') as df:
        try:
            sb = read_superblock(df)
        except ValueError as e:
            print(f"Error: {e}")
            return False
        size, name_len = ENTRY_LAYOUT[sb["ver"]]
        if len(target_name) > name_len - 1:
            print(f"Error: name '{target_name}' longer than {name_len - 1} characters (RedSea v{sb['ver']}).")
            return False
        entries = read_entries(df, sb)
        slot = next((i for i, e in enumerate(entries) if e["name"] == target_name), len(entries))
        max_entries = (sb["root_sec"] * 512) // size
        if slot >= max_entries:
            print("Error: RedSea directory full.")
            return False

        sector_count = max(1, (len(file_data) + 511) // 512)
        target_lba = first_free_lba(sb, entries)
        if target_lba + sector_count > sb["total_sec"]:
            print("Error: disk image full.")
            return False
        df.seek(target_lba * 512)
        df.write(file_data + b'\x00' * (sector_count * 512 - len(file_data)))

        df.seek(sb["root_lba"] * 512 + slot * size)
        df.write(struct.pack(f"<{name_len}sQQQII", target_name.encode('ascii').ljust(name_len, b'\x00'),
                             target_lba, sector_count, len(file_data), flags, kernel_crc32(file_data)))
        if slot == len(entries):
            sb["total_files"] += 1
        sb["free_ptr"] = max(sb["free_ptr"], target_lba + sector_count)
        write_superblock(df, sb)
    return True

def inject_file(disk_path, host_file_path, target_name):
    if not os.path.exists(host_file_path):
        print(f"Error: Host file '{host_file_path}' not found.")
        return False
    with open(host_file_path, 'rb') as hf:
        data = hf.read()
    res = inject_bytes(disk_path, data, target_name)
    if res:
        print(f"✅ Injected '{target_name}' ({len(data)} bytes) into '{disk_path}'.")
    return res

def parse_curated_ramfs(ramfs_c_path):
    if not os.path.exists(ramfs_c_path):
        print(f"Error: '{ramfs_c_path}' not found.")
        return {}
    with open(ramfs_c_path, 'r') as f:
        code = f.read()

    files = {}
    # Name mapping for DEFAULT_xxx in ramfs.c
    mapping = {
        'README_TXT': 'README.TXT',
        'HELLO_HQ': 'HELLO.HQ',
        'NOTES_TXT': 'NOTES.TXT',
    }

    pattern = re.compile(r'static\s+const\s+char\*\s+DEFAULT_(\w+)\s*=\s*(.*?);\n\n', re.DOTALL)
    for var_name, raw_content in pattern.findall(code):
        if var_name in mapping:
            # Parse C string literals joined by newlines/spaces
            str_literals = re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', raw_content)
            unescaped_text = "".join(str_literals)
            unescaped_text = unescaped_text.replace('\\n', '\n').replace('\\t', '\t').replace('\\"', '"').replace('\\\\', '\\')
            files[mapping[var_name]] = unescaped_text.encode('utf-8')

    return files

def sync_curated(disk_path, repo_root="."):
    ramfs_path = os.path.join(repo_root, "kernel", "ramfs.c")
    curated_files = parse_curated_ramfs(ramfs_path)
    if not curated_files:
        print("Error: Could not parse curated files from ramfs.c")
        return False

    format_disk(disk_path, total_mb=256, label="YESOS_EML_ROOT")

    print("\n--- Deploying curated files ---")
    for dest_name, src_key in [("README.TXT", "README.TXT"), ("APPS/HELLO.HQ", "HELLO.HQ"),
                               ("HOME/NOTES.TXT", "NOTES.TXT")]:
        if src_key in curated_files:
            data = curated_files[src_key]
            inject_bytes(disk_path, data, dest_name)
            print(f"  + Injected {dest_name:<24} ({len(data)} bytes)")
        else:
            print(f"  - Missing {src_key} for {dest_name}")

    # Deploy applications from apps/ directory into /PKG/
    apps_dir = os.path.join(repo_root, "apps")
    if os.path.exists(apps_dir):
        print("\n--- Packing and Deploying Packages into /PKG/ ---")
        try:
            tools_dir = os.path.dirname(os.path.abspath(__file__))
            if tools_dir not in sys.path:
                sys.path.insert(0, tools_dir)
            import deploy_app
            for app_name in sorted(os.listdir(apps_dir)):
                app_path = os.path.join(apps_dir, app_name)
                if os.path.isdir(app_path):
                    ypk_data = deploy_app.pack_app_folder(app_path)
                    target_name = f"PKG/{app_name.upper()}.YPK"
                    inject_bytes(disk_path, ypk_data, target_name)
                    print(f"  + Injected {target_name:<24} ({len(ypk_data)} bytes)")
        except Exception as e:
            print(f"  ! Warning packaging apps: {e}")

    print("\n✅ All curated platform files synchronized successfully.")
    list_files(disk_path)
    return True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Usage: redsea_injector.py <disk.img> [list | inject <host_file> <target_name> | format | sync_curated]")
        sys.exit(1)

    disk = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else "list"

    if cmd == "list":
        list_files(disk)
    elif cmd == "inject":
        if len(sys.argv) < 5:
            print("Usage: redsea_injector.py <disk.img> inject <host_file> <target_name>")
            sys.exit(1)
        inject_file(disk, sys.argv[3], sys.argv[4])
    elif cmd == "format":
        format_disk(disk)
        list_files(disk)
    elif cmd == "sync_curated":
        sync_curated(disk)
    else:
        print(f"Unknown command '{cmd}'")
