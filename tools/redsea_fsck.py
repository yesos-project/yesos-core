#!/usr/bin/env python3
"""
Host-side RedSea v3/v4 consistency check (same rules as the kernel's `fsck`).

Usage: python3 tools/redsea_fsck.py <image> [--quick]
Exit status 0 when clean, 1 when errors were found.

Checks: superblock geometry, every directory entry (name, bounds, size vs
sectors), duplicate names, overlapping extents (identical extents shared by
snapshots are allowed), and, unless --quick, every file's data against its
CRC (the kernel's Barrett CRC64, low 32 bits, or the legacy host checksum).
The free map is not stored on disk (the kernel rebuilds it at mount), so the
host check reports used and free space instead.
"""
import struct
import sys

M64 = (1 << 64) - 1
POLY_LO, MU_LO = 0x42F0E1EBA9EA3693, 0x578D29D06CC4F872
MAGIC1, MAGIC2 = 0x52454453, 0x454D4C32
F_USED, F_READONLY, F_DIR = 0x1, 0x2, 0x8


def _clmul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a <<= 1
        b >>= 1
    return r


def _reduce128(t_hi, t_lo):
    """Port of barrett_poly_reduce_128 (kernel/barrett_poly.c)."""
    q = t_hi ^ (_clmul(t_hi, MU_LO) >> 64)
    qp = _clmul(q, POLY_LO)
    r_lo = t_lo ^ (qp & M64)
    r_hi = t_hi ^ (q ^ (qp >> 64))
    if r_hi:
        q2 = r_hi ^ (_clmul(r_hi, MU_LO) >> 64)
        r_lo ^= _clmul(q2, POLY_LO) & M64
    return r_lo & M64


def _kernel_crc64_slow(data: bytes) -> int:
    """Direct port of barrett_crc64_sector (reference for the tables below)."""
    if not data:
        return 0
    crc = M64
    n = len(data) // 8
    for i in range(n):
        crc = _reduce128(crc ^ int.from_bytes(data[i * 8:i * 8 + 8], "little"), 0)
    tail = data[n * 8:]
    if tail:
        crc = _reduce128(crc ^ int.from_bytes(tail, "little"), 0)
    return crc ^ M64


# Each kernel step is crc' = (crc ^ w) * x^64 mod P, linear in (crc ^ w): split
# the 64-bit value into bytes and precompute byte_k * x^(8k) * x^64 mod P.
_TABLES = [[_reduce128(b << (8 * k), 0) for b in range(256)] for k in range(8)]


def kernel_crc64(data: bytes) -> int:
    """The CRC the kernel stores (low 32 bits), table-driven."""
    if not data:
        return 0
    t0, t1, t2, t3, t4, t5, t6, t7 = _TABLES
    crc = M64
    n = len(data) // 8
    mv = memoryview(data)
    for i in range(0, n * 8, 8):
        v = crc ^ int.from_bytes(mv[i:i + 8], "little")
        crc = (t0[v & 255] ^ t1[(v >> 8) & 255] ^ t2[(v >> 16) & 255] ^ t3[(v >> 24) & 255] ^
               t4[(v >> 32) & 255] ^ t5[(v >> 40) & 255] ^ t6[(v >> 48) & 255] ^ t7[v >> 56])
    tail = bytes(mv[n * 8:])
    if tail:
        v = crc ^ int.from_bytes(tail, "little")
        crc = 0
        for k in range(8):
            crc ^= _TABLES[k][(v >> (8 * k)) & 255]
    return crc ^ M64


def legacy_crc(data: bytes) -> int:
    h = 0x5A5A5A5A
    for b in data:
        h = (((h << 5) & 0xFFFFFFFF) ^ (h >> 27) ^ b) & 0xFFFFFFFF
    return h


def read_entries(f):
    f.seek(512)
    sb = f.read(512)
    m1, m2, ver, _ss, total, root_lba, root_sec, data_lba, _free_ptr, files = struct.unpack("<IIIIQQQQQQ", sb[:64])
    if (m1, m2) != (MAGIC1, MAGIC2):
        raise ValueError("not a RedSea volume")
    f.seek(root_lba * 512)
    raw = f.read(root_sec * 512)
    entries = []
    for slot in range(len(raw) // 256):
        e = raw[slot * 256:(slot + 1) * 256]
        flags = struct.unpack("<I", e[248:252])[0]
        if not flags & F_USED:
            continue
        name_raw = e[:224]
        lba, sec, size = struct.unpack("<QQQ", e[224:248])
        crc = struct.unpack("<I", e[252:256])[0]
        entries.append({"slot": slot, "name_raw": name_raw, "name": name_raw.split(b"\0")[0].decode(errors="replace"),
                        "lba": lba, "sec": sec, "size": size, "flags": flags, "crc": crc})
    geo = {"version": ver, "total": total, "root_lba": root_lba, "root_sec": root_sec,
           "data_lba": data_lba, "total_files": files}
    return geo, entries


def fsck(image, check_data=True):
    r = {"errors": [], "warnings": [], "files": 0, "dirs": 0, "shared": 0,
         "crc_ok": 0, "crc_legacy": 0, "crc_bad": 0, "legacy_backup": 0}
    with open(image, "rb") as f:
        geo, ents = read_entries(f)
        if {3: 512, 4: 8192}.get(geo["version"]) != geo["root_sec"] or geo["data_lba"] >= geo["total"]:
            r["errors"].append(f"superblock: version {geo['version']}, directory {geo['root_sec']} sectors")
        if geo["total_files"] != len(ents):
            r["warnings"].append(f"superblock says {geo['total_files']} files, directory has {len(ents)}")
        if geo["version"] == 3 and [e["slot"] for e in ents] != list(range(len(ents))):
            r["warnings"].append("v3 directory has empty slots (v4 allows them; the kernel migrates)")
        used = []
        if geo["root_lba"] >= geo["data_lba"]:
            used.append((geo["root_lba"], geo["root_lba"] + geo["root_sec"]))
        for e in ents:
            n = e["name"]
            if b"\0" not in e["name_raw"] or not n:
                r["errors"].append(f"slot {e['slot']}: bad name")
                continue
            is_dir = bool(e["flags"] & F_DIR)
            r["dirs" if is_dir else "files"] += 1
            if e["sec"] == 0 or e["lba"] < geo["data_lba"] or e["lba"] + e["sec"] > geo["total"]:
                r["errors"].append(f"'{n}': extent outside the data area (LBA {e['lba']}, {e['sec']} sectors)")
                continue
            if not is_dir and e["sec"] < max(1, (e["size"] + 511) // 512):
                r["errors"].append(f"'{n}': {e['sec']} sectors cannot hold {e['size']} bytes")
            if n.startswith("backup/") and not is_dir:
                if not n.startswith("backup/snap-"):
                    r["legacy_backup"] += 1
                elif not e["flags"] & F_READONLY:
                    r["errors"].append(f"'{n}': snapshot file not read-only")
            used.append((e["lba"], e["lba"] + e["sec"]))
        names = [e["name"] for e in ents]
        for dup in sorted({x for x in names if names.count(x) > 1}):
            r["errors"].append(f"'{dup}': duplicate entry")
        by_start = sorted(ents, key=lambda e: e["lba"])
        for i, a in enumerate(by_start):
            for b in by_start[i + 1:]:
                if b["lba"] >= a["lba"] + a["sec"]:
                    break
                same = (a["lba"], a["sec"], a["size"]) == (b["lba"], b["sec"], b["size"]) and not ((a["flags"] | b["flags"]) & F_DIR)
                if same:
                    r["shared"] += 1
                else:
                    r["errors"].append(f"'{a['name']}' and '{b['name']}' overlap at LBA {b['lba']}")
        used.sort()
        used_sec, cur = 0, 0
        for s0, s1 in used:
            s0 = max(s0, cur)
            if s1 > s0:
                used_sec += s1 - s0
            cur = max(cur, s1)
        r["used_sectors"] = used_sec
        r["free_sectors"] = geo["total"] - geo["data_lba"] - used_sec
        if check_data:
            for e in ents:
                if e["flags"] & F_DIR or e["lba"] + e["sec"] > geo["total"]:
                    continue
                f.seek(e["lba"] * 512)
                data = f.read(e["size"])
                if len(data) != e["size"]:
                    r["errors"].append(f"'{e['name']}': cannot read its data")
                elif e["size"] == 0 or kernel_crc64(data) & 0xFFFFFFFF == e["crc"]:
                    r["crc_ok"] += 1
                elif legacy_crc(data) == e["crc"]:
                    r["crc_legacy"] += 1
                else:
                    r["crc_bad"] += 1
                    r["errors"].append(f"'{e['name']}': data does not match its CRC")
    return r


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    r = fsck(sys.argv[1], "--quick" not in sys.argv)
    for w in r["warnings"]:
        print("  warn :", w)
    for e in r["errors"]:
        print("  ERROR:", e)
    print(f"{'CLEAN' if not r['errors'] else 'PROBLEMS FOUND'}: {len(r['errors'])} error(s), {len(r['warnings'])} warning(s); "
          f"{r['files']} files, {r['dirs']} dirs, {r['shared']} shared extents, {r['legacy_backup']} legacy /backup file(s); "
          f"CRC {r['crc_ok']} ok + {r['crc_legacy']} legacy, {r['crc_bad']} bad; "
          f"{r['used_sectors']} sectors used, {r['free_sectors']} free")
    sys.exit(1 if r["errors"] else 0)


if __name__ == "__main__":
    main()
