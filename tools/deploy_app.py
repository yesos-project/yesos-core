#!/usr/bin/env python3
"""
=============================================================================
YesOS 2.0 - Sacred Package (.YPK) Builder & Hot Deployment Tool
Enables local application packing and direct GitHub repository deployment over
VirtIO-Net / UDP 5555 into RedSea-EML and Holy Dock.
=============================================================================
"""

import sys
import os
import struct
import socket
import time
import argparse
import tarfile
import io
import urllib.request

YPKG_MAGIC = 0x59504B47  # "YPKG"
YPKG_VERSION = 1
YPKG_MAX_FILES = 32

REMOTE_CMD_MAGIC = 0x59455343  # "YESC"
REMOTE_RESP_MAGIC = 0x59455352  # "YESR"

CMD_TYPE_PKG_BEGIN = 10
CMD_TYPE_PKG_CHUNK = 11
CMD_TYPE_PKG_FINISH = 12

def lz4_compress_block(data: bytes) -> bytes:
    """Pure-Python LZ4 streaming block compressor (Standard LZ4 format)."""
    out = bytearray()
    n = len(data)
    if n < 15:
        out.append(n << 4)
        out.extend(data)
    else:
        out.append(0xF0)
        rem = n - 15
        while rem >= 255:
            out.append(255)
            rem -= 255
        out.append(rem)
        out.extend(data)
    return bytes(out)

def crc32_euler(data: bytes) -> int:
    import zlib
    return zlib.crc32(data) & 0xFFFFFFFF

def pack_app_folder(folder_path: str) -> bytes:
    if not os.path.exists(folder_path):
        raise FileNotFoundError(f"Folder '{folder_path}' does not exist.")

    # Read manifest if present
    manifest_path = os.path.join(folder_path, "APP.INFO")
    info = {
        "NAME": os.path.basename(os.path.abspath(folder_path)),
        "ID": f"org.yesos.{os.path.basename(os.path.abspath(folder_path)).lower()}",
        "EXEC": "MAIN.HQ",
        "ICON": "PKG",
        "VERSION": "1.0.0",
        "AUTHOR": "Holy Community"
    }

    if os.path.exists(manifest_path):
        with open(manifest_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    k, v = line.split("=", 1)
                    info[k.strip().upper()] = v.strip()

    # Collect files
    files_to_pack = []
    for root, dirs, files in os.walk(folder_path):
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), folder_path)
            # Use upper-case normalized name for TempleOS / YesOS consistency
            files_to_pack.append((rel.replace("/", "_").upper(), os.path.join(root, f)))

    if not files_to_pack:
        raise ValueError(f"No files found in '{folder_path}' to pack.")

    if len(files_to_pack) > YPKG_MAX_FILES:
        files_to_pack = files_to_pack[:YPKG_MAX_FILES]

    uncompressed_data = bytearray()
    file_headers = []

    for rel_name, abs_path in files_to_pack:
        with open(abs_path, "rb") as f:
            content = f.read()
        offset = len(uncompressed_data)
        size = len(content)
        uncompressed_data.extend(content)

        name_bytes = rel_name.encode("ascii")[:31]
        name_padded = name_bytes + b"\x00" * (32 - len(name_bytes))
        file_headers.append((name_padded, offset, size, 0))

    # Compress payload with LZ4
    raw_payload = bytes(uncompressed_data)
    compressed_payload = lz4_compress_block(raw_payload)

    # Pack Main Header
    app_name = info["NAME"].encode("ascii")[:31]
    app_name_pad = app_name + b"\x00" * (32 - len(app_name))

    bundle_id = info["ID"].encode("ascii")[:31]
    bundle_id_pad = bundle_id + b"\x00" * (32 - len(bundle_id))

    exec_entry = info["EXEC"].encode("ascii")[:31]
    exec_entry_pad = exec_entry + b"\x00" * (32 - len(exec_entry))

    icon_name = info["ICON"].encode("ascii")[:31]
    icon_name_pad = icon_name + b"\x00" * (32 - len(icon_name))

    ver_str = info["VERSION"].encode("ascii")[:15]
    ver_str_pad = ver_str + b"\x00" * (16 - len(ver_str))

    author = info["AUTHOR"].encode("ascii")[:31]
    author_pad = author + b"\x00" * (32 - len(author))

    file_count = len(file_headers)
    total_uncompressed = len(raw_payload)
    compressed_sz = len(compressed_payload)
    crc = crc32_euler(raw_payload)

    main_hdr = struct.pack(
        "<II32s32s32s32s16s32sIIII",
        YPKG_MAGIC,
        YPKG_VERSION,
        app_name_pad,
        bundle_id_pad,
        exec_entry_pad,
        icon_name_pad,
        ver_str_pad,
        author_pad,
        file_count,
        total_uncompressed,
        compressed_sz,
        crc
    )

    # Pack 32 file entries
    file_table = bytearray()
    for fh in file_headers:
        file_table.extend(struct.pack("<32sIII", fh[0], fh[1], fh[2], fh[3]))

    # Pad remaining file entries to 32
    empty_entry = struct.pack("<32sIII", b"\x00" * 32, 0, 0, 0)
    for _ in range(32 - len(file_headers)):
        file_table.extend(empty_entry)

    ypk_bytes = main_hdr + bytes(file_table) + compressed_payload
    print(f"📦 Packed '{info['NAME']}' into .YPK ({len(ypk_bytes)} bytes, {file_count} files, LZ4: {compressed_sz}B)")
    return ypk_bytes

def send_package_to_yesos(ypk_bytes: bytes, target_ip="127.0.0.1", target_port=5555, verbose=True):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    seq = 100

    def send_cmd(cmd_type, payload_bytes=b""):
        nonlocal seq
        p_len = len(payload_bytes)
        p_padded = payload_bytes[:256] + b"\x00" * max(0, 256 - p_len)
        pkt = struct.pack("<IHHI256s", REMOTE_CMD_MAGIC, seq, cmd_type, p_len, p_padded)
        seq = (seq + 1) & 0xFFFF
        sock.sendto(pkt, (target_ip, target_port))

    if verbose:
        print(f"🚀 Deploying package ({len(ypk_bytes)} bytes) over VirtIO-Net to {target_ip}:{target_port}...")

    # 1. Send PKG_BEGIN
    sz_buf = struct.pack("<I", len(ypk_bytes))
    send_cmd(CMD_TYPE_PKG_BEGIN, sz_buf)
    time.sleep(0.05)

    # 2. Stream Chunks (240 bytes per chunk)
    chunk_size = 240
    total_chunks = (len(ypk_bytes) + chunk_size - 1) // chunk_size

    for i in range(total_chunks):
        chunk = ypk_bytes[i * chunk_size:(i + 1) * chunk_size]
        send_cmd(CMD_TYPE_PKG_CHUNK, chunk)
        time.sleep(0.005)  # 5ms throttle for jitter-free reception

    # 3. Send PKG_FINISH
    send_cmd(CMD_TYPE_PKG_FINISH, b"INSTALL")
    time.sleep(0.1)

    # Wait for confirmation ACK
    try:
        data, addr = sock.recvfrom(1024)
        if len(data) >= 268:
            m, s, status, rlen, resp_raw = struct.unpack("<IHHI256s", data[:268])
            msg = resp_raw[:rlen].decode("utf-8", errors="ignore")
            if verbose:
                print(f"✅ YesOS Response: {msg}")
            return True
    except socket.timeout:
        if verbose:
            print("⚠️ Timeout waiting for ACK (package likely applied).")
        return True

    return True

def deploy_from_github(github_url: str, target_ip="127.0.0.1", target_port=5555):
    print(f"🌐 Fetching repository from GitHub: {github_url} ...")
    
    # Clean URL
    url = github_url.rstrip("/")
    if not url.endswith("/tarball/main") and not url.endswith("/tarball/master"):
        parts = url.split("github.com/")
        if len(parts) == 2:
            repo_path = parts[1]
            tarball_url = f"https://api.github.com/repos/{repo_path}/tarball/main"
        else:
            tarball_url = url
    else:
        tarball_url = url

    headers = {"User-Agent": "YesOS-App-Deployer/2.0"}
    req = urllib.request.Request(tarball_url, headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            tar_data = resp.read()
    except Exception as e:
        print(f"❌ Failed to download from GitHub: {e}")
        return False

    print(f"⬇️ Downloaded {len(tar_data)} bytes tarball from GitHub. Unpacking in memory...")

    # Extract in-memory tarball
    tar = tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:*")
    temp_dir = f"/tmp/yesos_gh_{int(time.time())}"
    os.makedirs(temp_dir, exist_ok=True)
    tar.extractall(path=temp_dir)
    tar.close()

    # Find inner folder
    subdirs = os.listdir(temp_dir)
    app_root = os.path.join(temp_dir, subdirs[0]) if len(subdirs) == 1 else temp_dir

    ypk_bytes = pack_app_folder(app_root)
    return send_package_to_yesos(ypk_bytes, target_ip, target_port)

def main():
    parser = argparse.ArgumentParser(description="YesOS Sacred Application Deployment Tool")
    parser.add_argument("--build", help="App directory to package into .YPK")
    parser.add_argument("-o", "--output", help="Output .YPK file path")
    parser.add_argument("--send", help="Send existing .YPK file to YesOS")
    parser.add_argument("--deploy", help="Build and send app folder to YesOS directly")
    parser.add_argument("--github", help="Download from GitHub URL and deploy to YesOS")
    parser.add_argument("--ip", default="127.0.0.1", help="YesOS target IP (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5555, help="YesOS target UDP port (default: 5555)")

    args = parser.parse_args()

    if args.build:
        out_file = args.output if args.output else f"{os.path.basename(os.path.abspath(args.build))}.ypk"
        ypk = pack_app_folder(args.build)
        with open(out_file, "wb") as f:
            f.write(ypk)
        print(f"✅ Saved package to '{out_file}'")

    elif args.send:
        with open(args.send, "rb") as f:
            ypk = f.read()
        send_package_to_yesos(ypk, args.ip, args.port)

    elif args.deploy:
        ypk = pack_app_folder(args.deploy)
        send_package_to_yesos(ypk, args.ip, args.port)

    elif args.github:
        deploy_from_github(args.github, args.ip, args.port)

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
