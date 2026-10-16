#!/usr/bin/env python3
"""
Line editor test: the console's line editing and history (shell/shell.c),
driven over the serial port with the escape sequences a terminal sends.
Checks the line the shell receives (its "Unknown command" line shows it
exactly), the exact echo bytes (printing and '\\b' only), UTF-8 characters
moved over and deleted whole, history (up, down, the line being typed kept,
16 entries, no repeats in a row) and that hidden input (a vault passphrase)
is neither editable nor stored in history. Non-zero exit status on failure.
"""
import os
import re
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import yesos_harness as harness  # noqa: E402

failures = []
UP, DOWN, RIGHT, LEFT = "\x1b[A", "\x1b[B", "\x1b[C", "\x1b[D"
HOME, END, DELETE = "\x1b[H", "\x1b[F", "\x1b[3~"
HOME2, END2 = "\x1b[1~", "\x1b[4~"           # the other forms terminals send
BS = "\x7f"


def check(cond, label):
    print(("  PASS  " if cond else "  FAIL  ") + label)
    if not cond:
        failures.append(label)


def raw(vm):
    with vm.lock:
        return bytes(vm.buf)


def keys(vm, s):
    """Send keys without Enter; an escape sequence goes in one write."""
    i = 0
    while i < len(s):
        if s[i] == "\x1b":
            j = i + 2
            while not (0x40 <= ord(s[j]) <= 0x7E):
                j += 1
            chunk = s[i:j + 1]
        else:
            chunk = s[i]
        vm.p.stdin.write(chunk.encode())
        vm.p.stdin.flush()
        time.sleep(0.05)
        i += len(chunk)


def line(vm, s):
    """Type s, press Enter; returns (what the shell received, the echo bytes)."""
    start = len(raw(vm))
    mark = len(vm.output())
    keys(vm, s + "\r")
    vm.wait_for("YesOS [", 10, mark)
    time.sleep(0.2)
    out = raw(vm)[start:]
    echo = out.split(b"\n", 1)[0]
    m = re.search(r"Unknown command: '(.*)'\. Type", out.decode(errors="replace"))
    return (m.group(1) if m else None), echo, out.decode(errors="replace")


def main():
    tmpdir = tempfile.mkdtemp(prefix="yesos_edit_")
    disk = os.path.join(tmpdir, "disk.img")
    shutil.copyfile(harness.SRC_DISK, disk)
    vm = harness.YesOS(disk, 40000 + os.getpid() % 20000)
    try:
        check(vm.wait_for("YesOS [", 90), "system boots")

        got, echo, _ = line(vm, "qq abc" + LEFT + LEFT + "X")
        check(got == "qq aXbc", f"left twice, insert: {got!r}")
        check(echo == b"qq abc\b\bXbc\b\b", f"echo is printing and backspaces only: {echo!r}")

        got, _, _ = line(vm, "bc" + HOME + "qq a" + END + "d")
        check(got == "qq abcd", f"Home, End: {got!r}")
        got, _, _ = line(vm, "c" + HOME2 + "qq ab" + END2 + "d")
        check(got == "qq abcd", f"ESC [1~ and ESC [4~: {got!r}")

        got, echo, _ = line(vm, "qq abcd" + LEFT + LEFT + DELETE)
        check(got == "qq abd", f"Delete under the cursor: {got!r}")
        check(echo == b"qq abcd\b\bd \b\b", f"Delete echo: {echo!r}")

        got, _, _ = line(vm, "qq abcd" + LEFT + LEFT + BS)
        check(got == "qq acd", f"backspace in the middle: {got!r}")
        got, _, _ = line(vm, "qq ab" + RIGHT + RIGHT + "c" + DELETE)
        check(got == "qq abc", f"right and Delete at the end do nothing: {got!r}")

        got, echo, _ = line(vm, "qq ñandú" + LEFT + LEFT + BS + LEFT + "é")
        check(got == "qq ñéadú", f"UTF-8: moved over and deleted whole: {got!r}")
        check(echo.count(b"\b") == 2 + 4 + 1 + 3, f"one backspace per character moved: {echo!r}")

        # history
        _, _, out = line(vm, "pwd")
        line(vm, "qq one")
        line(vm, "qq one")                                # a repeat in a row is stored once
        got, _, out = line(vm, UP + UP)
        check(got is None and "\n/" in out, "up twice: the command before the repeat (pwd) runs again")
        got, _, _ = line(vm, UP + UP)
        check(got == "qq one", f"pwd went to the top of history: {got!r}")
        got, _, _ = line(vm, "qq draft" + UP + UP + DOWN + DOWN)
        check(got == "qq draft", f"down back to the line being typed: {got!r}")
        got, _, _ = line(vm, UP + LEFT + LEFT + LEFT + "X")
        check(got == "qq drXaft", f"a recalled line can be edited: {got!r}")
        got, _, _ = line(vm, DOWN + "qq new")
        check(got == "qq new", f"down at the bottom does nothing: {got!r}")

        for i in range(20):
            line(vm, f"qq h{i}")
        got, _, _ = line(vm, UP * 25)
        check(got == "qq h4", f"16 entries kept, up stops at the oldest: {got!r}")

        # hidden input: a vault passphrase
        m = vm.send("vault init", 1)
        check("New vault passphrase" in vm.since(m), "vault init asks for a hidden passphrase")
        start = len(raw(vm))
        keys(vm, "pw-one" + UP + LEFT + HOME + "\r")
        time.sleep(0.5)
        echo = raw(vm)[start:].split(b"\n", 1)[0]
        check(echo == b"******", f"hidden: one '*' per character, editing keys ignored: {echo!r}")
        mark = len(vm.output())
        keys(vm, "pw-one\r")
        vm.wait_for("YesOS [", 30, mark)
        got, _, out = line(vm, UP + "")
        check("pw-one" not in out and "vault init" in out.split("\n", 1)[0],
              f"the passphrase is not in history: up shows {out.splitlines()[0]!r}")
        check("FATAL" not in vm.output() and "RISC-V EXCEPTION" not in vm.output(), "no kernel faults")
    finally:
        vm.stop()
    shutil.rmtree(tmpdir, ignore_errors=True)

    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed")


if __name__ == "__main__":
    main()
