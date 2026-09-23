#!/usr/bin/env python3
"""
CTF Reverse Engineering Template
==================================
Domain : Reverse Engineering
Usage  : python solve.py [--target URL] [--file FILE] [--data DATA]
"""

import argparse
import struct
import re
import os
import sys
import hashlib
import base64
import binascii
import string
import itertools

# ── Optional imports (install if needed) ──────────────────────────────
try:
    from pwn import *
except ImportError:
    print("[!] pwntools not installed — run: pip install pwntools")

try:
    import requests
except ImportError:
    print("[!] requests not installed — run: pip install requests")

try:
    import capstone
except ImportError:
    print("[!] capstone not installed — run: pip install capstone")

try:
    import angr
    try:
        from angr.rustylib import claripy
    except ImportError:
        import claripy
except ImportError:
    print("[!] angr not installed — run: pip install angr")

try:
    from z3 import *
except ImportError:
    print("[!] z3-solver not installed — run: pip install z3-solver")


# ══════════════════════════════════════════════════════════════════════
# CONFIGURATION — Fill these in during the competition
# ══════════════════════════════════════════════════════════════════════
TARGET_URL   = ""          # e.g. "http://challenge.ctf.com:1337"
BINARY_PATH  = ""          # e.g. "./challenge_binary"
FLAG_FORMAT  = r"FDC\{.*?\}"


# ══════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════
def read_file(path: str) -> bytes:
    """Read a local file and return raw bytes."""
    with open(path, "rb") as f:
        return f.read()


def hexdump_bytes(data: bytes, width: int = 16):
    """Pretty-print a hex dump of raw bytes."""
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")


def extract_strings(data: bytes, min_len: int = 4) -> list:
    """Extract printable ASCII strings from binary data."""
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    return [m.decode() for m in re.findall(pattern, data)]


def xor(data: bytes, key: bytes) -> bytes:
    """Repeating-key XOR."""
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))


def patch_bytes(data: bytearray, offset: int, patch: bytes) -> bytearray:
    """Patch bytes in a binary at a given offset."""
    data[offset:offset + len(patch)] = patch
    return data


def disassemble_x86(code: bytes, base_addr: int = 0x0, bits: int = 64):
    """Disassemble x86/x64 machine code using Capstone."""
    mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    for insn in md.disasm(code, base_addr):
        print(f"  0x{insn.address:08x}:  {insn.mnemonic:<8} {insn.op_str}")


def angr_find_flag(binary: str, find_addr: int, avoid_addrs: list = None):
    """Use angr to symbolically execute to a target address."""
    proj = angr.Project(binary, auto_load_libs=False)
    state = proj.factory.entry_state()
    simgr = proj.factory.simgr(state)
    simgr.explore(find=find_addr, avoid=avoid_addrs or [])
    if simgr.found:
        found_state = simgr.found[0]
        print(f"[+] Input: {found_state.posix.dumps(0)}")
        print(f"[+] Output: {found_state.posix.dumps(1)}")
        return found_state
    else:
        print("[-] No solution found by angr.")
        return None


def find_flag(text: str) -> list:
    """Extract flags from text using the configured flag format."""
    return re.findall(FLAG_FORMAT, text)


# ══════════════════════════════════════════════════════════════════════
# SOLVE LOGIC — Implement your solution here
# ══════════════════════════════════════════════════════════════════════
def solve(args):
    print("[*] Starting Reverse solve …")

    # ── Load binary / data ────────────────────────────────────────────
    binary_path = args.file or BINARY_PATH
    if binary_path and os.path.isfile(binary_path):
        data = read_file(binary_path)
        print(f"[+] Loaded {len(data)} bytes from {binary_path}")
        print(f"[+] Extracted strings:")
        for s in extract_strings(data)[:20]:
            print(f"      {s}")
    elif args.data:
        data = args.data.encode()
    else:
        data = b""

    # ── TODO: Write your reverse-engineering logic below ──────────────
    #
    # Example: Disassemble a code section
    #   code_section = data[0x1000:0x1100]
    #   disassemble_x86(code_section, base_addr=0x401000, bits=64)
    #
    # Example: angr symbolic execution
    #   angr_find_flag(binary_path, find_addr=0x401234, avoid_addrs=[0x401300])
    #
    # Example: z3 constraint solving
    #   s = Solver()
    #   flag = [BitVec(f"f{i}", 8) for i in range(32)]
    #   s.add(flag[0] == ord('F'))
    #   ...
    #

    print("[*] Done.")


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Reverse Engineering CTF Solver")
    parser.add_argument("-t", "--target", help="Target URL or host:port")
    parser.add_argument("-f", "--file",   help="Path to binary / challenge file")
    parser.add_argument("-d", "--data",   help="Inline data string")
    args = parser.parse_args()
    solve(args)
