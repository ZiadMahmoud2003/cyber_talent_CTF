#!/usr/bin/env python3
"""
CTF Crypto Challenge Template
==============================
Domain : Cryptography
Usage  : python solve.py [--target URL] [--file FILE] [--data DATA]
"""

import argparse
import hashlib
import base64
import binascii
import re
import struct
import itertools
import string
import os
import sys
from math import gcd

# ── Optional imports (install if needed) ──────────────────────────────
try:
    from Crypto.Cipher import AES, DES, PKCS1_OAEP
    from Crypto.PublicKey import RSA
    from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse, getPrime
    from Crypto.Util.Padding import pad, unpad
except ImportError:
    print("[!] pycryptodome not installed — run: pip install pycryptodome")

try:
    import requests
except ImportError:
    print("[!] requests not installed — run: pip install requests")

try:
    from sympy import factorint, nextprime, isprime
except ImportError:
    print("[!] sympy not installed — run: pip install sympy")

try:
    from pwn import *
except ImportError:
    print("[!] pwntools not installed — run: pip install pwntools")


# ══════════════════════════════════════════════════════════════════════
# CONFIGURATION — Fill these in during the competition
# ══════════════════════════════════════════════════════════════════════
TARGET_URL   = ""          # e.g. "http://challenge.ctf.com:1337"
TARGET_HOST  = ""          # e.g. "challenge.ctf.com"
TARGET_PORT  = 0           # e.g. 1337
FLAG_FORMAT  = r"FDC\{.*?\}"  # Adjust to match the CTF flag format


# ══════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════
def read_file(path: str) -> bytes:
    """Read a local file and return raw bytes."""
    with open(path, "rb") as f:
        return f.read()


def xor(data: bytes, key: bytes) -> bytes:
    """Repeating-key XOR."""
    return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))


def rot13(text: str) -> str:
    """Classic ROT13 substitution."""
    return text.translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
    ))


def brute_caesar(ciphertext: str):
    """Print all 26 Caesar-shift results."""
    for shift in range(26):
        decrypted = ""
        for ch in ciphertext:
            if ch.isalpha():
                base = ord("A") if ch.isupper() else ord("a")
                decrypted += chr((ord(ch) - base + shift) % 26 + base)
            else:
                decrypted += ch
        print(f"  shift {shift:>2}: {decrypted}")


def rsa_decrypt(c, d, n):
    """Textbook RSA decryption: m = c^d mod n."""
    m = pow(c, d, n)
    return long_to_bytes(m)


def find_flag(text: str) -> list:
    """Extract flags from text using the configured flag format."""
    return re.findall(FLAG_FORMAT, text)


# ══════════════════════════════════════════════════════════════════════
# SOLVE LOGIC — Implement your solution here
# ══════════════════════════════════════════════════════════════════════
def solve(args):
    print("[*] Starting Crypto solve …")

    # ── Load input data ───────────────────────────────────────────────
    if args.file:
        data = read_file(args.file)
        print(f"[+] Loaded {len(data)} bytes from {args.file}")
    elif args.data:
        data = args.data.encode()
    else:
        data = b""

    # ── Remote interaction (if needed) ────────────────────────────────
    if args.target:
        print(f"[*] Connecting to {args.target} …")
        # resp = requests.get(args.target)
        # print(resp.text)

    # ── TODO: Write your exploit / decode logic below ─────────────────
    #
    # Example RSA:
    #   n = 0x...
    #   e = 65537
    #   c = 0x...
    #   # factor n, compute d, decrypt …
    #
    # Example AES-ECB:
    #   key = b"????????????????"
    #   cipher = AES.new(key, AES.MODE_ECB)
    #   plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    #

    print("[*] Done.")


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Crypto CTF Solver")
    parser.add_argument("-t", "--target", help="Target URL or host:port")
    parser.add_argument("-f", "--file",   help="Path to local challenge file")
    parser.add_argument("-d", "--data",   help="Inline ciphertext / data string")
    args = parser.parse_args()
    solve(args)
