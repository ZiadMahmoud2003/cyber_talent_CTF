#!/usr/bin/env python3
"""
CTF Forensics Template
========================
Domain : Forensics
Usage  : python solve.py [--target URL] [--file FILE] [--data DATA]
"""

import argparse
import re
import os
import sys
import hashlib
import base64
import binascii
import struct
import json
import zipfile
import gzip
import io

# ── Optional imports (install if needed) ──────────────────────────────
try:
    import requests
except ImportError:
    print("[!] requests not installed — run: pip install requests")

try:
    from pwn import *
except ImportError:
    print("[!] pwntools not installed — run: pip install pwntools")

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
except ImportError:
    print("[!] Pillow not installed — run: pip install Pillow")

try:
    from scapy.all import rdpcap, TCP, UDP, IP, Raw
except ImportError:
    print("[!] scapy not installed — run: pip install scapy")

try:
    import magic  # python-magic
except ImportError:
    print("[!] python-magic not installed — run: pip install python-magic")


# ══════════════════════════════════════════════════════════════════════
# CONFIGURATION — Fill these in during the competition
# ══════════════════════════════════════════════════════════════════════
TARGET_URL   = ""          # e.g. "http://challenge.ctf.com:8080/download"
FLAG_FORMAT  = r"FDC\{.*?\}"

# Common file signatures (magic bytes)
FILE_SIGNATURES = {
    b"\x89PNG\r\n\x1a\n":  "PNG",
    b"\xff\xd8\xff":       "JPEG",
    b"GIF87a":             "GIF87a",
    b"GIF89a":             "GIF89a",
    b"PK\x03\x04":        "ZIP/DOCX/APK",
    b"\x1f\x8b":          "GZIP",
    b"BM":                "BMP",
    b"\x7fELF":           "ELF",
    b"MZ":                "PE/EXE",
    b"%PDF":              "PDF",
    b"Rar!\x1a\x07":      "RAR",
    b"\xd0\xcf\x11\xe0":  "MS Office (OLE)",
    b"RIFF":              "RIFF (WAV/AVI)",
    b"SQLite format 3":   "SQLite",
}


# ══════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════
def read_file(path: str) -> bytes:
    """Read a local file and return raw bytes."""
    with open(path, "rb") as f:
        return f.read()


def identify_file(data: bytes) -> str:
    """Identify file type from magic bytes."""
    for sig, name in FILE_SIGNATURES.items():
        if data.startswith(sig):
            return name
    return "Unknown"


def hexdump(data: bytes, width: int = 16, limit: int = 256):
    """Pretty hex dump of the first `limit` bytes."""
    for i in range(0, min(len(data), limit), width):
        chunk = data[i:i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"  {i:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")
    if len(data) > limit:
        print(f"  … ({len(data) - limit} more bytes)")


def extract_strings(data: bytes, min_len: int = 4) -> list:
    """Extract printable ASCII strings from binary data."""
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    return [m.decode() for m in re.findall(pattern, data)]


def extract_exif(image_path: str) -> dict:
    """Extract EXIF metadata from an image file."""
    img = Image.open(image_path)
    exif_data = img._getexif()
    if not exif_data:
        print("[-] No EXIF data found.")
        return {}
    readable = {}
    for tag_id, value in exif_data.items():
        tag_name = TAGS.get(tag_id, tag_id)
        readable[tag_name] = value
        print(f"  {tag_name}: {value}")
    return readable


def lsb_extract(image_path: str, num_bits: int = 1) -> bytes:
    """Extract least-significant bits from image pixels (basic stego)."""
    img = Image.open(image_path).convert("RGB")
    pixels = list(img.getdata())
    bits = ""
    for pixel in pixels:
        for channel in pixel:
            bits += str(channel & ((1 << num_bits) - 1))
    # Convert bits to bytes
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        if len(byte) == 8:
            result.append(int(byte, 2))
    return bytes(result)


def carve_files(data: bytes, output_dir: str = "./carved"):
    """Attempt to carve embedded files based on magic bytes."""
    os.makedirs(output_dir, exist_ok=True)
    found = []
    for sig, name in FILE_SIGNATURES.items():
        offset = 0
        while True:
            idx = data.find(sig, offset)
            if idx == -1:
                break
            print(f"[+] Found {name} at offset 0x{idx:x}")
            found.append((idx, name))
            offset = idx + 1
    return found


def analyze_pcap(pcap_path: str):
    """Basic PCAP analysis — extract TCP streams and look for flags."""
    packets = rdpcap(pcap_path)
    print(f"[+] Loaded {len(packets)} packets from {pcap_path}")

    streams = {}
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            stream_id = (
                pkt[IP].src, pkt[TCP].sport,
                pkt[IP].dst, pkt[TCP].dport,
            )
            streams.setdefault(stream_id, b"")
            streams[stream_id] += pkt[Raw].load

    print(f"[+] Found {len(streams)} TCP streams")
    for stream_id, payload in streams.items():
        flags = find_flag(payload.decode(errors="replace"))
        if flags:
            print(f"[+] FLAG in stream {stream_id}: {flags}")
        readable = payload.decode(errors="replace")[:200]
        if readable.strip():
            src, sp, dst, dp = stream_id
            print(f"  [{src}:{sp} → {dst}:{dp}] {readable}")

    return streams


def analyze_zip(zip_path: str):
    """List and inspect contents of a ZIP archive."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        print(f"[+] ZIP contents of {zip_path}:")
        for info in zf.infolist():
            print(f"    {info.filename}  ({info.file_size} bytes, "
                  f"compressed: {info.compress_size} bytes)")
        return zf.namelist()


def find_flag(text: str) -> list:
    """Extract flags from text using the configured flag format."""
    return re.findall(FLAG_FORMAT, text)


# ══════════════════════════════════════════════════════════════════════
# SOLVE LOGIC — Implement your solution here
# ══════════════════════════════════════════════════════════════════════
def solve(args):
    print("[*] Starting Forensics solve …")

    # ── Load file ─────────────────────────────────────────────────────
    if args.file:
        data = read_file(args.file)
        print(f"[+] Loaded {len(data)} bytes from {args.file}")

        # Identify file type
        file_type = identify_file(data)
        print(f"[+] File type: {file_type}")

        # Hex dump header
        print("[+] Header hex dump:")
        hexdump(data, limit=128)

        # Extract strings and scan for flag
        strings = extract_strings(data)
        flags_in_strings = []
        for s in strings:
            f = find_flag(s)
            if f:
                flags_in_strings.extend(f)
        if flags_in_strings:
            print(f"[+] FLAG found in strings: {flags_in_strings}")

    elif args.target:
        print(f"[*] Downloading from {args.target} …")
        resp = requests.get(args.target)
        data = resp.content
        print(f"[+] Downloaded {len(data)} bytes")
    else:
        data = b""

    # ── TODO: Write your forensics analysis logic below ───────────────
    #
    # Example: PCAP analysis
    #   streams = analyze_pcap(args.file)
    #
    # Example: Image steganography (LSB)
    #   hidden = lsb_extract(args.file, num_bits=1)
    #   print(hidden[:100])
    #
    # Example: EXIF metadata
    #   extract_exif(args.file)
    #
    # Example: File carving
    #   carve_files(data, output_dir="./carved")
    #
    # Example: ZIP analysis
    #   analyze_zip(args.file)
    #

    print("[*] Done.")


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Forensics CTF Solver")
    parser.add_argument("-t", "--target", help="Target URL to download challenge file")
    parser.add_argument("-f", "--file",   help="Path to local challenge file")
    parser.add_argument("-d", "--data",   help="Inline data string")
    args = parser.parse_args()
    solve(args)
