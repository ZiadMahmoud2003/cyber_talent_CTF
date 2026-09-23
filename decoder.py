#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║               CTF Multi-Decoder Utility  -  FDC Edition             ║
║                                                                      ║
║  Reads 'cipher.txt' and brute-forces every common encoding /        ║
║  cipher automatically. Pure deterministic Python - no AI.            ║
║                                                                      ║
║  Usage:                                                              ║
║      python decoder.py                   (reads ./cipher.txt)        ║
║      python decoder.py -f path/to/file   (reads custom file)        ║
║      python decoder.py -i "raw string"   (inline input)             ║
║      python decoder.py --flag FDC        (custom flag prefix)       ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import argparse
import base64
import binascii
import codecs
import hashlib
import os
import re
import string
import sys
import textwrap
from itertools import cycle


# ══════════════════════════════════════════════════════════════════════
# TERMINAL FORMATTING
# ══════════════════════════════════════════════════════════════════════
class Colors:
    """ANSI color codes (disabled automatically on non-TTY output)."""
    ENABLED = sys.stdout.isatty()

    RESET   = "\033[0m"   if ENABLED else ""
    BOLD    = "\033[1m"    if ENABLED else ""
    DIM     = "\033[2m"    if ENABLED else ""
    CYAN    = "\033[96m"   if ENABLED else ""
    GREEN   = "\033[92m"   if ENABLED else ""
    YELLOW  = "\033[93m"   if ENABLED else ""
    RED     = "\033[91m"   if ENABLED else ""
    MAGENTA = "\033[95m"   if ENABLED else ""
    WHITE   = "\033[97m"   if ENABLED else ""
    BG_GREEN = "\033[42m"  if ENABLED else ""


C = Colors

BANNER = rf"""
{C.CYAN}{C.BOLD}
   ____  _____ ____ ___  ____  _____ ____
  |  _ \| ____/ ___/ _ \|  _ \| ____|  _ \
  | | | |  _|| |  | | | | | | |  _| | |_) |
  | |_| | |__| |__| |_| | |_| | |___|  _ <
  |____/|_____\____\___/|____/|_____|_| \_\
{C.RESET}{C.DIM}  CTF Multi-Decoder Utility - Pure Deterministic Python{C.RESET}
"""

LINE_W = 72


def header(title: str):
    """Print a section header."""
    print()
    print(f"{C.CYAN}{C.BOLD}{'=' * LINE_W}")
    print(f"  {title}")
    print(f"{'=' * LINE_W}{C.RESET}")


def sub_header(title: str):
    """Print a subsection header."""
    print(f"\n{C.YELLOW}{C.BOLD}  -- {title} {'-' * max(1, LINE_W - len(title) - 6)}{C.RESET}")


def result_line(label: str, value: str, highlight: bool = False):
    """Print a single result row."""
    # Truncate very long output for readability
    display = value if len(value) <= 200 else value[:200] + " ..."
    display = display.replace("\n", "\\n").replace("\r", "\\r")

    if highlight:
        print(f"  {C.BG_GREEN}{C.BOLD} [*] {C.RESET} "
              f"{C.GREEN}{C.BOLD}{label:<22}{C.RESET}  {C.WHITE}{display}{C.RESET}")
    else:
        print(f"      {C.DIM}{label:<22}{C.RESET}  {display}")


def flag_found(flag: str):
    """Celebrate a flag match."""
    print(f"\n  {C.BG_GREEN}{C.BOLD}  >>> FLAG FOUND: {flag}  {C.RESET}\n")


# ══════════════════════════════════════════════════════════════════════
# ANALYSIS HELPERS
# ══════════════════════════════════════════════════════════════════════
def printable_ratio(data: bytes) -> float:
    """Return the fraction of bytes that are printable ASCII (0.0-1.0)."""
    if not data:
        return 0.0
    printable = sum(1 for b in data if 0x20 <= b <= 0x7E)
    return printable / len(data)


def is_interesting(text: str, min_ratio: float = 0.75) -> bool:
    """Heuristic: is this decoded output worth showing?"""
    if not text:
        return False
    return printable_ratio(text.encode("utf-8", errors="replace")) >= min_ratio


def check_flag(text: str, flag_prefix: str) -> list:
    """Search for CTF flags in a string."""
    pattern = re.escape(flag_prefix) + r"\{.*?\}"
    return re.findall(pattern, text, re.IGNORECASE)


# ══════════════════════════════════════════════════════════════════════
# DECODERS
# ══════════════════════════════════════════════════════════════════════

# ─── Base Encodings ───────────────────────────────────────────────────

def try_base64_decode(data: str) -> str | None:
    """Standard Base64 decoding (RFC 4648)."""
    try:
        # Pad if necessary
        padded = data.strip() + "=" * (-len(data.strip()) % 4)
        decoded = base64.b64decode(padded, validate=True)
        text = decoded.decode("utf-8", errors="replace")
        return text if is_interesting(text) else None
    except Exception:
        return None


def try_base64url_decode(data: str) -> str | None:
    """URL-safe Base64 decoding (RFC 4648 §5)."""
    try:
        padded = data.strip() + "=" * (-len(data.strip()) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        text = decoded.decode("utf-8", errors="replace")
        return text if is_interesting(text) else None
    except Exception:
        return None


def try_base32_decode(data: str) -> str | None:
    """Base32 decoding (RFC 4648)."""
    try:
        cleaned = data.strip().upper().replace(" ", "")
        padded = cleaned + "=" * (-len(cleaned) % 8)
        decoded = base64.b32decode(padded)
        text = decoded.decode("utf-8", errors="replace")
        return text if is_interesting(text) else None
    except Exception:
        return None


def try_base16_decode(data: str) -> str | None:
    """Base16 (uppercase hex) decoding."""
    try:
        cleaned = data.strip().upper().replace(" ", "")
        decoded = base64.b16decode(cleaned)
        text = decoded.decode("utf-8", errors="replace")
        return text if is_interesting(text) else None
    except Exception:
        return None


def try_base85_decode(data: str) -> str | None:
    """Ascii85 / Base85 decoding."""
    try:
        decoded = base64.b85decode(data.strip())
        text = decoded.decode("utf-8", errors="replace")
        return text if is_interesting(text) else None
    except Exception:
        return None


def try_ascii85_decode(data: str) -> str | None:
    """Adobe Ascii85 decoding (with <~ ~> wrappers or without)."""
    try:
        cleaned = data.strip()
        if cleaned.startswith("<~") and cleaned.endswith("~>"):
            cleaned = cleaned[2:-2]
        decoded = base64.a85decode(cleaned)
        text = decoded.decode("utf-8", errors="replace")
        return text if is_interesting(text) else None
    except Exception:
        return None


# ─── Hex Decoding ─────────────────────────────────────────────────────

def try_hex_decode(data: str) -> str | None:
    """Hex string → bytes → text."""
    try:
        cleaned = data.strip().replace(" ", "").replace("0x", "").replace(",", "")
        # Remove any \x notation
        cleaned = cleaned.replace("\\x", "")
        if len(cleaned) % 2 != 0:
            return None
        decoded = bytes.fromhex(cleaned)
        text = decoded.decode("utf-8", errors="replace")
        return text if is_interesting(text) else None
    except Exception:
        return None


# ─── Binary Decoding ─────────────────────────────────────────────────

def try_binary_decode(data: str) -> str | None:
    """Binary string (space- or non-space-separated) → text."""
    try:
        cleaned = data.strip().replace(" ", "")
        # Must be all 0s and 1s
        if not re.fullmatch(r"[01]+", cleaned):
            return None
        if len(cleaned) % 8 != 0:
            return None
        chars = [chr(int(cleaned[i:i + 8], 2)) for i in range(0, len(cleaned), 8)]
        text = "".join(chars)
        return text if is_interesting(text) else None
    except Exception:
        return None


# ─── Octal Decoding ──────────────────────────────────────────────────

def try_octal_decode(data: str) -> str | None:
    """Octal string (space-separated) → text."""
    try:
        parts = data.strip().split()
        if not all(re.fullmatch(r"[0-7]+", p) for p in parts):
            return None
        if len(parts) < 2:
            return None
        chars = [chr(int(p, 8)) for p in parts]
        text = "".join(chars)
        return text if is_interesting(text) else None
    except Exception:
        return None


# ─── Decimal Decoding ────────────────────────────────────────────────

def try_decimal_decode(data: str) -> str | None:
    """Space-separated decimal ASCII values → text."""
    try:
        parts = data.strip().split()
        if not all(p.isdigit() for p in parts):
            return None
        if len(parts) < 2:
            return None
        values = [int(p) for p in parts]
        if not all(0 <= v <= 127 for v in values):
            return None
        text = "".join(chr(v) for v in values)
        return text if is_interesting(text) else None
    except Exception:
        return None


# ─── ROT13 ───────────────────────────────────────────────────────────

def rot13_decode(data: str) -> str:
    """Apply ROT13."""
    return codecs.decode(data, "rot_13")


# ─── Caesar Cipher (all 26 shifts) ───────────────────────────────────

def caesar_shift(text: str, shift: int) -> str:
    """Shift each letter by `shift` positions (A-Z wrap)."""
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


def caesar_all_shifts(data: str) -> list[tuple[int, str]]:
    """Return all 26 Caesar-shift results."""
    return [(shift, caesar_shift(data, shift)) for shift in range(26)]


# ─── Atbash Cipher ───────────────────────────────────────────────────

def atbash_decode(data: str) -> str:
    """Atbash: A↔Z, B↔Y, etc."""
    result = []
    for ch in data:
        if ch.isalpha():
            if ch.isupper():
                result.append(chr(ord("Z") - (ord(ch) - ord("A"))))
            else:
                result.append(chr(ord("z") - (ord(ch) - ord("a"))))
        else:
            result.append(ch)
    return "".join(result)


# ─── Vigenère Brute-Force (common short keys) ────────────────────────

def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """Decrypt Vigenère cipher with a given key."""
    result = []
    key_cycle = cycle(key.upper())
    for ch in ciphertext:
        if ch.isalpha():
            shift = ord(next(key_cycle)) - ord("A")
            base = ord("A") if ch.isupper() else ord("a")
            result.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)


# ─── XOR Single-Byte ─────────────────────────────────────────────────

def xor_single_byte(data: bytes, key: int) -> bytes:
    """XOR every byte with a single key byte."""
    return bytes(b ^ key for b in data)


def xor_brute_force(data: bytes) -> list[tuple[int, str, float]]:
    """Try all 256 single-byte XOR keys. Return (key, text, score)."""
    results = []
    for key in range(1, 256):  # Skip 0 (identity)
        decoded = xor_single_byte(data, key)
        text = decoded.decode("utf-8", errors="replace")
        score = printable_ratio(decoded)
        if score >= 0.75:
            results.append((key, text, score))
    # Sort by printability score descending
    results.sort(key=lambda x: x[2], reverse=True)
    return results


# ─── URL Decoding ─────────────────────────────────────────────────────

def try_url_decode(data: str) -> str | None:
    """Percent-encoded URL decoding."""
    try:
        from urllib.parse import unquote
        decoded = unquote(data.strip())
        if decoded != data.strip():
            return decoded
        return None
    except Exception:
        return None


# ─── Unicode Escape Decoding ─────────────────────────────────────────

def try_unicode_escape(data: str) -> str | None:
    """Decode \\uXXXX and \\xXX escape sequences."""
    try:
        decoded = data.encode("utf-8").decode("unicode_escape")
        if decoded != data and is_interesting(decoded):
            return decoded
        return None
    except Exception:
        return None


# ─── Morse Code ──────────────────────────────────────────────────────

MORSE_TABLE = {
    ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
    "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
    "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
    ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
    "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
    "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
    "...--": "3", "....-": "4", ".....": "5", "-....": "6",
    "--...": "7", "---..": "8", "----.": "9",
}


def try_morse_decode(data: str) -> str | None:
    """Decode Morse code (dots/dashes separated by spaces, words by '/')."""
    try:
        # Check if input looks like Morse
        cleaned = data.strip()
        if not re.fullmatch(r"[\.\-\s/]+", cleaned):
            return None
        words = cleaned.split("/")
        decoded_words = []
        for word in words:
            letters = word.strip().split()
            decoded_word = ""
            for letter in letters:
                if letter in MORSE_TABLE:
                    decoded_word += MORSE_TABLE[letter]
                else:
                    return None  # Invalid Morse character
            decoded_words.append(decoded_word)
        text = " ".join(decoded_words)
        return text if len(text) > 0 else None
    except Exception:
        return None


# ─── Reversed String ─────────────────────────────────────────────────

def reverse_string(data: str) -> str:
    """Simple string reversal."""
    return data.strip()[::-1]


# ─── Rail Fence Cipher ───────────────────────────────────────────────

def rail_fence_decrypt(ciphertext: str, rails: int) -> str:
    """Decrypt a Rail Fence cipher with a given number of rails."""
    if rails < 2 or rails >= len(ciphertext):
        return ""
    n = len(ciphertext)
    pattern = [0] * n
    idx = 0
    for rail in range(rails):
        if rail == 0:
            step1 = 2 * (rails - 1)
            step2 = step1
        elif rail == rails - 1:
            step1 = 2 * (rails - 1)
            step2 = step1
        else:
            step1 = 2 * (rails - 1 - rail)
            step2 = 2 * rail
        i = rail
        toggle = True
        while i < n:
            pattern[i] = idx
            idx += 1
            i += step1 if toggle else step2
            toggle = not toggle
    result = [""] * n
    for i, p in enumerate(pattern):
        result[p] = ciphertext[i]
    return "".join(result)


# ─── Hash Identification ─────────────────────────────────────────────

def identify_hash(data: str) -> list[str]:
    """Identify potential hash types by length and character set."""
    cleaned = data.strip().lower()
    if not re.fullmatch(r"[0-9a-f]+", cleaned):
        return []
    length_map = {
        32:  ["MD5", "NTLM"],
        40:  ["SHA-1", "MySQL5"],
        56:  ["SHA-224"],
        64:  ["SHA-256", "SHA3-256"],
        96:  ["SHA-384", "SHA3-384"],
        128: ["SHA-512", "SHA3-512"],
    }
    return length_map.get(len(cleaned), [f"Unknown hash ({len(cleaned)} hex chars)"])


# ══════════════════════════════════════════════════════════════════════
# MAIN DECODER PIPELINE
# ══════════════════════════════════════════════════════════════════════
def run_all_decoders(raw_input: str, flag_prefix: str = "FDC"):
    """Run every decoder against the input and print results."""
    data = raw_input.strip()
    data_bytes = data.encode("utf-8", errors="replace")
    all_flags = []

    def scan_and_print(label: str, text: str | None, highlight_if_interesting: bool = True):
        """Print a result line and check for flags."""
        if text is None:
            return
        flags = check_flag(text, flag_prefix)
        if flags:
            all_flags.extend(flags)
            result_line(label, text, highlight=True)
            for f in flags:
                flag_found(f)
        elif highlight_if_interesting and is_interesting(text):
            result_line(label, text, highlight=False)

    # ── Input Summary ─────────────────────────────────────────────────
    header("INPUT SUMMARY")
    print(f"  {C.DIM}Length      :{C.RESET}  {len(data)} characters / {len(data_bytes)} bytes")
    print(f"  {C.DIM}Printable % :{C.RESET}  {printable_ratio(data_bytes) * 100:.1f}%")
    preview = data[:120].replace("\n", "\\n")
    if len(data) > 120:
        preview += " ..."
    print(f"  {C.DIM}Preview     :{C.RESET}  {preview}")

    # Hash identification
    hash_types = identify_hash(data)
    if hash_types:
        print(f"  {C.MAGENTA}Hash match  :{C.RESET}  {', '.join(hash_types)}")

    # ── Base Encodings ────────────────────────────────────────────────
    header("BASE ENCODINGS")

    sub_header("Base64 (standard)")
    scan_and_print("base64", try_base64_decode(data))

    sub_header("Base64 (URL-safe)")
    scan_and_print("base64url", try_base64url_decode(data))

    sub_header("Base32")
    scan_and_print("base32", try_base32_decode(data))

    sub_header("Base16 (hex)")
    scan_and_print("base16", try_base16_decode(data))

    sub_header("Base85")
    scan_and_print("base85", try_base85_decode(data))

    sub_header("Ascii85")
    scan_and_print("ascii85", try_ascii85_decode(data))

    # ── Hex / Binary / Octal / Decimal ────────────────────────────────
    header("NUMERIC ENCODINGS")

    sub_header("Hexadecimal")
    scan_and_print("hex", try_hex_decode(data))

    sub_header("Binary (8-bit groups)")
    scan_and_print("binary", try_binary_decode(data))

    sub_header("Octal (space-separated)")
    scan_and_print("octal", try_octal_decode(data))

    sub_header("Decimal ASCII (space-separated)")
    scan_and_print("decimal", try_decimal_decode(data))

    # ── Text Encodings ────────────────────────────────────────────────
    header("TEXT ENCODINGS")

    sub_header("URL percent-encoding")
    scan_and_print("url-decode", try_url_decode(data))

    sub_header("Unicode escape sequences")
    scan_and_print("unicode-escape", try_unicode_escape(data))

    sub_header("Morse code")
    scan_and_print("morse", try_morse_decode(data))

    # ── Substitution Ciphers ──────────────────────────────────────────
    header("SUBSTITUTION CIPHERS")

    sub_header("ROT13")
    r13 = rot13_decode(data)
    scan_and_print("rot13", r13)

    sub_header("Atbash")
    scan_and_print("atbash", atbash_decode(data))

    sub_header("Caesar Cipher - All 26 Shifts")
    shifts = caesar_all_shifts(data)
    for shift, text in shifts:
        if shift == 0:
            continue  # Skip identity (shift 0 = original)
        label = f"shift-{shift:>2}"
        flags = check_flag(text, flag_prefix)
        if flags:
            all_flags.extend(flags)
            result_line(label, text, highlight=True)
            for f in flags:
                flag_found(f)
        else:
            # Only print shifts 1-25; dim to reduce noise
            result_line(label, text, highlight=False)

    # ── Reversed String ───────────────────────────────────────────────
    header("STRING MANIPULATION")

    sub_header("Reversed")
    rev = reverse_string(data)
    scan_and_print("reversed", rev)

    # Also try base64-decoding the reversed string
    rev_b64 = try_base64_decode(rev)
    if rev_b64:
        scan_and_print("reversed→base64", rev_b64)

    # ── Rail Fence Cipher ─────────────────────────────────────────────
    sub_header("Rail Fence (2-6 rails)")
    for rails in range(2, 7):
        try:
            rf = rail_fence_decrypt(data, rails)
            label = f"rails-{rails}"
            scan_and_print(label, rf)
        except Exception:
            pass

    # ── XOR Single-Byte Brute-Force ───────────────────────────────────
    header("XOR SINGLE-BYTE BRUTE-FORCE")
    print(f"  {C.DIM}Testing 255 keys against raw bytes ...{C.RESET}")

    xor_results = xor_brute_force(data_bytes)
    if xor_results:
        top = xor_results[:15]  # Show top 15 by printability
        for key, text, score in top:
            label = f"key=0x{key:02X} ({score * 100:.0f}%)"
            scan_and_print(label, text)
    else:
        print(f"  {C.DIM}No high-confidence XOR results found.{C.RESET}")

    # ── Multi-Decode Chains ───────────────────────────────────────────
    header("MULTI-LAYER DECODE CHAINS")
    print(f"  {C.DIM}Trying common double-encoded patterns ...{C.RESET}")

    # Base64 → Hex
    b64 = try_base64_decode(data)
    if b64:
        hex_of_b64 = try_hex_decode(b64)
        if hex_of_b64:
            scan_and_print("base64→hex", hex_of_b64)

    # Hex → Base64
    hex_d = try_hex_decode(data)
    if hex_d:
        b64_of_hex = try_base64_decode(hex_d)
        if b64_of_hex:
            scan_and_print("hex→base64", b64_of_hex)

    # Base64 → Base64
    if b64:
        b64_of_b64 = try_base64_decode(b64)
        if b64_of_b64:
            scan_and_print("base64→base64", b64_of_b64)

    # Base32 → Base64
    b32 = try_base32_decode(data)
    if b32:
        b64_of_b32 = try_base64_decode(b32)
        if b64_of_b32:
            scan_and_print("base32→base64", b64_of_b32)

    # ROT13 → Base64
    r13_b64 = try_base64_decode(r13)
    if r13_b64:
        scan_and_print("rot13→base64", r13_b64)

    # ── Hash Quick-Check ──────────────────────────────────────────────
    header("HASH DIGEST REFERENCE")
    print(f"  {C.DIM}Hashes of the original input (for comparison):{C.RESET}")
    for algo in ["md5", "sha1", "sha256", "sha512"]:
        h = hashlib.new(algo, data_bytes).hexdigest()
        print(f"  {C.DIM}{algo:<10}{C.RESET}  {h}")

    # ── Final Summary ─────────────────────────────────────────────────
    header("RESULTS SUMMARY")
    if all_flags:
        print(f"  {C.GREEN}{C.BOLD}>>> {len(all_flags)} FLAG(S) FOUND:{C.RESET}")
        for f in set(all_flags):
            print(f"     {C.GREEN}{C.BOLD}{f}{C.RESET}")
    else:
        print(f"  {C.YELLOW}No flags matching '{flag_prefix}{{...}}' were found automatically.")
        print(f"  Review the decoded outputs above for manual inspection.{C.RESET}")
    print()


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(
        description="CTF Multi-Decoder: brute-force common encodings and ciphers.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python decoder.py                       Read from cipher.txt
              python decoder.py -f challenge.bin      Read from custom file
              python decoder.py -i "SGVsbG8="         Decode inline string
              python decoder.py --flag CTF            Use CTF{} flag format
        """),
    )
    parser.add_argument("-f", "--file", default="cipher.txt",
                        help="Path to input file (default: cipher.txt)")
    parser.add_argument("-i", "--inline", default=None,
                        help="Inline input string (overrides --file)")
    parser.add_argument("--flag", default="FDC",
                        help="Flag prefix for detection (default: FDC)")
    args = parser.parse_args()

    print(BANNER)

    # Load input
    if args.inline:
        raw = args.inline
        print(f"  {C.GREEN}[+]{C.RESET} Using inline input ({len(raw)} chars)")
    else:
        filepath = args.file
        if not os.path.isfile(filepath):
            print(f"  {C.RED}[!] File not found: {filepath}{C.RESET}")
            print(f"  {C.DIM}    Create a 'cipher.txt' file with the challenge data,")
            print(f"    or use  -i \"your string\"  for inline input.{C.RESET}")
            sys.exit(1)
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        print(f"  {C.GREEN}[+]{C.RESET} Loaded {len(raw)} chars from {C.BOLD}{filepath}{C.RESET}")

    if not raw.strip():
        print(f"  {C.RED}[!] Input is empty. Nothing to decode.{C.RESET}")
        sys.exit(1)

    run_all_decoders(raw, flag_prefix=args.flag)


if __name__ == "__main__":
    main()
