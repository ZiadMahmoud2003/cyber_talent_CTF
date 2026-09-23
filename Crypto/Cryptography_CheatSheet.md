# Cryptography Cheat Sheet - FDC CTF Blueprint

> **Framework**: CyberTalents | **Author**: FDC Team | **Paradigm**: Scenario -> Action -> Tool & Command

---

## Table of Contents

1. [Encoding Identification Flowchart](#1-encoding-identification-flowchart)
2. [Base Encodings Reference](#2-base-encodings-reference)
3. [Classical Ciphers](#3-classical-ciphers)
4. [XOR Attacks](#4-xor-attacks)
5. [RSA Attacks](#5-rsa-attacks)
6. [AES Attacks](#6-aes-attacks)
7. [Hash Cracking](#7-hash-cracking)
8. [Diffie-Hellman Attacks](#8-diffie-hellman-attacks)
9. [Useful Tools & One-Liners](#9-useful-tools--one-liners)

---

## 1. Encoding Identification Flowchart

```
START: You have an unknown encoded string
  |
  |-- Is it all 0s and 1s?
  |     YES --> BINARY encoding
  |             Decode: ''.join(chr(int(b,2)) for b in data.split())
  |
  |-- Is it all dots, dashes, and spaces/slashes?
  |     YES --> MORSE CODE
  |             Decode: Use morse lookup table
  |
  |-- Is it all hex chars (0-9, a-f, A-F)?
  |     |-- Length divisible by 2?
  |     |     YES --> HEX encoding
  |     |             Decode: bytes.fromhex(data).decode()
  |     |-- Length is exactly 32?
  |     |     YES --> Possibly MD5 hash
  |     |-- Length is exactly 40?
  |     |     YES --> Possibly SHA-1 hash
  |     |-- Length is exactly 64?
  |           YES --> Possibly SHA-256 hash
  |
  |-- Does it contain only A-Z and 2-7 (uppercase)?
  |     YES --> BASE32
  |             Padding: = signs to make length % 8 == 0
  |             Decode: base64.b32decode(data)
  |
  |-- Does it contain A-Z, a-z, 0-9, +, / (and = padding)?
  |     YES --> BASE64 (standard)
  |             Padding: = signs to make length % 4 == 0
  |             Decode: base64.b64decode(data)
  |
  |-- Does it contain A-Z, a-z, 0-9, -, _ (URL-safe)?
  |     YES --> BASE64URL
  |             Decode: base64.urlsafe_b64decode(data + '==')
  |
  |-- Does it contain A-Z, a-z, 0-9 but NO +/= and varied chars?
  |     YES --> Possibly BASE58 (Bitcoin/IPFS)
  |             No 0, O, I, l characters
  |             Decode: pip install base58; base58.b58decode(data)
  |
  |-- Does it contain printable ASCII 33-117 (!...u)?
  |     YES --> Possibly BASE85 / ASCII85
  |             May have <~ ~> wrapper (Adobe variant)
  |             Decode: base64.b85decode(data) or base64.a85decode(data)
  |
  |-- Does it contain %XX patterns?
  |     YES --> URL ENCODING (percent encoding)
  |             Decode: urllib.parse.unquote(data)
  |
  |-- Does it contain \uXXXX or \xXX patterns?
  |     YES --> UNICODE ESCAPE
  |             Decode: data.encode().decode('unicode_escape')
  |
  |-- Does it contain only letters (no numbers/symbols)?
  |     YES --> Possibly a SUBSTITUTION CIPHER
  |             Try: ROT13, Caesar (all 26 shifts), Atbash, Vigenere
  |
  |-- Does it look like English but shifted?
  |     YES --> CAESAR / ROT cipher
  |             Try all 26 shifts or frequency analysis
  |
  |-- Is it a large integer?
  |     YES --> Possibly RSA ciphertext or long_to_bytes conversion
  |             Try: from Crypto.Util.number import long_to_bytes
  |
  |-- None of the above?
        --> Try CyberChef (https://gchq.github.io/CyberChef/)
        --> Try dCode.fr (https://www.dcode.fr/)
        --> Try quipqiup.com (substitution cipher solver)
```

---

## 2. Base Encodings Reference

### 2.1 Quick Decode Table

| Encoding | Charset | Padding | Python Decode |
|---|---|---|---|
| Hex | `0-9 a-f` | None | `bytes.fromhex(data)` |
| Binary | `0 1` | None | `int(data, 2).to_bytes(...)` |
| Octal | `0-7` | None | `chr(int(x, 8)) for each` |
| Base16 | `0-9 A-F` | None | `base64.b16decode(data)` |
| Base32 | `A-Z 2-7` | `=` (mod 8) | `base64.b32decode(data)` |
| Base58 | `1-9 A-H J-N P-Z a-k m-z` | None | `base58.b58decode(data)` |
| Base64 | `A-Z a-z 0-9 + /` | `=` (mod 4) | `base64.b64decode(data)` |
| Base64URL | `A-Z a-z 0-9 - _` | `=` (mod 4) | `base64.urlsafe_b64decode(data)` |
| Base85 | ASCII 33-117 | None | `base64.b85decode(data)` |
| Ascii85 | ASCII 33-117 + `<~ ~>` | None | `base64.a85decode(data)` |

### 2.2 Multi-Layer Decode Script

```python
#!/usr/bin/env python3
"""Recursively decode multi-layered encodings."""
import base64
import binascii
import re
from urllib.parse import unquote

def try_all_decodings(data, depth=0, max_depth=10):
    """Recursively try decoding until we get plaintext or hit max depth."""
    if depth >= max_depth:
        return data
    
    indent = "  " * depth
    
    # Try Base64
    try:
        padded = data + "=" * (-len(data) % 4)
        decoded = base64.b64decode(padded, validate=True).decode("utf-8")
        if decoded.isprintable() and len(decoded) > 1:
            print(f"{indent}[Layer {depth}] Base64 -> {decoded[:80]}")
            return try_all_decodings(decoded, depth + 1, max_depth)
    except Exception:
        pass
    
    # Try Hex
    try:
        cleaned = data.strip().replace(" ", "")
        if re.fullmatch(r"[0-9a-fA-F]+", cleaned) and len(cleaned) % 2 == 0:
            decoded = bytes.fromhex(cleaned).decode("utf-8")
            if decoded.isprintable() and len(decoded) > 1:
                print(f"{indent}[Layer {depth}] Hex -> {decoded[:80]}")
                return try_all_decodings(decoded, depth + 1, max_depth)
    except Exception:
        pass
    
    # Try Base32
    try:
        cleaned = data.strip().upper() + "=" * (-len(data.strip()) % 8)
        decoded = base64.b32decode(cleaned).decode("utf-8")
        if decoded.isprintable() and len(decoded) > 1:
            print(f"{indent}[Layer {depth}] Base32 -> {decoded[:80]}")
            return try_all_decodings(decoded, depth + 1, max_depth)
    except Exception:
        pass
    
    # Try URL decode
    try:
        decoded = unquote(data)
        if decoded != data:
            print(f"{indent}[Layer {depth}] URL -> {decoded[:80]}")
            return try_all_decodings(decoded, depth + 1, max_depth)
    except Exception:
        pass
    
    return data

# Usage:
# result = try_all_decodings("U0dWc2JHOGdWMjl5YkdRPQ==")
# print(f"Final: {result}")
```

---

## 3. Classical Ciphers

### 3.1 Caesar / ROT Cipher

```python
#!/usr/bin/env python3
"""Caesar cipher brute-force all 26 shifts."""

def caesar_brute(ciphertext):
    """Print all 26 Caesar shifts with frequency scoring."""
    # English letter frequency (most to least common)
    english_freq = "etaoinshrdlcumwfgypbvkjxqz"
    
    results = []
    for shift in range(26):
        decrypted = ""
        for ch in ciphertext:
            if ch.isalpha():
                base = ord('A') if ch.isupper() else ord('a')
                decrypted += chr((ord(ch) - base + shift) % 26 + base)
            else:
                decrypted += ch
        
        # Score by English frequency
        score = sum(1 for c in decrypted.lower() if c in english_freq[:13])
        results.append((shift, decrypted, score))
    
    # Sort by score (best match first)
    results.sort(key=lambda x: x[2], reverse=True)
    
    print("=== Caesar Brute-Force (sorted by English frequency score) ===")
    for shift, text, score in results:
        marker = " <<<" if shift == results[0][0] else ""
        print(f"  ROT-{shift:>2} (score={score:>3}): {text[:80]}{marker}")
    
    return results[0]  # Return best match

# Usage:
# best_shift, plaintext, score = caesar_brute("GUVF VF GUR CNFFJBEQ")
```

### 3.2 Vigenere Cipher - Key Recovery via Kasiski + Frequency Analysis

```python
#!/usr/bin/env python3
"""
Vigenere cipher key recovery using:
  1. Kasiski examination (find key length)
  2. Frequency analysis (find each key character)
"""
from collections import Counter
from math import gcd
from functools import reduce
from itertools import cycle

ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074,
}

def find_key_length(ciphertext, max_len=20):
    """Use Kasiski examination to estimate key length."""
    text = ''.join(c.upper() for c in ciphertext if c.isalpha())
    distances = []
    
    for length in range(3, 6):
        for i in range(len(text) - length):
            substring = text[i:i + length]
            for j in range(i + 1, len(text) - length):
                if text[j:j + length] == substring:
                    distances.append(j - i)
    
    if not distances:
        return 3  # Default guess
    
    # Find GCD of distances
    likely_length = reduce(gcd, distances)
    
    # If GCD is 1, try finding the most common factor
    if likely_length == 1:
        factors = []
        for d in distances:
            for f in range(2, min(d, max_len + 1)):
                if d % f == 0:
                    factors.append(f)
        if factors:
            likely_length = Counter(factors).most_common(1)[0][0]
    
    print(f"[+] Estimated key length: {likely_length}")
    return likely_length

def frequency_attack(ciphertext, key_length):
    """Recover the key using frequency analysis on each position."""
    text = ''.join(c.upper() for c in ciphertext if c.isalpha())
    key = ""
    
    for pos in range(key_length):
        # Extract every key_length-th character starting at pos
        group = text[pos::key_length]
        
        best_shift = 0
        best_score = float('inf')
        
        for shift in range(26):
            score = 0
            decrypted_freq = Counter()
            for ch in group:
                decrypted = chr((ord(ch) - ord('A') - shift) % 26 + ord('A'))
                decrypted_freq[decrypted] += 1
            
            total = len(group)
            for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
                observed = (decrypted_freq[letter] / total) * 100 if total > 0 else 0
                expected = ENGLISH_FREQ.get(letter, 0)
                score += (observed - expected) ** 2
            
            if score < best_score:
                best_score = score
                best_shift = shift
        
        key += chr(best_shift + ord('A'))
    
    return key

def vigenere_decrypt(ciphertext, key):
    """Decrypt Vigenere cipher with known key."""
    result = []
    key_cycle = cycle(key.upper())
    for ch in ciphertext:
        if ch.isalpha():
            shift = ord(next(key_cycle)) - ord('A')
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            result.append(ch)
    return ''.join(result)

def solve_vigenere(ciphertext):
    """Full automated Vigenere solve pipeline."""
    key_len = find_key_length(ciphertext)
    key = frequency_attack(ciphertext, key_len)
    plaintext = vigenere_decrypt(ciphertext, key)
    
    print(f"[+] Recovered key: {key}")
    print(f"[+] Plaintext: {plaintext[:200]}")
    return key, plaintext

# Usage:
# key, plaintext = solve_vigenere("LXFOP VEFRC ...")
```

### 3.3 Monoalphabetic Substitution Solver

```python
#!/usr/bin/env python3
"""
Monoalphabetic substitution cipher solver using frequency analysis.
For complex cases, use quipqiup.com as a crosscheck.
"""
from collections import Counter
import string

ENGLISH_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

def frequency_substitution(ciphertext):
    """Build a substitution map based on frequency analysis."""
    # Count letter frequencies in ciphertext
    letters_only = ''.join(c.upper() for c in ciphertext if c.isalpha())
    freq = Counter(letters_only)
    
    # Sort by frequency (most common first)
    cipher_order = ''.join([letter for letter, _ in freq.most_common(26)])
    # Pad with missing letters
    for c in string.ascii_uppercase:
        if c not in cipher_order:
            cipher_order += c
    
    # Build mapping: most frequent cipher letter -> E, second -> T, etc.
    mapping = {}
    for cipher_ch, plain_ch in zip(cipher_order, ENGLISH_ORDER):
        mapping[cipher_ch] = plain_ch
        mapping[cipher_ch.lower()] = plain_ch.lower()
    
    # Apply mapping
    result = ""
    for ch in ciphertext:
        if ch.upper() in mapping:
            result += mapping[ch] if ch.isupper() else mapping[ch.lower()].lower()
        else:
            result += ch
    
    print("=== Frequency-Based Substitution ===")
    print(f"Mapping: {cipher_order}")
    print(f"     ->  {ENGLISH_ORDER}")
    print(f"\nResult: {result[:200]}")
    print("\n[*] This is an approximation. Refine manually or use quipqiup.com")
    return result, mapping

# Usage:
# plaintext, mapping = frequency_substitution("GSRH RH Z HVXIVG NVHHZTV")
```

---

## 4. XOR Attacks

### 4.1 Single-Byte XOR Brute-Force

```python
#!/usr/bin/env python3
"""Single-byte XOR brute-force with English scoring."""
from collections import Counter

def english_score(text):
    """Score text by English letter frequency."""
    freq = "etaoinshrdlu "
    return sum(1 for c in text.lower() if c in freq)

def single_byte_xor(data):
    """Try all 256 single-byte XOR keys and rank by English score."""
    if isinstance(data, str):
        try:
            data = bytes.fromhex(data)
        except ValueError:
            data = data.encode()
    
    results = []
    for key in range(256):
        decoded = bytes([b ^ key for b in data])
        try:
            text = decoded.decode('ascii')
            score = english_score(text)
            if score > len(text) * 0.3:  # At least 30% common chars
                results.append((key, text, score))
        except (UnicodeDecodeError, ValueError):
            pass
    
    results.sort(key=lambda x: x[2], reverse=True)
    
    for key, text, score in results[:5]:
        print(f"  Key=0x{key:02x} ({chr(key) if 32 <= key < 127 else '.'}) "
              f"Score={score:>3}: {text[:80]}")
    
    return results[0] if results else None

# Usage:
# best = single_byte_xor("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
```

### 4.2 Multi-Byte XOR Key Recovery (Known Plaintext)

```python
#!/usr/bin/env python3
"""
Recover XOR key when you know part of the plaintext.
Classic case: you know the flag format (e.g., 'FDC{' or 'flag{').
"""

def recover_xor_key(ciphertext, known_plaintext):
    """
    XOR ciphertext with known plaintext to recover key bytes.
    ciphertext: bytes or hex string
    known_plaintext: bytes or string (e.g., b"FDC{")
    """
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext)
    if isinstance(known_plaintext, str):
        known_plaintext = known_plaintext.encode()
    
    # XOR cipher with known plain to get key fragment
    key_fragment = bytes([c ^ p for c, p in zip(ciphertext, known_plaintext)])
    
    print(f"[+] Key fragment ({len(key_fragment)} bytes): {key_fragment}")
    print(f"    Hex: {key_fragment.hex()}")
    print(f"    ASCII: {''.join(chr(b) if 32 <= b < 127 else '.' for b in key_fragment)}")
    
    # Try repeating the fragment as the full key
    for key_len in range(1, len(key_fragment) + 1):
        if len(key_fragment) % key_len == 0:
            possible_key = key_fragment[:key_len]
            if all(key_fragment[i] == possible_key[i % key_len] for i in range(len(key_fragment))):
                # This key length works, try decrypting
                decrypted = bytes([c ^ possible_key[i % key_len] for i, c in enumerate(ciphertext)])
                try:
                    text = decrypted.decode('utf-8')
                    print(f"\n[+] Likely key (len={key_len}): {possible_key}")
                    print(f"    Decrypted: {text}")
                except UnicodeDecodeError:
                    pass
    
    return key_fragment

# Usage:
# key = recover_xor_key("0a061b1c4f5d0a", "FDC{")
```

### 4.3 Repeating-Key XOR with Key Length Detection (Hamming Distance)

```python
#!/usr/bin/env python3
"""
Break repeating-key XOR using Hamming distance for key length
detection, then frequency analysis per position.
"""

def hamming_distance(a, b):
    """Count differing bits between two byte sequences."""
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))

def find_key_length(data, max_len=40):
    """Use normalized Hamming distance to find likely key lengths."""
    scores = []
    for kl in range(2, min(max_len, len(data) // 4)):
        blocks = [data[i*kl:(i+1)*kl] for i in range(4)]
        total_dist = 0
        comparisons = 0
        for i in range(len(blocks)):
            for j in range(i+1, len(blocks)):
                total_dist += hamming_distance(blocks[i], blocks[j])
                comparisons += 1
        normalized = (total_dist / comparisons) / kl
        scores.append((kl, normalized))
    
    scores.sort(key=lambda x: x[1])
    print("[+] Top 5 key length candidates:")
    for kl, score in scores[:5]:
        print(f"    Length={kl:>2}, Normalized Hamming={score:.4f}")
    
    return scores[0][0]

def break_repeating_xor(data):
    """Full attack: find key length, then single-byte XOR each position."""
    if isinstance(data, str):
        data = bytes.fromhex(data)
    
    key_len = find_key_length(data)
    print(f"\n[+] Using key length: {key_len}")
    
    key = bytearray()
    for pos in range(key_len):
        group = bytes(data[i] for i in range(pos, len(data), key_len))
        best_key = 0
        best_score = 0
        for k in range(256):
            decoded = bytes(b ^ k for b in group)
            try:
                text = decoded.decode('ascii')
                score = sum(1 for c in text.lower() if c in "etaoinshrdlu ")
                if score > best_score:
                    best_score = score
                    best_key = k
            except (UnicodeDecodeError, ValueError):
                pass
        key.append(best_key)
    
    plaintext = bytes(d ^ key[i % len(key)] for i, d in enumerate(data))
    
    print(f"[+] Recovered key: {bytes(key)}")
    print(f"    Key hex: {bytes(key).hex()}")
    print(f"[+] Plaintext: {plaintext.decode('utf-8', errors='replace')[:200]}")
    
    return bytes(key), plaintext

# Usage:
# key, plaintext = break_repeating_xor(ciphertext_hex)
```

---

## 5. RSA Attacks

### 5.1 RSA Fundamentals Reference

```
RSA Parameters:
  p, q       = two large primes
  n          = p * q                    (modulus)
  phi(n)     = (p-1) * (q-1)           (Euler's totient, also called et)
  e          = public exponent          (commonly 65537 = 0x10001)
  d          = e^(-1) mod phi(n)        (private exponent)
  c          = m^e mod n                (ciphertext)
  m          = c^d mod n                (plaintext)

When you see n, e, c in a challenge:
  -> Your goal is to find d (private key) or m (plaintext) directly
  -> The attack depends on what weakness exists
```

### 5.2 Attack Decision Tree

```
START: You have (n, e, c) and need to find m
  |
  |-- Is n small (< 100 digits)?
  |     YES --> Factor n directly
  |             Use: factordb.com or sympy.factorint(n)
  |
  |-- Is e very small (e = 3, 5, 7)?
  |     |-- Is c < n (c^(1/e) is exact)?
  |     |     YES --> Cube root attack (no modular reduction)
  |     |             m = gmpy2.iroot(c, e)
  |     |
  |     |-- Do you have multiple (c, n) pairs with same m?
  |           YES --> Hastad's Broadcast Attack
  |                   Use CRT on (c1, n1), (c2, n2), ..., (ce, ne)
  |
  |-- Is e very large (close to n)?
  |     YES --> Wiener's Attack (continued fractions)
  |             d is small, recoverable from e/n convergents
  |
  |-- Do you have multiple n values?
  |     YES --> Check for common factors
  |             gcd(n1, n2) might reveal p
  |
  |-- Is n = p^2 or p*q where p is close to q?
  |     YES --> Fermat's factorization
  |             a = isqrt(n), increment a until a^2 - n is perfect square
  |
  |-- Is d reused across different (e, n) pairs?
  |     YES --> Common modulus attack
  |
  |-- None of the above?
        --> Try RsaCtfTool: github.com/RsaCtfTool/RsaCtfTool
        --> Try factoring with yafu, msieve, or cado-nfs
```

### 5.3 FactorDB API Factoring

```python
#!/usr/bin/env python3
"""Factor n using the FactorDB API."""
import requests
from Crypto.Util.number import long_to_bytes, inverse

def factor_with_factordb(n):
    """Query factordb.com API to factor n."""
    url = f"http://factordb.com/api?query={n}"
    resp = requests.get(url)
    data = resp.json()
    
    status = data.get("status", "")
    factors = data.get("factors", [])
    
    # Status: "FF" = fully factored, "CF" = composite, not factored
    if status == "FF" and len(factors) >= 2:
        p = int(factors[0][0])
        q = int(factors[1][0])
        print(f"[+] Factored successfully!")
        print(f"    p = {p}")
        print(f"    q = {q}")
        return p, q
    else:
        print(f"[-] FactorDB status: {status}")
        print(f"    Could not fully factor n")
        return None, None

def rsa_decrypt(n, e, c):
    """Full RSA decrypt: factor n, compute d, recover plaintext."""
    p, q = factor_with_factordb(n)
    if p is None:
        print("[-] Factoring failed. Try other methods.")
        return None
    
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    m = pow(c, d, n)
    plaintext = long_to_bytes(m)
    
    print(f"[+] d = {d}")
    print(f"[+] Plaintext bytes: {plaintext}")
    print(f"[+] Plaintext text:  {plaintext.decode('utf-8', errors='replace')}")
    return plaintext

# Usage:
# rsa_decrypt(n=0x..., e=65537, c=0x...)
```

### 5.4 Small e Cube Root Attack

```python
#!/usr/bin/env python3
"""
RSA small exponent attack: when e is small (e.g., 3) and the
message m is small enough that m^e < n (no modular reduction).
"""
import gmpy2
from Crypto.Util.number import long_to_bytes

def cube_root_attack(c, e):
    """
    If m^e < n, then c = m^e (no mod needed).
    Simply take the e-th root of c.
    """
    m, is_exact = gmpy2.iroot(c, e)
    
    if is_exact:
        plaintext = long_to_bytes(int(m))
        print(f"[+] Exact {e}-th root found!")
        print(f"[+] m = {m}")
        print(f"[+] Plaintext: {plaintext.decode('utf-8', errors='replace')}")
        return plaintext
    else:
        print(f"[-] Not an exact root. Message was likely padded or m^e > n.")
        # Try with small multiples of n (in case m^e wrapped around a few times)
        print("[*] Trying m^e = c + k*n for small k...")
        return None

def cube_root_with_k(c, e, n, max_k=100000):
    """Try c + k*n for small k values (when m^e slightly exceeds n)."""
    for k in range(max_k):
        m, is_exact = gmpy2.iroot(c + k * n, e)
        if is_exact:
            plaintext = long_to_bytes(int(m))
            print(f"[+] Found at k={k}!")
            print(f"[+] Plaintext: {plaintext.decode('utf-8', errors='replace')}")
            return plaintext
    print(f"[-] Not found within k={max_k}")
    return None

# Usage:
# cube_root_attack(c=0x..., e=3)
# cube_root_with_k(c=0x..., e=3, n=0x...)
```

### 5.5 Wiener's Attack (Large e / Small d)

```python
#!/usr/bin/env python3
"""
Wiener's continued fraction attack on RSA.
Works when d < (1/3) * n^(1/4), i.e., d is small and e is large.
"""
from Crypto.Util.number import long_to_bytes

def continued_fraction(numerator, denominator):
    """Compute the continued fraction expansion of numerator/denominator."""
    cf = []
    while denominator:
        q = numerator // denominator
        cf.append(q)
        numerator, denominator = denominator, numerator - q * denominator
    return cf

def convergents(cf):
    """Compute convergents (h/k) from continued fraction expansion."""
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    
    for a in cf:
        h_prev, h_curr = h_curr, a * h_curr + h_prev
        k_prev, k_curr = k_curr, a * k_curr + k_prev
        yield h_curr, k_curr

def wiener_attack(n, e, c):
    """
    Attempt Wiener's attack to recover d from (n, e).
    Returns plaintext if successful.
    """
    cf = continued_fraction(e, n)
    
    for k, d in convergents(cf):
        if k == 0:
            continue
        
        # Check if (e*d - 1) is divisible by k
        if (e * d - 1) % k != 0:
            continue
        
        phi = (e * d - 1) // k
        
        # phi(n) = n - p - q + 1, so p + q = n - phi + 1
        s = n - phi + 1
        
        # p and q are roots of: x^2 - s*x + n = 0
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue
        
        from gmpy2 import isqrt, is_square
        if not is_square(discriminant):
            continue
        
        sqrt_disc = isqrt(discriminant)
        p = (s + sqrt_disc) // 2
        q = (s - sqrt_disc) // 2
        
        if p * q == n:
            print(f"[+] Wiener's attack succeeded!")
            print(f"    d = {d}")
            print(f"    p = {p}")
            print(f"    q = {q}")
            
            m = pow(c, d, n)
            plaintext = long_to_bytes(m)
            print(f"[+] Plaintext: {plaintext.decode('utf-8', errors='replace')}")
            return plaintext
    
    print("[-] Wiener's attack failed. d is not small enough.")
    return None

# Usage:
# wiener_attack(n=0x..., e=0x..., c=0x...)
```

### 5.6 Hastad's Broadcast Attack

```python
#!/usr/bin/env python3
"""
Hastad's Broadcast Attack: same plaintext m encrypted with small e
to multiple recipients with different n values.
Requires e ciphertexts: (c1,n1), (c2,n2), ..., (ce,ne).
"""
import gmpy2
from Crypto.Util.number import long_to_bytes
from functools import reduce

def chinese_remainder_theorem(remainders, moduli):
    """Solve system of congruences using CRT."""
    N = reduce(lambda a, b: a * b, moduli)
    result = 0
    for r, m in zip(remainders, moduli):
        Ni = N // m
        # Modular inverse of Ni mod m
        Mi = pow(Ni, -1, m)
        result += r * Ni * Mi
    return result % N

def hastad_attack(ciphertexts, moduli, e):
    """
    Hastad's Broadcast Attack.
    ciphertexts: list of e ciphertexts [c1, c2, ..., ce]
    moduli:      list of e moduli [n1, n2, ..., ne]
    e:           public exponent (must equal len(ciphertexts))
    """
    assert len(ciphertexts) == e, f"Need exactly {e} ciphertexts for e={e}"
    assert len(moduli) == e, f"Need exactly {e} moduli for e={e}"
    
    # Use CRT to find m^e mod (n1*n2*...*ne)
    m_e = chinese_remainder_theorem(ciphertexts, moduli)
    
    # Take e-th root
    m, is_exact = gmpy2.iroot(m_e, e)
    
    if is_exact:
        plaintext = long_to_bytes(int(m))
        print(f"[+] Hastad's attack succeeded!")
        print(f"[+] m = {m}")
        print(f"[+] Plaintext: {plaintext.decode('utf-8', errors='replace')}")
        return plaintext
    else:
        print("[-] e-th root is not exact. Attack may not apply.")
        return None

# Usage (e=3 example):
# hastad_attack(
#     ciphertexts=[c1, c2, c3],
#     moduli=[n1, n2, n3],
#     e=3
# )
```

### 5.7 Common Factor Attack (GCD)

```python
#!/usr/bin/env python3
"""
Common Factor Attack: when two RSA moduli share a prime factor.
If gcd(n1, n2) > 1, both are immediately factored.
"""
from math import gcd
from Crypto.Util.number import long_to_bytes, inverse

def common_factor_attack(n_list, e, c, target_n_index=0):
    """
    Check all pairs of moduli for common factors.
    n_list: list of RSA moduli
    e:      public exponent
    c:      ciphertext encrypted under n_list[target_n_index]
    """
    target_n = n_list[target_n_index]
    
    for i, ni in enumerate(n_list):
        if i == target_n_index:
            continue
        
        common = gcd(target_n, ni)
        if common > 1 and common < target_n:
            p = common
            q = target_n // p
            
            print(f"[+] Common factor found between n[{target_n_index}] and n[{i}]!")
            print(f"    p = {p}")
            print(f"    q = {q}")
            
            phi = (p - 1) * (q - 1)
            d = inverse(e, phi)
            m = pow(c, d, target_n)
            plaintext = long_to_bytes(m)
            
            print(f"[+] Plaintext: {plaintext.decode('utf-8', errors='replace')}")
            return plaintext
    
    print("[-] No common factors found between any moduli pair.")
    return None

# Usage:
# common_factor_attack([n1, n2, n3], e=65537, c=c1, target_n_index=0)
```

### 5.8 Fermat's Factorization (p close to q)

```python
#!/usr/bin/env python3
"""
Fermat's factorization: works when p and q are close together.
If |p - q| is small, n can be factored as a^2 - b^2 = (a+b)(a-b).
"""
import gmpy2
from Crypto.Util.number import long_to_bytes, inverse

def fermat_factor(n, max_iterations=1000000):
    """Factor n using Fermat's method (p and q close together)."""
    a = gmpy2.isqrt(n) + 1
    
    for i in range(max_iterations):
        b_sq = a * a - n
        if gmpy2.is_square(b_sq):
            b = gmpy2.isqrt(b_sq)
            p = int(a + b)
            q = int(a - b)
            print(f"[+] Factored in {i+1} iterations!")
            print(f"    p = {p}")
            print(f"    q = {q}")
            return p, q
        a += 1
    
    print(f"[-] Fermat factorization failed after {max_iterations} iterations.")
    return None, None

def solve_close_primes(n, e, c):
    """Full solve for RSA with close primes."""
    p, q = fermat_factor(n)
    if p is None:
        return None
    
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    m = pow(c, d, n)
    plaintext = long_to_bytes(m)
    print(f"[+] Plaintext: {plaintext.decode('utf-8', errors='replace')}")
    return plaintext

# Usage:
# solve_close_primes(n=0x..., e=65537, c=0x...)
```

### 5.9 RsaCtfTool (Swiss Army Knife)

```bash
# Clone and setup
git clone https://github.com/RsaCtfTool/RsaCtfTool.git
cd RsaCtfTool
pip install -r requirements.txt

# Attack with known n, e, c
python RsaCtfTool.py -n N_VALUE -e E_VALUE --uncipher C_VALUE

# Attack from public key file
python RsaCtfTool.py --publickey public.pem --uncipherfile cipher.txt

# Attack multiple keys (common factor)
python RsaCtfTool.py --publickey "key1.pem,key2.pem,key3.pem"

# Specify attack
python RsaCtfTool.py -n N -e E --uncipher C --attack wiener
python RsaCtfTool.py -n N -e E --uncipher C --attack smallq
python RsaCtfTool.py -n N -e E --uncipher C --attack fermat
```

---

## 6. AES Attacks

### 6.1 ECB Mode Detection & Exploitation

```python
#!/usr/bin/env python3
"""
AES-ECB detection: identical plaintext blocks produce identical
ciphertext blocks. Send repeating plaintext to detect.
"""
from collections import Counter

def detect_ecb(ciphertext, block_size=16):
    """Detect ECB mode by checking for repeated blocks."""
    blocks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    duplicates = len(blocks) - len(set(blocks))
    
    if duplicates > 0:
        print(f"[+] ECB detected! {duplicates} duplicate blocks found.")
        return True
    else:
        print("[-] No duplicate blocks. Likely not ECB.")
        return False

def ecb_byte_at_a_time(oracle_func, block_size=16, known_prefix_len=0):
    """
    ECB byte-at-a-time decryption.
    oracle_func(plaintext) -> returns encryption of (plaintext || secret)
    """
    secret = b""
    
    for byte_index in range(256):  # Max secret length
        block_num = (known_prefix_len + len(secret)) // block_size
        padding_len = block_size - 1 - (len(secret) % block_size)
        
        # Create padding to push next unknown byte to end of block
        padding = b"A" * padding_len
        
        # Get reference ciphertext
        reference = oracle_func(padding)
        target_block = reference[block_num * block_size : (block_num + 1) * block_size]
        
        # Try all possible byte values
        found = False
        for byte_val in range(256):
            test = padding + secret + bytes([byte_val])
            result = oracle_func(test)
            test_block = result[block_num * block_size : (block_num + 1) * block_size]
            
            if test_block == target_block:
                secret += bytes([byte_val])
                found = True
                break
        
        if not found:
            break
    
    print(f"[+] Recovered secret: {secret}")
    return secret
```

### 6.2 CBC Bit-Flipping

```python
#!/usr/bin/env python3
"""
AES-CBC bit-flipping attack.
Modify ciphertext to change specific plaintext bytes in the next block.
Flipping bit at position i in block N changes the same position in plaintext block N+1.
"""

def cbc_bitflip(ciphertext, block_size, target_block_idx, byte_offset, old_byte, new_byte):
    """
    Flip a byte in the ciphertext to change the corresponding
    plaintext byte in the NEXT block.
    
    Modify block (target_block_idx - 1) to affect block target_block_idx.
    """
    ct = bytearray(ciphertext)
    
    # Position in the previous block
    flip_pos = (target_block_idx - 1) * block_size + byte_offset
    
    # XOR: old_value XOR desired_value cancels old and produces new
    ct[flip_pos] ^= old_byte ^ new_byte
    
    print(f"[+] Flipped byte at position {flip_pos}")
    print(f"    Old: 0x{old_byte:02x} ('{chr(old_byte)}') -> New: 0x{new_byte:02x} ('{chr(new_byte)}')")
    
    return bytes(ct)

# Example: Change ";admin=0" to ";admin=1" in block 2
# modified = cbc_bitflip(ciphertext, 16, target_block_idx=2, byte_offset=7,
#                        old_byte=ord('0'), new_byte=ord('1'))
```

---

## 7. Hash Cracking

### 7.1 Identification Table

| Length | Characters | Likely Hash |
|---|---|---|
| 32 | hex | MD5 |
| 40 | hex | SHA-1 |
| 56 | hex | SHA-224 |
| 64 | hex | SHA-256 |
| 96 | hex | SHA-384 |
| 128 | hex | SHA-512 |
| 32 | hex | NTLM |
| 13 | mixed | DES crypt |
| 34 | `$1$` prefix | MD5 crypt |
| 34 | `$5$` prefix | SHA-256 crypt |
| 34 | `$6$` prefix | SHA-512 crypt |
| 60 | `$2b$` prefix | bcrypt |

### 7.2 Cracking Commands

```bash
# Hashcat
hashcat -m 0    hash.txt wordlist.txt     # MD5
hashcat -m 100  hash.txt wordlist.txt     # SHA-1
hashcat -m 1400 hash.txt wordlist.txt     # SHA-256
hashcat -m 1000 hash.txt wordlist.txt     # NTLM
hashcat -m 3200 hash.txt wordlist.txt     # bcrypt

# John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
john --format=raw-md5 --wordlist=rockyou.txt hash.txt
john --format=raw-sha256 --wordlist=rockyou.txt hash.txt

# Online resources
# https://crackstation.net/
# https://hashes.com/en/decrypt/hash
# https://cmd5.org/
```

### 7.3 Hash Length Extension Attack

```python
#!/usr/bin/env python3
"""
Hash Length Extension attack using hlextend.
When: MAC = H(secret || message) and you know MAC + message but not secret.
You can compute H(secret || message || padding || extension) without knowing secret.
"""
# pip install hlextend
import hlextend

sha = hlextend.new('sha256')

# Known values
known_mac     = "original_mac_hex"
known_message = b"original_message"
secret_length = 16                    # Length of unknown secret (guess or brute)
extension     = b";admin=true"

# Compute extended hash and new message
new_mac = sha.extend(extension, known_message, secret_length, known_mac)
new_message = sha.payload

print(f"[+] New MAC:     {new_mac}")
print(f"[+] New message: {new_message}")
```

---

## 8. Diffie-Hellman Attacks

### 8.1 Small Subgroup / Discrete Log

```python
#!/usr/bin/env python3
"""
Solve discrete logarithm for small parameters.
When p is small or g generates a small subgroup.
"""
from sympy.ntheory.residues import discrete_log

def solve_dh(p, g, A):
    """
    Solve g^a = A (mod p) for a.
    Only feasible for small p or small order of g.
    """
    a = discrete_log(p, A, g)
    print(f"[+] Private key a = {a}")
    return a

# Usage:
# a = solve_dh(p=..., g=..., A=...)
# shared_secret = pow(B, a, p)
```

---

## 9. Useful Tools & One-Liners

### 9.1 Python Quick Conversions

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long

# Integer to bytes
long_to_bytes(0x464443)                        # b'FDC'

# Bytes to integer
bytes_to_long(b"FDC")                          # 4539459

# Hex string to bytes
bytes.fromhex("464443")                        # b'FDC'

# Bytes to hex string
b"FDC".hex()                                   # '464443'

# Base64
import base64
base64.b64encode(b"FDC{flag}")                 # b'RkRDe2ZsYWd9'
base64.b64decode(b"RkRDe2ZsYWd9")             # b'FDC{flag}'

# XOR two byte strings
xor = bytes(a ^ b for a, b in zip(b"hello", b"keyke"))

# Generate RSA key pair
from Crypto.PublicKey import RSA
key = RSA.generate(2048)
print(key.n, key.e, key.d, key.p, key.q)
```

### 9.2 CyberChef Recipes (Manual)

```
Common CyberChef operations for CTF crypto:
  1. From Base64 -> To Hex -> XOR({key:'...'})
  2. From Hex -> ROT13 -> From Base64
  3. Magic (auto-detect encoding)
  4. Entropy analysis (detect randomness vs structure)
```

### 9.3 Essential CLI Tools

```bash
# OpenSSL RSA key inspection
openssl rsa -in key.pem -text -noout              # Inspect private key
openssl rsa -pubin -in pub.pem -text -noout        # Inspect public key
openssl rsautl -decrypt -inkey priv.pem -in ct.bin # Decrypt with private key

# Quick Python one-liners
python3 -c "print(int('flag',16))"                 # Hex to int
python3 -c "print(bytes.fromhex('666c6167'))"      # Hex to bytes
python3 -c "import base64; print(base64.b64decode('RkxBRw=='))"  # Base64 decode
python3 -c "from Crypto.Util.number import long_to_bytes; print(long_to_bytes(0x666c6167))"
```
