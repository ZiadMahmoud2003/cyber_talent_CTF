# Reverse Engineering Cheat Sheet - FDC CTF Blueprint

> **Framework**: CyberTalents | **Author**: FDC Team | **Paradigm**: Scenario -> Action -> Tool & Command

---

## Table of Contents

1. [Static Analysis Triage](#1-static-analysis-triage)
2. [Ghidra Decompilation Strategies](#2-ghidra-decompilation-strategies)
3. [IDA Pro Decompilation Strategies](#3-ida-pro-decompilation-strategies)
4. [Dynamic Debugging with GDB](#4-dynamic-debugging-with-gdb)
5. [Android APK Reverse Engineering](#5-android-apk-reverse-engineering)
6. [Common Algorithm Patterns](#6-common-algorithm-patterns)
7. [Anti-Reversing Bypass](#7-anti-reversing-bypass)
8. [Symbolic Execution with angr](#8-symbolic-execution-with-angr)
9. [Z3 Constraint Solving](#9-z3-constraint-solving)

---

## 1. Static Analysis Triage

### 1.1 Initial Binary Assessment

```
When you receive an unknown binary:
  -> Execute this exact triage sequence
  -> Each step reveals critical information

Step 1: Identify file type and architecture
  file binary
  # Output examples:
  #   ELF 64-bit LSB executable, x86-64, dynamically linked
  #   ELF 32-bit LSB pie executable, Intel 80386, statically linked
  #   PE32+ executable (console) x86-64, for MS Windows
  #   Mach-O 64-bit x86_64 executable

Step 2: Check security mitigations
  checksec --file=binary
  # Look for:
  #   RELRO:     Full/Partial/No RELRO
  #   Stack:     Canary found / No canary
  #   NX:        NX enabled / disabled
  #   PIE:       PIE enabled / No PIE
  #   FORTIFY:   Yes / No

Step 3: Check for packing/obfuscation
  strings binary | head -20               # Few strings = likely packed
  upx -t binary                           # Test if UPX packed
  upx -d binary -o binary_unpacked        # Unpack UPX
  
  # Other packers:
  detect-it-easy binary                   # DIE: detect packer/compiler
  rabin2 -I binary                        # radare2 binary info

Step 4: List linked libraries
  ldd binary                              # Dynamic library dependencies
  readelf -d binary | grep NEEDED         # Required shared libraries

Step 5: List symbols and functions
  nm binary                               # Symbol table
  nm -D binary                            # Dynamic symbols only
  readelf -s binary                       # ELF symbol table
  objdump -t binary | grep " F "         # Function symbols only

Step 6: Extract strings
  strings binary                          # ASCII strings
  strings -n 8 binary                     # Minimum 8 chars
  strings binary | grep -i "flag\|password\|correct\|wrong\|success\|fail\|FDC"

Step 7: View section headers
  readelf -S binary                       # Section headers
  readelf -l binary                       # Program headers
  objdump -h binary                       # Section sizes

Step 8: Quick disassembly of main
  objdump -d -M intel binary | grep -A 50 "<main>"
```

### 1.2 Quick Assessment Decision Tree

```
START: file binary
  |
  |-- "ELF ... dynamically linked"
  |     -> ldd, checksec, nm, strings
  |     -> Open in Ghidra/IDA
  |
  |-- "ELF ... statically linked"
  |     -> No ldd needed, all code is in binary
  |     -> Larger file, harder to identify library functions
  |     -> Ghidra: apply function signatures (FIDB)
  |
  |-- "PE32 executable"
  |     -> Windows binary, use IDA or Ghidra
  |     -> Check for .NET: strings | grep "mscoree"
  |     -> .NET binary: use dnSpy or dotPeek
  |
  |-- "Java class" or "Java archive"
  |     -> Use jadx-gui or jd-gui to decompile
  |     -> unzip file.jar; javap -c ClassName.class
  |
  |-- "Python ... byte-compiled"
  |     -> Use uncompyle6 or decompyle3
  |     -> uncompyle6 -o . script.pyc
  |
  |-- "UPX compressed"
  |     -> upx -d binary -o unpacked
  |     -> Then proceed with normal analysis
  |
  |-- "data" (unknown or stripped)
  |     -> xxd binary | head -5  (check magic bytes)
  |     -> binwalk binary
  |     -> Could be encrypted, compressed, or custom format
```

### 1.3 readelf / objdump Quick Reference

```bash
# Section headers (find .text, .data, .rodata, .bss)
readelf -S binary

# Program headers (LOAD segments, STACK executable?)
readelf -l binary

# Symbol table (function names, global variables)
readelf -s binary | grep FUNC

# Relocations (GOT/PLT entries)
readelf -r binary

# Disassemble specific function
objdump -d -M intel binary | sed -n '/<function_name>:/,/^$/p'

# Disassemble at specific address
objdump -d -M intel --start-address=0x401234 --stop-address=0x401300 binary

# List all functions with addresses
nm binary | grep " T \| t " | sort
```

---

## 2. Ghidra Decompilation Strategies

### 2.1 Setting Up a New Analysis

```
When you open a new binary in Ghidra:
  -> Execute this initial setup sequence
  -> Use these exact steps:

1. File -> Import File -> select binary
   - Accept auto-detected format and architecture
   - Language: x86:LE:64:default (or 32 as appropriate)

2. Analysis -> Auto Analyze
   - Enable ALL analyzers for first pass
   - Key analyzers:
     * Aggressive Instruction Finder
     * ASCII Strings
     * Decompiler Switch Analysis
     * Function ID
     * Stack
   - Click "Analyze"

3. Find main function:
   Method A: Symbol Tree -> Functions -> main
   Method B: Search -> For Strings -> "Enter" or "flag" or "correct"
   Method C: Navigate to entry point, follow call chain:
     entry -> __libc_start_main(main, ...)
     First argument to __libc_start_main IS the main function

4. Window layout recommendation:
   - Listing (disassembly) on left
   - Decompiler on right
   - Symbol Tree at bottom-left
   - Console at bottom
```

### 2.2 Tracing the Main Logic

```
When you reach the main function in Ghidra:
  -> Execute decompilation analysis
  -> Follow this tracing pattern:

Pattern 1: Input -> Transform -> Compare
  Look for: scanf/gets/fgets/read (input)
            loop with XOR/ADD/SUB/ROL/ROR (transform)
            strcmp/memcmp/strncmp (compare)
  Strategy: Reverse the transformation, apply to expected output

Pattern 2: Character-by-character comparison
  Look for: loop iterating over each char
            if (input[i] != expected[i]) { fail; }
  Strategy: Read the expected values directly from memory/data

Pattern 3: Custom hash/checksum
  Look for: accumulator variable, loop over input
            final comparison against a constant
  Strategy: z3 solver or brute-force if short input

Pattern 4: State machine / switch statement
  Look for: switch(state) with case labels
            State transitions based on input
  Strategy: Map the state machine, find valid input path
```

### 2.3 Ghidra Scripting (Java/Python)

```python
# Ghidra Python script: Extract hardcoded comparison bytes
# Run from Ghidra's Script Manager or Jython console

# Find all references to strcmp/memcmp
from ghidra.program.model.symbol import SourceType

fm = currentProgram.getFunctionManager()
listing = currentProgram.getListing()

for func in fm.getFunctions(True):
    name = func.getName()
    if name in ["strcmp", "memcmp", "strncmp"]:
        refs = getReferencesTo(func.getEntryPoint())
        for ref in refs:
            addr = ref.getFromAddress()
            print(f"[+] {name} called from {addr}")
            
            # Look backwards for the comparison string being loaded
            # This varies by calling convention and optimization
```

```python
# Ghidra Script: Dump all string references in a function
# Useful for finding hardcoded flags or comparison values

func = getFunctionContaining(currentAddress)
if func:
    body = func.getBody()
    refs = currentProgram.getReferenceManager()
    
    for addr_range in body:
        for addr in range(addr_range.getMinAddress().getOffset(),
                         addr_range.getMaxAddress().getOffset()):
            from ghidra.program.model.address import GenericAddress
            a = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr)
            for ref in refs.getReferencesFrom(a):
                to_addr = ref.getToAddress()
                data = getDataAt(to_addr)
                if data and data.hasStringValue():
                    print(f"  {a} -> String: {data.getValue()}")
```

### 2.4 Dealing with Obfuscated Switch Statements

```
When Ghidra shows a complex switch statement or jump table:
  -> Execute these analysis steps:

1. Right-click the switch variable -> Retype Variable
   - Set to correct enum type if known

2. Check the Listing view for the jump table:
   - Look for: jmp [rax*8 + TABLE_ADDR]
   - Navigate to TABLE_ADDR to see case targets

3. In Decompiler:
   - Right-click switch -> "Edit Function Signature"
   - May need to adjust parameter types

4. If Ghidra fails to identify the switch:
   - Analyze -> One Shot -> "Decompiler Switch Analysis"
   - Or manually define the jump table:
     Right-click jump instruction -> "Create Jump Table"
```

---

## 3. IDA Pro Decompilation Strategies

### 3.1 Navigation Shortcuts

| Action | Shortcut |
|---|---|
| Go to address | `G` |
| Go to function | `Ctrl+P` |
| Cross-references to | `X` |
| Cross-references from | `Ctrl+X` |
| Rename variable/function | `N` |
| Set type | `Y` |
| Decompile (Hex-Rays) | `F5` |
| Toggle graph/text view | `Space` |
| List all strings | `Shift+F12` |
| List all functions | `Ctrl+F` in Functions window |
| Set breakpoint (debug) | `F2` |
| Step into | `F7` |
| Step over | `F8` |
| Run to cursor | `F4` |
| Comment | `:` (colon) |

### 3.2 Finding the Main Logic in IDA

```
When you open a binary in IDA:
  -> Execute this search strategy:

Method 1: Strings window
  View -> Open Subviews -> Strings (Shift+F12)
  Search for: "flag", "correct", "wrong", "password", "Enter", "FDC{"
  Double-click -> takes you to .rodata
  Press X -> shows cross-references (where string is used)

Method 2: Imports window
  View -> Open Subviews -> Imports
  Search for: strcmp, memcmp, printf, scanf, gets
  Press X -> follow to call sites

Method 3: Entry point tracing
  Navigate to start/entry
  Follow: entry -> __libc_start_main -> first arg = main
  In IDA: the first argument pushed before call __libc_start_main

Method 4: Function list
  View -> Open Subviews -> Functions
  Sort by size (large custom functions are interesting)
  Look for non-library function names
```

### 3.3 Handling Custom Math Transformations

```
When the decompiler shows a complex transformation loop:
  -> Execute these analysis steps:

Example decompiled code:
  for (i = 0; i < len; i++) {
    result[i] = ((input[i] ^ 0x42) + 0x13) & 0xFF;
  }
  if (memcmp(result, expected, len) == 0) { success(); }

Reversal strategy:
  1. Identify the transformation chain:
     input -> XOR 0x42 -> ADD 0x13 -> AND 0xFF -> result
  
  2. Reverse each operation:
     expected -> AND 0xFF (no-op) -> SUB 0x13 -> XOR 0x42 -> input
  
  3. Extract 'expected' bytes from the binary:
     In IDA: navigate to the expected data address
     Select bytes -> Edit -> Export Data
  
  4. Write the reversal script:
```

```python
#!/usr/bin/env python3
"""
Template for reversing custom math transformations.
Modify the reverse_transform function to match the challenge.
"""

def reverse_transform(expected_bytes):
    """
    Reverse the transformation applied to the input.
    MODIFY THIS to match the actual binary's logic.
    """
    flag = bytearray()
    for byte in expected_bytes:
        # Reverse: result = ((input ^ 0x42) + 0x13) & 0xFF
        # So: input = (result - 0x13) ^ 0x42
        original = ((byte - 0x13) & 0xFF) ^ 0x42
        flag.append(original)
    return bytes(flag)

# Expected bytes extracted from the binary
# (copy from IDA/Ghidra data section)
expected = bytes([
    0x25, 0x34, 0x20, 0x17, 0x6A,  # Replace with actual values
    0x3B, 0x22, 0x19, 0x40, 0x55,
])

flag = reverse_transform(expected)
print(f"[+] Flag: {flag.decode('utf-8', errors='replace')}")
```

---

## 4. Dynamic Debugging with GDB

### 4.1 GDB + GEF Setup

```bash
# Install GEF (GDB Enhanced Features)
bash -c "$(curl -fsSL https://gef.blah.cat/sh)"

# OR install pwndbg (alternative)
git clone https://github.com/pwndbg/pwndbg
cd pwndbg && ./setup.sh

# Launch GDB with the binary
gdb ./binary

# Load with arguments
gdb --args ./binary arg1 arg2

# Attach to running process
gdb -p PID
```

### 4.2 Essential GDB Commands

| Action | GDB Command | GEF/pwndbg Extra |
|---|---|---|
| Run program | `run` or `r` | `r` |
| Run with input | `r < input.txt` | `r < input.txt` |
| Run with args | `r arg1 arg2` | `r arg1 arg2` |
| Set breakpoint at function | `b main` | `b main` |
| Set breakpoint at address | `b *0x401234` | `b *0x401234` |
| Set breakpoint at offset | `b *main+42` | `b *main+42` |
| Conditional breakpoint | `b *0x401234 if $rax==0x41` | same |
| List breakpoints | `info breakpoints` | `info breakpoints` |
| Delete breakpoint | `d 1` (breakpoint number) | `d 1` |
| Continue execution | `c` | `c` |
| Step one instruction | `si` | `si` |
| Step over function call | `ni` | `ni` |
| Step one source line | `s` | `s` |
| Next source line | `n` | `n` |
| Finish current function | `finish` | `finish` |
| Print register | `info registers` | `regs` |
| Print specific register | `p $rax` or `p/x $rax` | `p/x $rax` |
| Print memory (hex) | `x/20xb 0x401234` | `hexdump 0x401234` |
| Print memory (string) | `x/s 0x401234` | `x/s 0x401234` |
| Print memory (words) | `x/10xw $rsp` | `telescope $rsp` |
| Print stack | `x/20xg $rsp` | `stack 20` |
| Examine function | `disas main` | `disas main` |
| Set register | `set $rax = 0x42` | same |
| Set memory byte | `set {char}0x401234 = 0x42` | same |
| Write string to memory | `set {char[6]}0x401234 = "hello"` | same |
| Search memory for string | `find 0x400000,0x500000,"flag"` | `search-pattern "flag"` |
| Backtrace | `bt` | `bt` |
| Print variable | `p variable_name` | same |
| View source (if available) | `list` | same |

### 4.3 GDB Debugging Workflow for Flag Extraction

```
When you need to extract a flag from a binary using GDB:
  -> Execute this systematic debugging workflow
  -> Use these exact steps:

Strategy A: Break at comparison function
  1. Find where the input is compared:
     gdb ./binary
     b strcmp
     b memcmp
     b strncmp
     r
     
  2. When breakpoint hits, examine arguments:
     # For strcmp(user_input, expected_flag):
     x/s $rdi              # First argument (64-bit Linux)
     x/s $rsi              # Second argument
     
     # For 32-bit:
     x/s *(int*)($esp+4)   # First argument
     x/s *(int*)($esp+8)   # Second argument

Strategy B: Break at the comparison instruction
  1. Disassemble the check function:
     disas check_function
     
  2. Find the cmp instruction:
     b *0x401234            # Break at the cmp
     r
     
  3. Examine what's being compared:
     p/c $al                # Character comparison
     p/x $rax               # Value comparison
     x/s $rdi               # String pointed to by rdi

Strategy C: Hook a loop to dump character-by-character comparison
  (See section 4.4 below)
```

### 4.4 Automated Loop Hook for Character Comparison

```
When the binary compares the flag character by character in a loop:
  -> Execute an automated GDB hook to dump each expected character
  -> Use this GDB script:

Scenario: The binary has a loop like:
  for (i = 0; i < len; i++) {
    if (input[i] != expected[i]) { return 0; }
  }
```

```bash
# Save this as solve.gdb and run: gdb -x solve.gdb ./binary

# Disable output noise
set pagination off
set logging file flag_output.txt
set logging on

# Break at the comparison instruction inside the loop
# REPLACE 0x401234 with the actual address of the cmp instruction
b *0x401234

# Define a hook to run each time the breakpoint is hit
commands 1
  silent
  # Print the expected character (adjust register based on the binary)
  # Common patterns:
  #   cmp al, dl      -> expected is in DL
  #   cmp byte [rbx+rax], cl  -> expected is in CL
  #   cmp al, byte [rsi+rcx]  -> expected is at [rsi+rcx]
  printf "Char[%d] = 0x%02x '%c'\n", $rcx, $dl, $dl
  continue
end

# Provide dummy input that's long enough
# Method 1: From stdin
run <<< "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

# Method 2: From file
# run < input.txt

set logging off
quit
```

```python
#!/usr/bin/env python3
"""
Automate GDB to extract character-by-character flag comparison.
Uses pwntools for clean GDB scripting.
"""
from pwn import *

BINARY = "./binary"
CMP_ADDR = 0x401234        # Address of the cmp instruction in the loop
EXPECTED_REG = "dl"         # Register holding the expected character
INDEX_REG = "rcx"           # Register holding the loop index
FLAG_LEN = 40               # Maximum expected flag length

context.binary = BINARY

# Build GDB script
gdb_script = f"""
set pagination off
b *{hex(CMP_ADDR)}
commands 1
  silent
  printf "EXTRACT:%d:%d\\n", ${INDEX_REG}, ${EXPECTED_REG}
  continue
end
run <<< "{'A' * FLAG_LEN}"
quit
"""

# Run GDB and capture output
io = process(["gdb", "-batch", "-ex", f"source /dev/stdin", BINARY],
             stdin=PTY)
io.send(gdb_script.encode())
io.shutdown('send')

output = io.recvall(timeout=10).decode(errors='replace')

# Parse extracted characters
flag = {}
for line in output.split('\n'):
    if line.startswith("EXTRACT:"):
        parts = line.strip().split(":")
        idx = int(parts[1])
        char_val = int(parts[2])
        flag[idx] = chr(char_val)

# Reconstruct flag
if flag:
    max_idx = max(flag.keys())
    result = ''.join(flag.get(i, '?') for i in range(max_idx + 1))
    print(f"[+] Extracted flag: {result}")
```

### 4.5 Bypassing Anti-Debug Checks with GDB

```
When the binary detects the debugger and exits:
  -> Execute these bypass techniques:

Bypass 1: Patch ptrace anti-debug
  The binary calls ptrace(PTRACE_TRACEME, 0, 0, 0)
  If it returns -1, a debugger is attached.
  
  gdb ./binary
  b ptrace
  r
  # When ptrace breakpoint hits:
  set $rax = 0              # Force return value to 0 (success)
  c

Bypass 2: Skip the check entirely
  # Find the conditional jump after the anti-debug check
  disas main                # or the function containing the check
  # Find: je/jne after the ptrace call
  # Patch the jump:
  set {unsigned char}0x401234 = 0xEB  # Change JE to JMP (unconditional)
  c

Bypass 3: LD_PRELOAD fake ptrace
  # Create a shared library that overrides ptrace:
  # fake_ptrace.c:
  #   long ptrace(int request, ...) { return 0; }
  gcc -shared -o fake_ptrace.so fake_ptrace.c
  LD_PRELOAD=./fake_ptrace.so gdb ./binary

Bypass 4: Environment variable checks
  # Some binaries check for GDB-related env vars
  unset LINES
  unset COLUMNS
  gdb ./binary
```

---

## 5. Android APK Reverse Engineering

### 5.1 APK Analysis Workflow

```
When you receive an Android APK file:
  -> Execute this complete analysis pipeline
  -> Use these tools in order:

Step 1: Basic inspection
  file challenge.apk                       # Should show "Zip archive"
  unzip -l challenge.apk                   # List contents

Step 2: Decode with apktool (preserves resources)
  apktool d challenge.apk -o apk_decoded/
  # This gives you:
  #   AndroidManifest.xml    (readable XML, not binary)
  #   res/                   (decoded resources)
  #   smali/                 (Dalvik bytecode as smali)
  #   assets/                (raw assets)

Step 3: Decompile with jadx (Java source)
  jadx-gui challenge.apk                   # GUI decompiler
  # OR command line:
  jadx challenge.apk -d jadx_output/       # Decompile to directory
  # This gives you readable Java source code

Step 4: Search for interesting content
  # In the jadx output:
  grep -rn "flag\|password\|secret\|key\|encrypt\|decrypt\|FDC" jadx_output/
  grep -rn "SharedPreferences\|SQLiteDatabase\|Base64\|Cipher" jadx_output/
  
  # In the decoded resources:
  grep -rn "flag\|password\|secret" apk_decoded/res/values/strings.xml
  cat apk_decoded/res/values/strings.xml

Step 5: Check for hardcoded secrets
  # strings.xml often contains flags/keys
  cat apk_decoded/res/values/strings.xml | grep -i "flag\|key\|secret\|password"
  
  # Check assets directory
  ls -la apk_decoded/assets/
  file apk_decoded/assets/*
  strings apk_decoded/assets/* | grep -i "flag\|FDC"
  
  # Check native libraries
  ls apk_decoded/lib/*/
  strings apk_decoded/lib/*/lib*.so | grep -i "flag\|FDC"

Step 6: Check AndroidManifest.xml
  cat apk_decoded/AndroidManifest.xml
  # Look for:
  #   android:debuggable="true"     (can attach debugger)
  #   exported activities/services  (accessible externally)
  #   permissions                   (what the app does)
  #   intent-filters                (entry points)
```

### 5.2 jadx-gui Navigation

```
When you open an APK in jadx-gui:
  -> Execute this analysis strategy:

1. Find the entry point:
   - Look in AndroidManifest.xml for the LAUNCHER activity
   - Find: <action android:name="android.intent.action.MAIN"/>
   - The containing <activity> is the starting point

2. Search for flag-related code:
   - Navigation -> Text Search (Ctrl+Shift+F)
   - Search: "flag", "correct", "success", "decrypt", "check"
   - Also search: "AES", "DES", "Base64", "SHA", "MD5"

3. Follow the logic:
   - Find the validation function
   - Right-click -> "Find Usage" to trace call chain
   - Look for string comparisons, encryption/decryption

4. Common patterns in CTF APKs:
   - Flag hardcoded in strings.xml but obfuscated
   - Flag computed from multiple string resources
   - Flag decrypted at runtime from assets
   - Native library (.so) contains the flag logic
```

### 5.3 Extracting and Decrypting APK Assets

```python
#!/usr/bin/env python3
"""
Extract and decrypt encrypted assets from Android APK files.
Common pattern: AES-encrypted flag stored in assets/ directory.
"""
import zipfile
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def extract_apk_asset(apk_path, asset_name):
    """Extract a specific asset from an APK file."""
    with zipfile.ZipFile(apk_path, 'r') as z:
        # List all files
        for name in z.namelist():
            if asset_name in name:
                data = z.read(name)
                print(f"[+] Extracted {name}: {len(data)} bytes")
                return data
    
    print(f"[-] Asset '{asset_name}' not found")
    return None

def try_aes_decrypt(encrypted_data, key, mode="ECB"):
    """Try AES decryption with common modes."""
    try:
        if isinstance(key, str):
            key = key.encode()
        
        # Ensure key is correct length (16, 24, or 32 bytes)
        if len(key) < 16:
            key = key.ljust(16, b'\x00')
        elif len(key) < 24:
            key = key[:16]
        elif len(key) < 32:
            key = key[:24]
        else:
            key = key[:32]
        
        if mode == "ECB":
            cipher = AES.new(key, AES.MODE_ECB)
            decrypted = unpad(cipher.decrypt(encrypted_data), AES.block_size)
        elif mode == "CBC":
            iv = encrypted_data[:16]
            cipher = AES.new(key, AES.MODE_CBC, iv=iv)
            decrypted = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
        
        print(f"[+] Decrypted ({mode}): {decrypted}")
        return decrypted
    except Exception as e:
        print(f"[-] Decryption failed ({mode}): {e}")
        return None

def search_apk_for_strings(apk_path, patterns=None):
    """Search all files in APK for interesting strings."""
    if patterns is None:
        patterns = ["flag", "FDC{", "password", "secret", "key", "encrypt"]
    
    with zipfile.ZipFile(apk_path, 'r') as z:
        for name in z.namelist():
            try:
                data = z.read(name).decode('utf-8', errors='replace')
                for pattern in patterns:
                    if pattern.lower() in data.lower():
                        # Find the exact line
                        for i, line in enumerate(data.split('\n')):
                            if pattern.lower() in line.lower():
                                print(f"[+] {name}:{i+1}: {line.strip()[:200]}")
            except Exception:
                pass

# Usage:
# search_apk_for_strings("challenge.apk")
# asset_data = extract_apk_asset("challenge.apk", "encrypted_flag")
# key = "hardcoded_key_from_java_source"
# try_aes_decrypt(asset_data, key, mode="ECB")
```

### 5.4 Smali Patching (Modify APK Behavior)

```
When you need to modify an APK and re-run it:
  -> Execute the patch-rebuild-sign workflow:

Step 1: Decode
  apktool d challenge.apk -o decoded/

Step 2: Modify smali code
  # Example: Change a comparison result
  # Find: if-eqz v0, :label    (if v0 == 0, jump)
  # Change to: if-nez v0, :label  (if v0 != 0, jump)
  # This inverts the condition (bypass check)
  
  # Example: Force a method to return true
  # Replace method body with:
  #   const/4 v0, 0x1
  #   return v0

Step 3: Rebuild
  apktool b decoded/ -o patched.apk

Step 4: Sign (required for Android to accept)
  # Generate a key (one time)
  keytool -genkey -v -keystore debug.keystore -storepass android \
    -alias debugkey -keypass android -keyalg RSA -keysize 2048 -validity 10000
  
  # Sign the APK
  jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 \
    -keystore debug.keystore -storepass android patched.apk debugkey
  
  # OR use apksigner (newer):
  apksigner sign --ks debug.keystore --ks-pass pass:android patched.apk

Step 5: Install
  adb install patched.apk
```

---

## 6. Common Algorithm Patterns

### 6.1 Pattern Recognition Quick Reference

| Decompiled Pattern | Algorithm | Reversal |
|---|---|---|
| `c = p ^ key` | XOR | `p = c ^ key` |
| `c = (p + key) % 256` | ADD cipher | `p = (c - key) % 256` |
| `c = (p - key) % 256` | SUB cipher | `p = (c + key) % 256` |
| `c = (p * key) % 256` | MUL cipher | `p = (c * modinv(key, 256)) % 256` |
| `c = p << n \| p >> (8-n)` | ROL (rotate left) | `p = c >> n \| c << (8-n)` |
| `c = p >> n \| p << (8-n)` | ROR (rotate right) | `p = c << n \| c >> (8-n)` |
| `c = ~p` (bitwise NOT) | NOT | `p = ~c` |
| `c[i] = p[i] ^ p[i-1]` | Differential XOR | Reverse iterate: `p[i] = c[i] ^ c[i-1]` |
| `c[i] = p[len-1-i]` | Reverse | `p[i] = c[len-1-i]` |
| `c = base64(p)` | Base64 | `p = base64.b64decode(c)` |
| Matrix multiplication | Hill cipher | Inverse matrix mod 26 |
| `c = (a*p + b) % m` | Affine cipher | `p = modinv(a,m) * (c - b) % m` |
| S-box lookup table | Substitution | Reverse S-box lookup |
| Feistel structure (L/R swap + round func) | Feistel cipher | Run rounds in reverse |

### 6.2 S-Box / Lookup Table Reversal

```python
#!/usr/bin/env python3
"""Reverse an S-box substitution cipher."""

# Example S-box extracted from the binary
SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,  # First 8 entries
    # ... (complete 256-byte S-box)
]

def reverse_sbox(sbox):
    """Build the inverse S-box."""
    inv = [0] * 256
    for i, v in enumerate(sbox):
        inv[v] = i
    return inv

def decrypt_with_sbox(ciphertext, sbox):
    """Decrypt using inverse S-box substitution."""
    inv_sbox = reverse_sbox(sbox)
    return bytes(inv_sbox[b] for b in ciphertext)

# Usage:
# plaintext = decrypt_with_sbox(ciphertext_bytes, SBOX)
```

---

## 7. Anti-Reversing Bypass

### 7.1 Common Anti-Analysis Techniques

| Technique | Detection | Bypass |
|---|---|---|
| `ptrace(TRACEME)` | `ltrace` shows ptrace call | LD_PRELOAD or GDB: `set $rax=0` at ptrace |
| `/proc/self/status` check | Strings shows `TracerPid` | Patch the fopen/read call or use `faketime` |
| Time-based detection | `rdtsc` or `clock_gettime` calls | GDB: skip the time check or patch comparison |
| Signal-based (`SIGTRAP`) | `signal(SIGTRAP, handler)` | GDB: `handle SIGTRAP nostop noprint` |
| Self-modifying code | Code section is writable | Set write breakpoint, trace modifications |
| Anti-VM checks | Checks for VM artifacts | Run on bare metal or patch checks |
| Obfuscated control flow | Opaque predicates | Symbolic execution (angr) |
| Stripped symbols | `nm` returns nothing | Use `objdump`, Ghidra's analysis to find functions |

---

## 8. Symbolic Execution with angr

### 8.1 Basic angr Template

```python
#!/usr/bin/env python3
"""
angr symbolic execution template for CTF reversing challenges.
Automatically finds input that reaches a target address (e.g., "Correct!" print).
"""
import angr
import claripy
import sys

BINARY = "./binary"
FLAG_LEN = 32                        # Expected input length

# Addresses (find from Ghidra/IDA)
FIND_ADDR   = 0x401234              # Address of success (e.g., "Correct!")
AVOID_ADDRS = [0x401300]            # Address of failure (e.g., "Wrong!")

def solve():
    proj = angr.Project(BINARY, auto_load_libs=False)
    
    # Create symbolic input
    flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(FLAG_LEN)]
    flag = claripy.Concat(*flag_chars)
    
    # Start from entry point with symbolic stdin
    state = proj.factory.full_init_state(
        args=[BINARY],
        stdin=flag,
    )
    
    # Constrain to printable ASCII
    for ch in flag_chars:
        state.solver.add(ch >= 0x20)
        state.solver.add(ch <= 0x7E)
    
    # Optional: constrain flag format
    # state.solver.add(flag_chars[0] == ord('F'))
    # state.solver.add(flag_chars[1] == ord('D'))
    # state.solver.add(flag_chars[2] == ord('C'))
    # state.solver.add(flag_chars[3] == ord('{'))
    # state.solver.add(flag_chars[-1] == ord('}'))
    
    # Run simulation
    simgr = proj.factory.simulation_manager(state)
    simgr.explore(find=FIND_ADDR, avoid=AVOID_ADDRS)
    
    if simgr.found:
        found_state = simgr.found[0]
        solution = found_state.solver.eval(flag, cast_to=bytes)
        print(f"[+] Flag: {solution.decode(errors='replace')}")
        return solution
    else:
        print("[-] No solution found")
        return None

if __name__ == "__main__":
    solve()
```

---

## 9. Z3 Constraint Solving

### 9.1 Z3 Template for Reversing Math Constraints

```python
#!/usr/bin/env python3
"""
Z3 constraint solver template for reversing challenges.
When the binary applies mathematical constraints to the input,
model them in Z3 and solve.
"""
from z3 import *

FLAG_LEN = 20

def solve():
    # Create symbolic variables for each flag character
    flag = [BitVec(f"f{i}", 8) for i in range(FLAG_LEN)]
    s = Solver()
    
    # Constraint 1: All characters are printable ASCII
    for ch in flag:
        s.add(ch >= 0x20)
        s.add(ch <= 0x7E)
    
    # Constraint 2: Known flag format
    s.add(flag[0] == ord('F'))
    s.add(flag[1] == ord('D'))
    s.add(flag[2] == ord('C'))
    s.add(flag[3] == ord('{'))
    s.add(flag[FLAG_LEN - 1] == ord('}'))
    
    # Constraint 3: Custom constraints from the binary
    # MODIFY THESE to match the actual constraints
    # Example: flag[4] + flag[5] == 0xAB
    # Example: flag[6] ^ flag[7] == 0x12
    # Example: flag[8] * 3 == 0xF9
    s.add(flag[4] ^ 0x42 == 0x30)
    s.add(flag[5] + flag[6] == 200)
    s.add(flag[7] - flag[8] == 10)
    
    # Solve
    if s.check() == sat:
        model = s.model()
        result = ''.join(chr(model[ch].as_long()) for ch in flag)
        print(f"[+] Flag: {result}")
        return result
    else:
        print("[-] No solution (UNSAT)")
        return None

if __name__ == "__main__":
    solve()
```

### 9.2 Z3 for Matrix/System of Equations

```python
#!/usr/bin/env python3
"""Z3 solver for systems of linear equations (common in RE challenges)."""
from z3 import *

def solve_linear_system():
    """
    Solve: A * x = b (mod 256)
    Where A is a known matrix, b is known output, x is the flag.
    """
    n = 4  # Number of unknowns
    x = [BitVec(f"x{i}", 8) for i in range(n)]
    s = Solver()
    
    # Printable ASCII constraints
    for xi in x:
        s.add(xi >= 0x20)
        s.add(xi <= 0x7E)
    
    # Matrix equation (example):
    # 2*x0 + 3*x1 + 1*x2 + 4*x3 = 0xAB (mod 256)
    # 1*x0 + 0*x1 + 2*x2 + 1*x3 = 0xCD (mod 256)
    # 3*x0 + 2*x1 + 1*x2 + 0*x3 = 0xEF (mod 256)
    # 0*x0 + 1*x1 + 3*x2 + 2*x3 = 0x12 (mod 256)
    
    A = [[2, 3, 1, 4],
         [1, 0, 2, 1],
         [3, 2, 1, 0],
         [0, 1, 3, 2]]
    b = [0xAB, 0xCD, 0xEF, 0x12]
    
    for i in range(n):
        equation = sum(A[i][j] * x[j] for j in range(n))
        s.add(equation & 0xFF == b[i])
    
    if s.check() == sat:
        model = s.model()
        result = ''.join(chr(model[xi].as_long()) for xi in x)
        print(f"[+] Solution: {result}")
        return result
    else:
        print("[-] UNSAT")
        return None

solve_linear_system()
```
