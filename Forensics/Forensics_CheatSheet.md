# Forensics Cheat Sheet - FDC CTF Blueprint

> **Framework**: CyberTalents | **Author**: FDC Team | **Paradigm**: Scenario -> Action -> Tool & Command

---

## Table of Contents

1. [File Analysis & Identification](#1-file-analysis--identification)
2. [Magic Bytes Repair Guide](#2-magic-bytes-repair-guide)
3. [Image Steganography](#3-image-steganography)
4. [Audio Forensics & MalMusic](#4-audio-forensics--malmusic)
5. [Network Capture Analysis](#5-network-capture-analysis)
6. [Memory Forensics](#6-memory-forensics)
7. [Disk & Filesystem Forensics](#7-disk--filesystem-forensics)
8. [Document & Archive Analysis](#8-document--archive-analysis)
9. [Metadata Extraction](#9-metadata-extraction)

---

## 1. File Analysis & Identification

### 1.1 Initial Triage Commands

```
When you receive an unknown file:
  -> Execute file identification in this exact order
  -> Use these commands:

Step 1: Identify file type
  file challenge_file
  file -b challenge_file            # Brief output (no filename)

Step 2: Check magic bytes manually
  xxd challenge_file | head -5      # Hex dump first 5 lines
  hexdump -C challenge_file | head -5

Step 3: Check for embedded files
  binwalk challenge_file             # Scan for embedded signatures
  binwalk -e challenge_file          # Extract embedded files
  binwalk --dd='.*' challenge_file   # Extract everything

Step 4: Extract strings
  strings challenge_file             # ASCII strings (min 4 chars)
  strings -n 6 challenge_file       # Minimum 6 chars
  strings -e l challenge_file       # Little-endian 16-bit
  strings -e b challenge_file       # Big-endian 16-bit
  strings challenge_file | grep -i "flag\|ctf\|FDC\|password\|secret"

Step 5: Check entropy
  ent challenge_file                 # Entropy analysis
  binwalk -E challenge_file          # Entropy visualization

Step 6: Compute hashes (for verification)
  md5sum challenge_file
  sha256sum challenge_file
```

### 1.2 File Signature Reference

| File Type | Magic Bytes (Hex) | ASCII Representation |
|---|---|---|
| PNG | `89 50 4E 47 0D 0A 1A 0A` | `.PNG....` |
| JPEG | `FF D8 FF E0` or `FF D8 FF E1` | `....` |
| GIF87a | `47 49 46 38 37 61` | `GIF87a` |
| GIF89a | `47 49 46 38 39 61` | `GIF89a` |
| BMP | `42 4D` | `BM` |
| TIFF (LE) | `49 49 2A 00` | `II*.` |
| TIFF (BE) | `4D 4D 00 2A` | `MM.*` |
| PDF | `25 50 44 46 2D` | `%PDF-` |
| ZIP | `50 4B 03 04` | `PK..` |
| RAR | `52 61 72 21 1A 07` | `Rar!..` |
| 7z | `37 7A BC AF 27 1C` | `7z....` |
| GZIP | `1F 8B 08` | `...` |
| BZIP2 | `42 5A 68` | `BZh` |
| ELF | `7F 45 4C 46` | `.ELF` |
| PE/EXE | `4D 5A` | `MZ` |
| Java Class | `CA FE BA BE` | `....` |
| SQLite | `53 51 4C 69 74 65` | `SQLite` |
| WAV | `52 49 46 46 xx xx xx xx 57 41 56 45` | `RIFF....WAVE` |
| MP3 | `FF FB` or `49 44 33` | `..` or `ID3` |
| OGG | `4F 67 67 53` | `OggS` |
| FLAC | `66 4C 61 43` | `fLaC` |
| AVI | `52 49 46 46 xx xx xx xx 41 56 49 20` | `RIFF....AVI ` |
| MKV | `1A 45 DF A3` | `...` |
| PSD | `38 42 50 53` | `8BPS` |

### 1.3 File Footer Reference

| File Type | Footer Bytes (Hex) | Notes |
|---|---|---|
| PNG | `49 45 4E 44 AE 42 60 82` | `IEND` chunk |
| JPEG | `FF D9` | End of image marker |
| PDF | `25 25 45 4F 46` | `%%EOF` |
| ZIP | `50 4B 05 06` | End of central directory |
| GIF | `00 3B` | Trailer |

---

## 2. Magic Bytes Repair Guide

### 2.1 PNG Header Repair

```
When you encounter a corrupted PNG:
  -> Execute header inspection and repair
  -> Use these exact steps:

Correct PNG structure:
  Offset 0x00: 89 50 4E 47 0D 0A 1A 0A    (PNG signature)
  Offset 0x08: IHDR chunk begins
    Length (4 bytes) + "IHDR" + Width (4B) + Height (4B) + BitDepth (1B)
    + ColorType (1B) + Compression (1B) + Filter (1B) + Interlace (1B)
    + CRC (4B)

Common corruptions and fixes:
  1. Wrong signature bytes -> Replace first 8 bytes with: 89 50 4E 47 0D 0A 1A 0A
  2. Wrong IHDR chunk type -> Bytes at 0x0C should be: 49 48 44 52
  3. Wrong dimensions      -> Recalculate from expected pixel count
  4. Wrong CRC             -> Recalculate CRC for the chunk
```

```python
#!/usr/bin/env python3
"""
PNG repair toolkit: fix headers, brute-force dimensions, recalculate CRCs.
"""
import struct
import zlib
import os

def fix_png_signature(filepath, output=None):
    """Replace the first 8 bytes with the correct PNG signature."""
    PNG_SIG = b'\x89PNG\r\n\x1a\n'
    
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())
    
    print(f"[*] Original header: {data[:8].hex()}")
    data[:8] = PNG_SIG
    print(f"[+] Fixed header:    {data[:8].hex()}")
    
    output = output or filepath + ".fixed.png"
    with open(output, 'wb') as f:
        f.write(data)
    print(f"[+] Saved to {output}")

def brute_force_png_dimensions(filepath, output=None):
    """
    Brute-force PNG width and height to fix corrupted IHDR.
    The CRC at the end of IHDR validates the correct dimensions.
    """
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())
    
    # IHDR starts at offset 8 (after PNG sig)
    # Structure: length(4) + "IHDR"(4) + width(4) + height(4) + ...
    ihdr_start = 8
    ihdr_length = struct.unpack('>I', data[ihdr_start:ihdr_start+4])[0]
    ihdr_data_start = ihdr_start + 4  # After length field
    
    # CRC covers chunk type + chunk data
    crc_offset = ihdr_data_start + 4 + ihdr_length  # After "IHDR" + data
    expected_crc = struct.unpack('>I', data[crc_offset:crc_offset+4])[0]
    
    print(f"[*] IHDR length: {ihdr_length}")
    print(f"[*] Expected CRC: {hex(expected_crc)}")
    print(f"[*] Brute-forcing dimensions...")
    
    # Save the IHDR chunk data template (everything except width/height)
    chunk_type_and_data = bytearray(data[ihdr_data_start:crc_offset])
    
    for width in range(1, 4096):
        for height in range(1, 4096):
            # Set width and height in the chunk data
            struct.pack_into('>I', chunk_type_and_data, 4, width)   # offset 4 = after "IHDR"
            struct.pack_into('>I', chunk_type_and_data, 8, height)  # offset 8
            
            calc_crc = zlib.crc32(chunk_type_and_data) & 0xFFFFFFFF
            
            if calc_crc == expected_crc:
                print(f"[+] Found correct dimensions: {width} x {height}")
                
                # Apply fix
                data[ihdr_data_start:crc_offset] = chunk_type_and_data
                output = output or filepath + ".fixed.png"
                with open(output, 'wb') as f:
                    f.write(data)
                print(f"[+] Saved to {output}")
                return width, height
    
    print("[-] Could not find matching dimensions")
    return None, None

def recalculate_all_crcs(filepath, output=None):
    """Recalculate all chunk CRCs in a PNG file."""
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())
    
    pos = 8  # Skip PNG signature
    fixes = 0
    
    while pos < len(data) - 4:
        chunk_len = struct.unpack('>I', data[pos:pos+4])[0]
        chunk_type = data[pos+4:pos+8]
        chunk_data = data[pos+4:pos+8+chunk_len]  # type + data
        crc_pos = pos + 8 + chunk_len
        
        if crc_pos + 4 > len(data):
            break
        
        stored_crc = struct.unpack('>I', data[crc_pos:crc_pos+4])[0]
        calc_crc = zlib.crc32(chunk_data) & 0xFFFFFFFF
        
        if stored_crc != calc_crc:
            print(f"[!] Chunk '{chunk_type.decode(errors='replace')}' at offset {pos}: "
                  f"CRC mismatch (stored={hex(stored_crc)}, calc={hex(calc_crc)})")
            struct.pack_into('>I', data, crc_pos, calc_crc)
            fixes += 1
        
        pos = crc_pos + 4
    
    if fixes > 0:
        output = output or filepath + ".fixed.png"
        with open(output, 'wb') as f:
            f.write(data)
        print(f"[+] Fixed {fixes} CRCs. Saved to {output}")
    else:
        print("[+] All CRCs are correct.")

# Usage:
# fix_png_signature("corrupted.png")
# brute_force_png_dimensions("corrupted.png")
# recalculate_all_crcs("corrupted.png")
```

### 2.2 JPEG Repair

```
When you encounter a corrupted JPEG:
  -> Check and repair these markers:

JPEG structure:
  Start: FF D8 FF E0 (SOI + APP0) or FF D8 FF E1 (SOI + APP1/EXIF)
  End:   FF D9 (EOI - End of Image)

Repair steps:
  1. Ensure file starts with FF D8
  2. Ensure file ends with FF D9
  3. If data is appended after FF D9 -> extract it (hidden data)
  4. If FF D9 is missing -> append it

Hidden data check:
  python3 -c "
  data = open('image.jpg','rb').read()
  eoi = data.find(b'\xff\xd9')
  if eoi != -1 and eoi + 2 < len(data):
      hidden = data[eoi+2:]
      print(f'Hidden data after JPEG footer: {len(hidden)} bytes')
      open('hidden_data.bin','wb').write(hidden)
  "
```

### 2.3 ZIP Repair

```
When you encounter a corrupted ZIP:
  -> Check and repair these signatures:

ZIP structure:
  Local file header:         50 4B 03 04
  Central directory header:  50 4B 01 02
  End of central directory:  50 4B 05 06

Repair steps:
  1. Ensure file starts with 50 4B 03 04
  2. Try: zip -FF corrupt.zip --out fixed.zip
  3. Try: jar -xvf corrupt.zip (Java's ZIP is more lenient)
  4. Try: 7z x corrupt.zip (7-Zip handles many corruptions)

Password-protected ZIPs:
  zip2john protected.zip > hash.txt
  john --wordlist=rockyou.txt hash.txt

  fcrackzip -v -D -u -p rockyou.txt protected.zip
  fcrackzip -v -b -c 'aA1!' -l 1-6 -u protected.zip    # Brute-force
```

---

## 3. Image Steganography

### 3.1 Systematic Steganography Workflow

```
When you receive an image file in a forensics challenge:
  -> Execute this complete stego workflow in order
  -> Each step covers a different hiding technique

Step 1: Basic checks
  file image.png
  exiftool image.png                      # Check metadata/comments
  strings image.png | grep -i "flag\|FDC\|ctf\|password"
  xxd image.png | tail -20                # Check for appended data

Step 2: Embedded file detection
  binwalk image.png                       # Scan for signatures
  binwalk -e image.png                    # Extract embedded files
  foremost image.png -o output/           # File carving

Step 3: LSB steganography
  zsteg image.png                         # PNG/BMP LSB analysis (BEST TOOL)
  zsteg -a image.png                      # Try all methods
  zsteg image.png -E "b1,rgb,lsb,xy"     # Specific extraction

Step 4: Password-based steganography
  steghide info image.jpg                 # Check if steghide was used
  steghide extract -sf image.jpg -p ""    # Try empty password
  steghide extract -sf image.jpg -p "password"
  stegseek image.jpg rockyou.txt          # Brute-force steghide password

Step 5: Other tools
  outguess -r image.jpg output.txt        # Outguess extraction
  openstego extract -sf image.png -xf output.txt  # OpenStego

Step 6: Visual analysis
  stegsolve                               # Visual bitplane analysis (Java GUI)
  # Or use Python/PIL for programmatic analysis
```

### 3.2 zsteg Deep Reference

```bash
# zsteg is the most powerful PNG/BMP steganography tool
# Install: gem install zsteg

# Full auto-analysis (try everything)
zsteg -a image.png

# Extract specific channel/bit
zsteg image.png -E "b1,r,lsb,xy"          # Bit 1, Red channel, LSB, row-by-row
zsteg image.png -E "b1,rgb,lsb,xy"        # Bit 1, RGB combined
zsteg image.png -E "b2,g,msb,xy"          # Bit 2, Green channel, MSB
zsteg image.png -E "b1,rgba,lsb,xy"       # Include alpha channel
zsteg image.png -E "b1,bgr,lsb,yx"        # BGR order, column-by-column

# Check for specific patterns
zsteg image.png --strings                   # Extract embedded strings
zsteg image.png --bits 1-3                  # Check bits 1 through 3

# Output to file
zsteg image.png -E "b1,rgb,lsb,xy" > extracted.bin
```

### 3.3 Python LSB Extraction

```python
#!/usr/bin/env python3
"""
Manual LSB (Least Significant Bit) steganography extraction.
Extract hidden data from image pixel values.
"""
from PIL import Image
import sys

def extract_lsb(image_path, channels="rgb", bits=1, order="xy"):
    """
    Extract LSB data from an image.
    channels: which color channels to use ("r", "g", "b", "rgb", etc.)
    bits: number of LSBs to extract (1-8)
    order: "xy" = row-by-row, "yx" = column-by-column
    """
    img = Image.open(image_path).convert("RGBA")
    pixels = img.load()
    width, height = img.size
    
    channel_map = {'r': 0, 'g': 1, 'b': 2, 'a': 3}
    bit_string = ""
    
    if order == "xy":
        coords = [(x, y) for y in range(height) for x in range(width)]
    else:
        coords = [(x, y) for x in range(width) for y in range(height)]
    
    for x, y in coords:
        pixel = pixels[x, y]
        for ch in channels.lower():
            if ch in channel_map:
                value = pixel[channel_map[ch]]
                for bit_pos in range(bits):
                    bit_string += str((value >> bit_pos) & 1)
    
    # Convert bit string to bytes
    result = bytearray()
    for i in range(0, len(bit_string) - 7, 8):
        byte = int(bit_string[i:i+8], 2)
        result.append(byte)
        # Stop at null terminator
        if byte == 0:
            break
    
    return bytes(result)

def scan_all_channels(image_path):
    """Try common LSB extraction patterns and show results."""
    patterns = [
        ("r", 1, "xy"),   ("g", 1, "xy"),   ("b", 1, "xy"),
        ("rgb", 1, "xy"), ("bgr", 1, "xy"),
        ("r", 1, "yx"),   ("rgb", 1, "yx"),
        ("rgb", 2, "xy"), ("r", 2, "xy"),
    ]
    
    print(f"[*] Scanning {image_path} for LSB steganography...\n")
    
    for channels, bits, order in patterns:
        try:
            data = extract_lsb(image_path, channels, bits, order)
            # Check if result contains printable text
            printable = sum(1 for b in data if 32 <= b <= 126)
            if printable > len(data) * 0.5 and len(data) > 4:
                text = data.decode('utf-8', errors='replace').rstrip('\x00')
                print(f"  [+] ch={channels} bits={bits} order={order}: {text[:100]}")
        except Exception as e:
            pass

# Usage:
# scan_all_channels("challenge.png")
# data = extract_lsb("challenge.png", channels="rgb", bits=1, order="xy")
# print(data.decode(errors='replace'))
```

### 3.4 Pixel Value Difference (PVD) Steganography

```python
#!/usr/bin/env python3
"""Extract data hidden using Pixel Value Difference steganography."""
from PIL import Image

def extract_pvd(image_path):
    """Extract hidden bits from pixel value differences."""
    img = Image.open(image_path).convert("L")  # Grayscale
    pixels = list(img.getdata())
    width, height = img.size
    
    bits = ""
    for i in range(0, len(pixels) - 1, 2):
        diff = abs(pixels[i] - pixels[i + 1])
        # Lower range = fewer bits, higher range = more bits
        if diff < 8:
            n_bits = 3
        elif diff < 16:
            n_bits = 3
        elif diff < 32:
            n_bits = 4
        elif diff < 64:
            n_bits = 5
        elif diff < 128:
            n_bits = 6
        else:
            n_bits = 7
        
        bits += format(diff, f'0{n_bits}b')[-n_bits:]
    
    # Convert to bytes
    result = bytearray()
    for i in range(0, len(bits) - 7, 8):
        byte = int(bits[i:i+8], 2)
        if byte == 0:
            break
        result.append(byte)
    
    return bytes(result)
```

---

## 4. Audio Forensics & MalMusic

### 4.1 Audio Analysis Workflow

```
When you receive an audio file in a forensics challenge:
  -> Execute this systematic analysis
  -> Use these tools in order:

Step 1: File identification
  file audio_file
  mediainfo audio_file               # Detailed format info
  ffprobe audio_file                 # FFmpeg probe

Step 2: String extraction
  strings audio_file | grep -i "flag\|FDC\|ctf\|secret"
  exiftool audio_file                # Check metadata comments

Step 3: Spectrogram analysis (visual message in frequency domain)
  sox audio_file -n spectrogram -o spectrogram.png
  # OR open in Audacity:
  #   File -> Import -> Audio -> select file
  #   View -> Spectrogram (or click track dropdown -> Spectrogram)
  #   Adjust: Preferences -> Spectrograms -> Window size: 4096, Max freq: 22000

Step 4: Check for steganography
  # Steghide (for WAV files)
  steghide info audio.wav
  steghide extract -sf audio.wav -p ""
  steghide extract -sf audio.wav -p "password"

  # DeepSound (Windows tool for audio stego)
  # Download DeepSound and open the audio file

Step 5: Check for hidden data in metadata/headers
  binwalk audio_file
  binwalk -e audio_file

Step 6: DTMF / Morse code analysis
  # Listen for Morse code (dots and dashes as tones)
  # Listen for DTMF tones (phone dial tones)
  # Use multimon-ng for decoding
  sox audio.wav -t raw -r 22050 -e signed -b 16 - | multimon-ng -t raw -
```

### 4.2 Audacity Spectrogram Settings for Hidden Messages

```
When you suspect a visual message hidden in the audio spectrogram:
  -> Execute these exact Audacity settings:

1. Open audio file in Audacity
2. Click the track name dropdown (left panel) -> "Spectrogram"
3. Click track name dropdown -> "Spectrogram Settings":
   - Algorithm: Frequencies
   - Window Size: 2048 or 4096 (try both)
   - Window Type: Hanning
   - Minimum Frequency: 0 Hz
   - Maximum Frequency: 22000 Hz (or 8000 if message is in lower range)
   - Gain: 20 dB
   - Range: 80 dB
   - Frequency Gain: 0 dB
   - Color scheme: Grayscale or Color (try both)

4. Zoom into specific frequency ranges:
   - Most hidden text appears between 1000-20000 Hz
   - QR codes/images often span the full spectrum
   - Narrow-band signals suggest data encoding

5. If you see binary-looking patterns:
   - High amplitude = 1, Low amplitude = 0
   - Read left to right, convert binary to ASCII
```

### 4.3 Python Audio Spectrogram Generation

```python
#!/usr/bin/env python3
"""
Generate spectrograms from audio files for forensic analysis.
Reveals hidden visual messages encoded in the frequency domain.
"""
import numpy as np
import wave
import struct

def read_wav(filepath):
    """Read a WAV file and return sample data and sample rate."""
    with wave.open(filepath, 'rb') as wf:
        n_channels = wf.getnchannels()
        sample_width = wf.getsampwidth()
        sample_rate = wf.getframerate()
        n_frames = wf.getnframes()
        
        raw_data = wf.readframes(n_frames)
        
        if sample_width == 1:
            fmt = f"<{n_frames * n_channels}B"
        elif sample_width == 2:
            fmt = f"<{n_frames * n_channels}h"
        elif sample_width == 4:
            fmt = f"<{n_frames * n_channels}i"
        else:
            raise ValueError(f"Unsupported sample width: {sample_width}")
        
        samples = struct.unpack(fmt, raw_data)
        
        if n_channels == 2:
            # Take only left channel
            samples = samples[::2]
        
        print(f"[+] WAV: {sample_rate} Hz, {n_channels} ch, "
              f"{sample_width*8}-bit, {n_frames} frames")
        
        return np.array(samples, dtype=np.float64), sample_rate

def extract_hidden_bits(filepath, threshold=0.5):
    """
    Extract binary data from audio amplitude patterns.
    Used when data is encoded as high/low amplitude segments.
    """
    samples, sample_rate = read_wav(filepath)
    
    # Normalize to 0-1
    samples = np.abs(samples) / np.max(np.abs(samples))
    
    # Segment into chunks (one bit per chunk)
    # Common chunk sizes: 100, 441, 1000, 4410 samples
    for chunk_size in [100, 441, 1000, 4410, sample_rate // 10]:
        bits = ""
        for i in range(0, len(samples) - chunk_size, chunk_size):
            chunk = samples[i:i + chunk_size]
            avg_amplitude = np.mean(chunk)
            bits += "1" if avg_amplitude > threshold else "0"
        
        # Try converting to text
        text = ""
        for i in range(0, len(bits) - 7, 8):
            byte = int(bits[i:i+8], 2)
            if 32 <= byte <= 126:
                text += chr(byte)
            elif byte == 0:
                break
            else:
                text = ""
                break
        
        if len(text) > 3:
            print(f"[+] Chunk size {chunk_size}: {text[:100]}")

def extract_frequency_data(filepath, target_freq=1000, bandwidth=100):
    """
    Extract data encoded at a specific frequency.
    Useful for DTMF or FSK encoded data.
    """
    samples, sample_rate = read_wav(filepath)
    
    # Apply FFT in windows
    window_size = 1024
    bits = ""
    
    for i in range(0, len(samples) - window_size, window_size):
        window = samples[i:i + window_size]
        fft = np.fft.rfft(window)
        freqs = np.fft.rfftfreq(window_size, 1.0 / sample_rate)
        
        # Find energy at target frequency
        mask = (freqs >= target_freq - bandwidth) & (freqs <= target_freq + bandwidth)
        energy = np.sum(np.abs(fft[mask]))
        
        # Threshold
        bits += "1" if energy > np.mean(np.abs(fft)) * 2 else "0"
    
    # Convert bits to bytes
    result = ""
    for i in range(0, len(bits) - 7, 8):
        byte = int(bits[i:i+8], 2)
        if 32 <= byte <= 126:
            result += chr(byte)
    
    if result:
        print(f"[+] Frequency {target_freq}Hz data: {result[:100]}")
    
    return result

# Usage:
# samples, sr = read_wav("challenge.wav")
# extract_hidden_bits("challenge.wav")
# extract_frequency_data("challenge.wav", target_freq=1000)
```

### 4.4 SSTV (Slow-Scan Television) Decoding

```
When you hear warbling/buzzing tones that sound like a fax machine:
  -> Execute SSTV decoding
  -> This encodes images in audio

Linux:
  # Install qsstv
  sudo apt install qsstv
  # Play audio into qsstv (use pavucontrol to route audio)
  qsstv

Python alternative:
  pip install sstv
  sstv -d audio.wav -o decoded_image.png

Command line:
  # Convert to correct format first
  sox input.wav -r 44100 -b 16 -c 1 sstv_input.wav
```

### 4.5 Morse Code Audio Decoder

```python
#!/usr/bin/env python3
"""Decode Morse code from audio files (tone-based encoding)."""
import numpy as np
import wave
import struct

MORSE_TABLE = {
    '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
    '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
    '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
    '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
    '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
    '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
    '...--': '3', '....-': '4', '.....': '5', '-....': '6',
    '--...': '7', '---..': '8', '----.': '9',
    '{': '{', '}': '}', '_': '_',
}

def decode_morse_audio(filepath, tone_freq=800, threshold=0.3):
    """
    Decode Morse code from an audio file.
    Detects tone on/off patterns and converts to dots/dashes.
    """
    with wave.open(filepath, 'rb') as wf:
        sr = wf.getframerate()
        n_frames = wf.getnframes()
        raw = wf.readframes(n_frames)
        samples = np.array(struct.unpack(f'<{n_frames}h', raw), dtype=np.float64)
    
    # Normalize
    samples = samples / np.max(np.abs(samples))
    
    # Detect envelope (amplitude over time)
    window = int(sr * 0.01)  # 10ms windows
    envelope = []
    for i in range(0, len(samples) - window, window):
        chunk = samples[i:i + window]
        envelope.append(np.sqrt(np.mean(chunk ** 2)))
    
    envelope = np.array(envelope)
    
    # Convert to on/off states
    on_off = envelope > threshold
    
    # Find runs of on and off
    runs = []
    current = on_off[0]
    length = 1
    for i in range(1, len(on_off)):
        if on_off[i] == current:
            length += 1
        else:
            runs.append((current, length))
            current = on_off[i]
            length = 1
    runs.append((current, length))
    
    # Determine dit/dah threshold (dit is ~1 unit, dah is ~3 units)
    on_lengths = [l for state, l in runs if state]
    if not on_lengths:
        print("[-] No tones detected")
        return ""
    
    avg_on = np.median(on_lengths)
    dit_dah_threshold = avg_on * 2
    
    # Convert to Morse
    morse = ""
    for state, length in runs:
        if state:  # Tone on
            morse += "." if length < dit_dah_threshold else "-"
        else:  # Silence
            if length > dit_dah_threshold * 3:
                morse += " / "  # Word gap
            elif length > dit_dah_threshold:
                morse += " "    # Letter gap
    
    # Decode Morse to text
    words = morse.split(" / ")
    decoded = ""
    for word in words:
        letters = word.strip().split()
        for letter in letters:
            decoded += MORSE_TABLE.get(letter, '?')
        decoded += " "
    
    print(f"[+] Morse: {morse}")
    print(f"[+] Decoded: {decoded.strip()}")
    return decoded.strip()

# Usage:
# decode_morse_audio("morse_challenge.wav")
```

---

## 5. Network Capture Analysis

### 5.1 Wireshark Display Filters

| Scenario | Filter |
|---|---|
| HTTP traffic only | `http` |
| HTTP POST requests | `http.request.method == "POST"` |
| HTTP GET requests | `http.request.method == "GET"` |
| HTTP with specific host | `http.host contains "target.com"` |
| HTTP response with flag | `http contains "flag" or http contains "FDC"` |
| HTTP file uploads | `http.content_type contains "multipart"` |
| DNS queries | `dns` |
| DNS queries for specific domain | `dns.qry.name contains "target.com"` |
| DNS TXT records | `dns.txt` |
| DNS exfiltration (long subdomains) | `dns.qry.name.len > 50` |
| TCP stream | `tcp.stream eq 0` |
| FTP traffic | `ftp` |
| FTP data transfer | `ftp-data` |
| FTP credentials | `ftp.request.command == "USER" or ftp.request.command == "PASS"` |
| SMTP traffic | `smtp` |
| TLS/SSL handshake | `tls.handshake` |
| Specific IP source | `ip.src == 192.168.1.100` |
| Specific IP destination | `ip.dst == 10.0.0.1` |
| TCP SYN packets (port scan) | `tcp.flags.syn == 1 and tcp.flags.ack == 0` |
| ICMP traffic | `icmp` |
| Telnet traffic | `telnet` |
| SSH traffic | `ssh` |
| SMB traffic | `smb or smb2` |
| Packets with specific string | `frame contains "password"` |
| USB traffic | `usb` |
| USB keyboard data | `usb.transfer_type == 0x01 and usb.data_len == 8` |

### 5.2 tshark Command-Line Analysis

```bash
# Extract all HTTP objects (files downloaded)
tshark -r capture.pcap --export-objects "http,./exported_files"

# Extract all SMB objects
tshark -r capture.pcap --export-objects "smb,./smb_files"

# Extract all FTP-DATA content
tshark -r capture.pcap -Y "ftp-data" -T fields -e data > ftp_data.hex

# List all HTTP requests
tshark -r capture.pcap -Y "http.request" -T fields \
  -e frame.number -e ip.src -e http.request.method \
  -e http.host -e http.request.uri

# Extract POST data
tshark -r capture.pcap -Y "http.request.method == POST" -T fields \
  -e http.file_data

# Extract DNS queries
tshark -r capture.pcap -Y "dns.qry.name" -T fields \
  -e dns.qry.name | sort -u

# Extract DNS TXT record answers (data exfiltration)
tshark -r capture.pcap -Y "dns.txt" -T fields -e dns.txt

# Follow TCP stream (stream 0)
tshark -r capture.pcap -z "follow,tcp,ascii,0" -q

# Extract all unique IP addresses
tshark -r capture.pcap -T fields -e ip.src -e ip.dst | sort -u

# Extract HTTP cookies
tshark -r capture.pcap -Y "http.cookie" -T fields \
  -e ip.src -e http.cookie

# Decrypt TLS traffic with key log file
tshark -r capture.pcap -o "tls.keylog_file:sslkeys.log" \
  -Y "http" -T fields -e http.request.uri -e http.file_data

# Extract credentials from various protocols
tshark -r capture.pcap -Y "ftp.request.command == USER || ftp.request.command == PASS" \
  -T fields -e ftp.request.command -e ftp.request.arg

# USB keyboard extraction (HID data)
tshark -r capture.pcap -Y "usb.capdata && usb.data_len == 8" \
  -T fields -e usb.capdata
```

### 5.3 DNS Exfiltration Extraction Script

```python
#!/usr/bin/env python3
"""
Extract data hidden in DNS queries (DNS tunneling / exfiltration).
Attackers encode data as subdomain labels in DNS queries.
"""
import re
import base64
import subprocess

def extract_dns_exfil(pcap_path, domain_filter=""):
    """
    Extract and decode data from DNS query subdomains.
    Common patterns:
      - Hex-encoded subdomains: aabbccdd.evil.com
      - Base64-encoded subdomains: dGVzdA==.evil.com
      - Base32-encoded subdomains: ORSXG5A=.evil.com
    """
    # Extract DNS queries using tshark
    cmd = f'tshark -r "{pcap_path}" -Y "dns.qry.name" -T fields -e dns.qry.name'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    queries = result.stdout.strip().split('\n')
    print(f"[+] Found {len(queries)} DNS queries")
    
    # Filter for the exfiltration domain
    if domain_filter:
        queries = [q for q in queries if domain_filter in q]
        print(f"[+] Filtered to {len(queries)} queries matching '{domain_filter}'")
    
    # Extract subdomain parts (data before the main domain)
    encoded_parts = []
    for query in queries:
        parts = query.strip().split('.')
        if domain_filter:
            # Take everything before the filter domain
            domain_parts = domain_filter.split('.')
            idx = len(parts) - len(domain_parts)
            data_parts = parts[:idx]
        else:
            # Take all parts except last two (domain.tld)
            data_parts = parts[:-2]
        
        if data_parts:
            encoded_parts.append('.'.join(data_parts))
    
    if not encoded_parts:
        print("[-] No exfiltration data found")
        return ""
    
    # Concatenate all parts
    raw_data = ''.join(encoded_parts)
    # Remove dots within data
    raw_data_nodots = raw_data.replace('.', '')
    
    print(f"[+] Concatenated data ({len(raw_data_nodots)} chars): {raw_data_nodots[:80]}...")
    
    # Try different decodings
    print("\n[*] Attempting decodings:")
    
    # Hex
    try:
        decoded = bytes.fromhex(raw_data_nodots).decode('utf-8', errors='replace')
        print(f"  [+] Hex: {decoded[:200]}")
    except Exception:
        pass
    
    # Base64
    try:
        padded = raw_data_nodots + '=' * (-len(raw_data_nodots) % 4)
        decoded = base64.b64decode(padded).decode('utf-8', errors='replace')
        print(f"  [+] Base64: {decoded[:200]}")
    except Exception:
        pass
    
    # Base32
    try:
        padded = raw_data_nodots.upper() + '=' * (-len(raw_data_nodots) % 8)
        decoded = base64.b32decode(padded).decode('utf-8', errors='replace')
        print(f"  [+] Base32: {decoded[:200]}")
    except Exception:
        pass
    
    # Raw ASCII
    print(f"  [+] Raw: {raw_data_nodots[:200]}")
    
    return raw_data_nodots

# Usage:
# extract_dns_exfil("capture.pcap", domain_filter="evil.com")
```

### 5.4 TLS Decryption with Key Log

```
When you receive a PCAP with TLS-encrypted traffic AND a key log file:
  -> Execute TLS decryption in Wireshark or tshark
  -> Use these exact steps:

Wireshark GUI:
  1. Edit -> Preferences -> Protocols -> TLS
  2. Set "(Pre)-Master-Secret log filename" to the provided key log file
  3. Apply -> All TLS traffic is now decrypted
  4. Filter with: http or http2

tshark CLI:
  tshark -r capture.pcap \
    -o "tls.keylog_file:/path/to/sslkeys.log" \
    -Y "http" -T fields \
    -e http.request.method -e http.host -e http.request.uri \
    -e http.file_data

Key log file format (SSLKEYLOGFILE):
  CLIENT_RANDOM <hex_random> <hex_master_secret>
  
  This file is generated by browsers/curl when SSLKEYLOGFILE env var is set:
    export SSLKEYLOGFILE=/tmp/sslkeys.log
    curl https://target.com
```

### 5.5 USB Keyboard Capture Decoder

```python
#!/usr/bin/env python3
"""
Decode USB HID keyboard data from a PCAP capture.
Extracts keystrokes from USB keyboard traffic.
"""
import subprocess

# USB HID Keyboard scan code mapping
USB_HID_KEYS = {
    0x04: ('a', 'A'), 0x05: ('b', 'B'), 0x06: ('c', 'C'), 0x07: ('d', 'D'),
    0x08: ('e', 'E'), 0x09: ('f', 'F'), 0x0A: ('g', 'G'), 0x0B: ('h', 'H'),
    0x0C: ('i', 'I'), 0x0D: ('j', 'J'), 0x0E: ('k', 'K'), 0x0F: ('l', 'L'),
    0x10: ('m', 'M'), 0x11: ('n', 'N'), 0x12: ('o', 'O'), 0x13: ('p', 'P'),
    0x14: ('q', 'Q'), 0x15: ('r', 'R'), 0x16: ('s', 'S'), 0x17: ('t', 'T'),
    0x18: ('u', 'U'), 0x19: ('v', 'V'), 0x1A: ('w', 'W'), 0x1B: ('x', 'X'),
    0x1C: ('y', 'Y'), 0x1D: ('z', 'Z'),
    0x1E: ('1', '!'), 0x1F: ('2', '@'), 0x20: ('3', '#'), 0x21: ('4', '$'),
    0x22: ('5', '%'), 0x23: ('6', '^'), 0x24: ('7', '&'), 0x25: ('8', '*'),
    0x26: ('9', '('), 0x27: ('0', ')'),
    0x28: ('\n', '\n'),  # Enter
    0x2C: (' ', ' '),    # Space
    0x2D: ('-', '_'), 0x2E: ('=', '+'), 0x2F: ('[', '{'), 0x30: (']', '}'),
    0x31: ('\\', '|'), 0x33: (';', ':'), 0x34: ("'", '"'), 0x35: ('`', '~'),
    0x36: (',', '<'), 0x37: ('.', '>'), 0x38: ('/', '?'),
}

def decode_usb_keyboard(pcap_path):
    """Extract and decode USB keyboard data from PCAP."""
    # Extract HID data using tshark
    cmd = (f'tshark -r "{pcap_path}" '
           f'-Y "usb.capdata && usb.data_len == 8" '
           f'-T fields -e usb.capdata')
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if not result.stdout.strip():
        # Try alternative field name
        cmd = (f'tshark -r "{pcap_path}" '
               f'-Y "usbhid.data" '
               f'-T fields -e usbhid.data')
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    lines = result.stdout.strip().split('\n')
    print(f"[+] Found {len(lines)} USB HID packets")
    
    typed_text = ""
    for line in lines:
        line = line.strip().replace(':', '')
        if not line or len(line) < 16:
            continue
        
        try:
            data = bytes.fromhex(line)
        except ValueError:
            continue
        
        if len(data) < 4:
            continue
        
        modifier = data[0]
        keycode = data[2]
        
        if keycode == 0:
            continue
        
        shift = modifier & 0x22  # Left Shift or Right Shift
        
        if keycode in USB_HID_KEYS:
            char = USB_HID_KEYS[keycode][1 if shift else 0]
            typed_text += char
        elif keycode == 0x2A:  # Backspace
            typed_text = typed_text[:-1]
    
    print(f"[+] Decoded keystrokes: {typed_text}")
    return typed_text

# Usage:
# decode_usb_keyboard("usb_capture.pcap")
```

---

## 6. Memory Forensics

### 6.1 Volatility 3 Quick Reference

```bash
# Install: pip install volatility3

# Identify the OS profile
vol -f memory.raw banners.Banners
vol -f memory.raw windows.info.Info

# Process listing
vol -f memory.raw windows.pslist.PsList
vol -f memory.raw windows.pstree.PsTree
vol -f memory.raw windows.psscan.PsScan       # Find hidden processes

# Command line arguments
vol -f memory.raw windows.cmdline.CmdLine

# Network connections
vol -f memory.raw windows.netscan.NetScan
vol -f memory.raw windows.netstat.NetStat

# File listing and extraction
vol -f memory.raw windows.filescan.FileScan | grep -i "flag\|password\|secret"
vol -f memory.raw windows.dumpfiles.DumpFiles --virtaddr 0xADDRESS

# Registry
vol -f memory.raw windows.registry.hivelist.HiveList
vol -f memory.raw windows.hashdump.Hashdump    # Extract password hashes

# Strings search
strings -e l memory.raw | grep -i "flag{" > strings_output.txt
```

### 6.2 Volatility 2 (Legacy)

```bash
# Identify profile
vol.py -f memory.raw imageinfo

# Process listing
vol.py -f memory.raw --profile=Win7SP1x64 pslist
vol.py -f memory.raw --profile=Win7SP1x64 pstree

# Dump process memory
vol.py -f memory.raw --profile=Win7SP1x64 memdump -p PID -D ./dump/

# Extract files
vol.py -f memory.raw --profile=Win7SP1x64 filescan | grep -i flag
vol.py -f memory.raw --profile=Win7SP1x64 dumpfiles -Q 0xADDR -D ./files/

# Clipboard contents
vol.py -f memory.raw --profile=Win7SP1x64 clipboard

# Internet Explorer history
vol.py -f memory.raw --profile=Win7SP1x64 iehistory

# Console command history
vol.py -f memory.raw --profile=Win7SP1x64 consoles
```

---

## 7. Disk & Filesystem Forensics

### 7.1 Disk Image Analysis

```bash
# Mount disk image
sudo mount -o loop,ro disk.img /mnt/evidence

# File system info
fsstat disk.img
fls -r disk.img                     # List all files (including deleted)
fls -r -d disk.img                  # List deleted files only

# Recover deleted files
tsk_recover -r disk.img ./recovered/

# Timeline analysis
fls -r -m "/" disk.img > bodyfile.txt
mactime -b bodyfile.txt > timeline.csv

# Search for specific file content
sigfind -b 512 disk.img             # Find file signatures
```

### 7.2 Ext4 Filesystem Recovery

```bash
# List deleted files with inode info
debugfs disk.img
debugfs: lsdel                       # List deleted inodes
debugfs: dump <inode> recovered.txt  # Recover by inode

# Using extundelete
extundelete disk.img --restore-all
extundelete disk.img --restore-file path/to/file
```

---

## 8. Document & Archive Analysis

### 8.1 PDF Analysis

```bash
# Extract text
pdftotext document.pdf output.txt

# Analyze structure
pdf-parser.py document.pdf
pdf-parser.py -s "/JavaScript" document.pdf    # Find JavaScript
pdf-parser.py -s "/OpenAction" document.pdf    # Find auto-actions
pdf-parser.py -o 5 document.pdf                # Examine object 5

# Extract embedded files/streams
pdf-parser.py -f document.pdf                  # Filter streams
peepdf document.pdf                            # Interactive analysis

# Check for steganography
binwalk document.pdf
strings document.pdf | grep -i "flag"
```

### 8.2 Office Document Analysis

```bash
# Extract macros
olevba document.docx
olevba document.xlsm

# Extract embedded objects
oleobj document.docx

# Unzip and inspect (OOXML format)
unzip document.docx -d document_extracted/
cat document_extracted/word/document.xml       # Main content

# Extract hidden text
python3 -c "
import zipfile
z = zipfile.ZipFile('document.docx')
for name in z.namelist():
    if 'document.xml' in name or 'comments' in name:
        print(z.read(name).decode(errors='replace'))
"
```

---

## 9. Metadata Extraction

### 9.1 ExifTool Comprehensive Commands

```bash
# All metadata
exiftool file.jpg

# Specific fields
exiftool -GPS* file.jpg             # GPS coordinates
exiftool -Comment file.jpg          # Comments (common stego hiding spot)
exiftool -Author file.jpg
exiftool -CreateDate file.jpg

# Write/modify metadata (for crafting challenges)
exiftool -Comment="hidden_data" file.jpg
exiftool -Author="flag_here" file.jpg

# Extract thumbnail
exiftool -b -ThumbnailImage file.jpg > thumbnail.jpg

# Remove all metadata
exiftool -all= file.jpg

# Recursive search in directory
exiftool -r -Comment -FileName ./images/ | grep -B1 -i "flag"
```

### 9.2 Quick Python Metadata Reader

```python
#!/usr/bin/env python3
"""Extract and display all metadata from image files."""
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

def extract_all_metadata(image_path):
    """Extract every metadata field from an image."""
    img = Image.open(image_path)
    
    # Basic info
    print(f"[+] Format: {img.format}")
    print(f"[+] Size: {img.size[0]}x{img.size[1]}")
    print(f"[+] Mode: {img.mode}")
    
    # PNG text chunks
    if hasattr(img, 'text'):
        for key, value in img.text.items():
            print(f"[+] PNG Text '{key}': {value}")
    
    # EXIF data
    exif = img._getexif()
    if exif:
        print("\n[+] EXIF Data:")
        for tag_id, value in exif.items():
            tag = TAGS.get(tag_id, tag_id)
            print(f"    {tag}: {value}")
    
    # Check for appended data after image
    with open(image_path, 'rb') as f:
        data = f.read()
    
    # For JPEG: check after FF D9
    if data[:2] == b'\xff\xd8':
        eoi = data.find(b'\xff\xd9')
        if eoi != -1 and eoi + 2 < len(data):
            extra = data[eoi + 2:]
            print(f"\n[!] {len(extra)} bytes found after JPEG footer!")
            print(f"    Preview: {extra[:100]}")

# Usage:
# extract_all_metadata("challenge.jpg")
```
