$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
$venvPy = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

if (-not (Test-Path $venvPy)) {
    Write-Host "[!] Virtual environment not found at $venvPy" -ForegroundColor Red
    Write-Host "[*] Run: python -m venv .venv; pip install -r requirements.txt" -ForegroundColor Yellow
    exit 1
}

if ($args.Count -eq 0) {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "  CTF Toolkit - Quick Runner (.venv)" -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "  Usage: .\run.ps1 <script.py> [arguments]"
    Write-Host ""
    Write-Host "  Examples:"
    Write-Host "    .\run.ps1 tools\decoder.py"
    Write-Host "    .\run.ps1 tools\decoder.py -i 'SGVsbG8='"
    Write-Host "    .\run.ps1 Web\fuzzer.py -u 'http://target/FUZZ' -w wordlist.txt"
    Write-Host "    .\run.ps1 Reverse\solve.py -f crackme"
    Write-Host "    .\run.ps1 Crypto\solve.py -f ciphertext.txt"
    Write-Host "    .\run.ps1 Forensics\solve.py -f capture.pcap"
    Write-Host "    .\run.ps1 Pwn\exploit.py"
    Write-Host "======================================================================" -ForegroundColor Cyan
    return
}

& $venvPy $args
