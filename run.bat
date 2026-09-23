@echo off
setlocal
chcp 65001 > nul
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

set "SCRIPT_DIR=%~dp0"
set "VENV_PY=%SCRIPT_DIR%.venv\Scripts\python.exe"

if not exist "%VENV_PY%" (
    echo [!] Virtual environment not found at .venv\Scripts\python.exe
    echo [*] Please create it first: python -m venv .venv ^&^& pip install -r requirements.txt
    exit /b 1
)

if "%~1"=="" (
    echo ======================================================================
    echo   CTF Toolkit - Quick Runner [.venv]
    echo ======================================================================
    echo   Usage: run.bat [script.py] [arguments]
    echo.
    echo   Examples:
    echo     run.bat tools\decoder.py
    echo     run.bat tools\decoder.py -i "SGVsbG8="
    echo     run.bat Web\fuzzer.py -u "http://target/FUZZ" -w wordlist.txt
    echo     run.bat Reverse\solve.py -f crackme
    echo     run.bat Crypto\solve.py -f ciphertext.txt
    echo     run.bat Forensics\solve.py -f capture.pcap
    echo     run.bat Pwn\exploit.py
    echo ======================================================================
    exit /b 0
)

"%VENV_PY%" %*
