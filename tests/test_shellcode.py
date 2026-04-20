import os
import tempfile
import pytest
from malforge.shellcode import from_file, from_hex, from_csharp


def test_from_hex_raw():
    assert from_hex('fc4883e4f0') == b'\xfc\x48\x83\xe4\xf0'


def test_from_hex_escaped():
    assert from_hex('\\xfc\\x48\\x83') == b'\xfc\x48\x83'


def test_from_hex_0x_prefix():
    assert from_hex('0xfc 0x48 0x83') == b'\xfc\x48\x83'


def test_from_hex_mixed_whitespace():
    assert from_hex('fc 48\n83\re4') == b'\xfc\x48\x83\xe4'


def test_from_hex_empty():
    assert from_hex('') == b''


def test_from_hex_single_byte():
    assert from_hex('ff') == b'\xff'


def test_from_hex_invalid():
    with pytest.raises(ValueError):
        from_hex('zz')


def test_from_csharp_basic():
    result = from_csharp('0xfc,0x48,0x83')
    assert result == b'\xfc\x48\x83'


def test_from_csharp_braces():
    result = from_csharp('{ 0xfc, 0x48, 0x83 }')
    assert result == b'\xfc\x48\x83'


def test_from_csharp_multiline():
    text = '''byte[] buf = new byte[] {
        0xfc, 0x48, 0x83, 0xe4,
        0xf0, 0xe8
    };'''
    result = from_csharp(text)
    assert result == b'\xfc\x48\x83\xe4\xf0\xe8'


def test_from_csharp_no_bytes(capsys):
    with pytest.raises(SystemExit):
        from_csharp('no hex here')


def test_from_file_reads_binary():
    data = os.urandom(128)
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        f.write(data)
        path = f.name
    assert from_file(path) == data
    os.unlink(path)


def test_from_file_not_found():
    with pytest.raises(SystemExit):
        from_file('/tmp/nonexistent_malforge_test_file.bin')


def test_from_file_empty():
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as f:
        path = f.name
    with pytest.raises(SystemExit):
        from_file(path)
    os.unlink(path)
