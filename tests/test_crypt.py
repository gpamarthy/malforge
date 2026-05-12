import os
import pytest
from malforge.crypt import xor, aes, rc4, caesar, chain


SAMPLE = os.urandom(512)  # random shellcode stand-in


def test_xor_roundtrip():
    enc, meta = xor(SAMPLE)
    key = meta['xor_key']
    dec, _ = xor(enc, key=key)
    assert dec == SAMPLE


def test_xor_single_byte_key():
    enc, meta = xor(SAMPLE, key=0xfa)
    dec, _ = xor(enc, key=0xfa)
    assert dec == SAMPLE


def test_aes_roundtrip():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding

    enc, meta = aes(SAMPLE)
    key, iv = meta['aes_key'], meta['aes_iv']
    # manual decrypt to verify
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(enc) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    result = unpadder.update(padded) + unpadder.finalize()
    assert result == SAMPLE


def test_aes_output_longer():
    """AES adds PKCS7 padding, so ciphertext is always >= plaintext."""
    enc, meta = aes(SAMPLE)
    assert len(enc) >= len(SAMPLE)
    assert len(enc) % 16 == 0  # block-aligned


def test_rc4_roundtrip():
    enc, meta = rc4(SAMPLE)
    # rc4 is symmetric -- encrypt again with same key to decrypt
    dec, _ = rc4(enc, key=meta['rc4_key'])
    assert dec == SAMPLE


def test_caesar_roundtrip():
    enc, meta = caesar(SAMPLE)
    shift = meta['caesar_shift']
    dec, _ = caesar(enc, shift=(256 - shift))
    assert dec == SAMPLE


def test_chain_single():
    enc, meta_chain = chain(SAMPLE, ['xor'])
    assert len(meta_chain) == 1
    assert meta_chain[0]['method'] == 'xor'
    # decrypt
    dec, _ = xor(enc, key=meta_chain[0]['xor_key'])
    assert dec == SAMPLE


def test_chain_double():
    enc, meta_chain = chain(SAMPLE, ['xor', 'aes'])
    assert len(meta_chain) == 2
    assert meta_chain[0]['method'] == 'xor'
    assert meta_chain[1]['method'] == 'aes'


def test_chain_empty():
    enc, meta_chain = chain(SAMPLE, [])
    assert enc == SAMPLE
    assert meta_chain[0]['method'] == 'none'


def test_chain_unknown_method():
    with pytest.raises(ValueError, match='unknown encryption'):
        chain(SAMPLE, ['blowfish'])


class TestXor:
    def test_different_key_sizes(self):
        for klen in (1, 4, 16, 32):
            key = os.urandom(klen)
            enc, meta = xor(SAMPLE, key=key)
            dec, _ = xor(enc, key=key)
            assert dec == SAMPLE

    def test_zero_key_is_identity(self):
        enc, meta = xor(b'\xaa\xbb', key=b'\x00')
        assert enc == b'\xaa\xbb'

    def test_single_byte(self):
        enc, meta = xor(b'\xff', key=b'\x0f')
        assert enc == b'\xf0'


class TestAes:
    def test_block_alignment(self):
        for size in (1, 15, 16, 17, 31, 32, 33):
            data = os.urandom(size)
            enc, meta = aes(data)
            assert len(enc) % 16 == 0
            assert len(enc) >= size

    def test_custom_key_iv(self):
        key = os.urandom(32)
        iv = os.urandom(16)
        enc, meta = aes(SAMPLE, key=key, iv=iv)
        assert meta['aes_key'] == key
        assert meta['aes_iv'] == iv

    def test_empty_data(self):
        enc, meta = aes(b'')
        assert len(enc) == 16  # one full block of padding


class TestRc4:
    def test_various_key_sizes(self):
        for klen in (1, 8, 16, 32, 64):
            key = os.urandom(klen)
            enc, meta = rc4(SAMPLE, key=key)
            dec, _ = rc4(enc, key=key)
            assert dec == SAMPLE

    def test_preserves_length(self):
        enc, meta = rc4(SAMPLE)
        assert len(enc) == len(SAMPLE)


class TestCaesar:
    def test_shift_range(self):
        for _ in range(20):
            enc, meta = caesar(SAMPLE)
            shift = meta['caesar_shift']
            assert 1 <= shift <= 255

    def test_custom_shift(self):
        enc, meta = caesar(b'\x00\x01\x02', shift=10)
        assert enc == bytes([10, 11, 12])

    def test_wraps_at_256(self):
        enc, meta = caesar(b'\xff', shift=1)
        assert enc == b'\x00'

    def test_preserves_length(self):
        enc, meta = caesar(SAMPLE)
        assert len(enc) == len(SAMPLE)


class TestChainExtended:
    def test_triple_chain_roundtrip(self):
        enc, meta_chain = chain(SAMPLE, ['xor', 'aes', 'rc4'])
        assert len(meta_chain) == 3
        # decrypt in reverse: rc4 -> aes -> xor
        step3, _ = rc4(enc, key=meta_chain[2]['rc4_key'])

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding as sym_padding
        cipher = Cipher(algorithms.AES(meta_chain[1]['aes_key']),
                        modes.CBC(meta_chain[1]['aes_iv']))
        dec = cipher.decryptor()
        padded = dec.update(step3) + dec.finalize()
        unpadder = sym_padding.PKCS7(128).unpadder()
        step2 = unpadder.update(padded) + unpadder.finalize()

        step1, _ = xor(step2, key=meta_chain[0]['xor_key'])
        assert step1 == SAMPLE

    def test_chain_with_user_key(self):
        key = os.urandom(16)
        enc, meta_chain = chain(SAMPLE, ['xor'], key=key)
        assert meta_chain[0]['xor_key'] == key
        dec, _ = xor(enc, key=key)
        assert dec == SAMPLE

    def test_chain_user_key_first_layer_only(self):
        key = os.urandom(16)
        enc, meta_chain = chain(SAMPLE, ['xor', 'rc4'], key=key)
        assert meta_chain[0]['xor_key'] == key
        # second layer key should be auto-generated, not the user key
        assert meta_chain[1]['rc4_key'] != key

    def test_chain_user_key_aes(self):
        key = os.urandom(32)
        enc, meta_chain = chain(SAMPLE, ['aes'], key=key)
        assert meta_chain[0]['aes_key'] == key

    def test_same_method_chain(self):
        enc, meta_chain = chain(SAMPLE, ['xor', 'xor'])
        assert len(meta_chain) == 2
        # keys should be different (first is auto, second is auto)
        # just verify it doesn't crash and produces 2 distinct steps

    def test_all_four_methods(self):
        enc, meta_chain = chain(SAMPLE, ['xor', 'aes', 'rc4', 'caesar'])
        assert len(meta_chain) == 4
        assert [m['method'] for m in meta_chain] == ['xor', 'aes', 'rc4', 'caesar']

    def test_empty_data_chain(self):
        enc, meta_chain = chain(b'', ['xor'])
        assert enc == b''

    def test_single_byte_chain(self):
        enc, meta_chain = chain(b'\xcc', ['xor', 'caesar'])
        assert len(meta_chain) == 2
