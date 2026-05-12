import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding


def xor(data, key=None):
    if key is None:
        key = os.urandom(16)
    elif isinstance(key, int):
        key = bytes([key])
    out = bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
    return out, {'method': 'xor', 'xor_key': key, 'out_len': len(out)}


def aes(data, key=None, iv=None):
    if key is None:
        key = os.urandom(32)
    if iv is None:
        iv = os.urandom(16)
    # pkcs7 pad to 16-byte blocks
    padder = sym_padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return ct, {'method': 'aes', 'aes_key': key, 'aes_iv': iv, 'out_len': len(ct)}


def rc4(data, key=None):
    if key is None:
        key = os.urandom(16)
    # rc4 keystream
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % len(key)]) % 256
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        out.append(byte ^ S[(S[i] + S[j]) % 256])
    return bytes(out), {'method': 'rc4', 'rc4_key': key, 'out_len': len(out)}


def caesar(data, shift=None):
    if shift is None:
        shift = os.urandom(1)[0] % 254 + 1
    out = bytes((b + shift) % 256 for b in data)
    return out, {'method': 'caesar', 'caesar_shift': shift, 'out_len': len(out)}


# TODO: chacha20 for cross-platform payloads
METHODS = {
    'xor': xor,
    'aes': aes,
    'rc4': rc4,
    'caesar': caesar,
}


def chain(data, methods, key=None):
    """Encrypt with multiple methods in order. Returns (ciphertext, [meta_list]).
    To decrypt, reverse the meta_list and apply each method's inverse.
    If key is provided, it's used for the first encryption layer."""
    if not methods:
        # no encryption -- return raw with dummy metadata
        return data, [{'method': 'none', 'out_len': len(data)}]
    meta_chain = []
    current = data
    for idx, name in enumerate(methods):
        fn = METHODS.get(name)
        if fn is None:
            raise ValueError(f'unknown encryption method: {name}')
        if idx == 0 and key is not None:
            if name == 'caesar':
                current, meta = fn(current, shift=int.from_bytes(key[:1], 'big') % 254 + 1)
            else:
                current, meta = fn(current, key=key)
        else:
            current, meta = fn(current)
        meta_chain.append(meta)
    return current, meta_chain
