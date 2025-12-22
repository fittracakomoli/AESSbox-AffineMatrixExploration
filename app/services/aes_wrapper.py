# app/services/aes_wrapper.py
from app.utils.aes_engine import AESEngine
from typing import List

def _normalize_key(key_str: str) -> bytes:
    key_bytes = key_str.encode('utf-8')
    if len(key_bytes) > 16:
        return key_bytes[:16]
    return key_bytes.ljust(16, b'\0')

def pad(data: bytes) -> bytes:
    """PKCS#7 Padding"""
    length = 16 - (len(data) % 16)
    return data + bytes([length] * length)

def unpad(data: bytes) -> bytes:
    """Remove PKCS#7 Padding"""
    length = data[-1]
    if length > 16: return data # Error safety
    return data[:-length]

def aes_encrypt_custom(plaintext_str: str, key_str: str, sbox: List[int]) -> str:
    # 1. Init Engine
    engine = AESEngine(_normalize_key(key_str), sbox)

    # 2. Prepare Plaintext (Padding)
    pt_bytes = pad(plaintext_str.encode('utf-8'))

    # 3. Encrypt Block by Block (ECB Mode Simplification)
    encrypted_blocks = []
    for i in range(0, len(pt_bytes), 16):
        block = pt_bytes[i:i+16]
        encrypted_blocks.append(engine.encrypt_block(block))

    return b"".join(encrypted_blocks).hex()

def aes_decrypt_custom(ciphertext_hex: str, key_str: str, sbox: List[int]) -> str:
    # 1. Init Engine
    engine = AESEngine(_normalize_key(key_str), sbox)

    # 2. Decode Hex
    try:
        ct_bytes = bytes.fromhex(ciphertext_hex)
    except:
        return "Error: Invalid Hex"

    # 3. Decrypt Block by Block
    decrypted_blocks = []
    for i in range(0, len(ct_bytes), 16):
        block = ct_bytes[i:i+16]
        decrypted_blocks.append(engine.decrypt_block(block))

    full_decrypted = b"".join(decrypted_blocks)

    # 4. Unpad
    return unpad(full_decrypted).decode('utf-8', errors='ignore')

def aes_encrypt_bytes(data: bytes, key_str: str, sbox: List[int]) -> bytes:
    engine = AESEngine(_normalize_key(key_str), sbox)
    padded = pad(data)
    encrypted_blocks = []
    for i in range(0, len(padded), 16):
        block = padded[i:i+16]
        encrypted_blocks.append(engine.encrypt_block(block))
    return b"".join(encrypted_blocks)

def aes_decrypt_bytes(ciphertext: bytes, key_str: str, sbox: List[int]) -> bytes:
    engine = AESEngine(_normalize_key(key_str), sbox)
    decrypted_blocks = []
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_blocks.append(engine.decrypt_block(block))
    full_decrypted = b"".join(decrypted_blocks)
    return unpad(full_decrypted)

def aes_encrypt_bytes_no_pad(data: bytes, key_str: str, sbox: List[int]) -> bytes:
    """Encrypt bytes without padding; tail bytes (len % 16) are left unchanged."""
    engine = AESEngine(_normalize_key(key_str), sbox)
    full_len = len(data) - (len(data) % 16)
    encrypted_blocks = []
    for i in range(0, full_len, 16):
        block = data[i:i+16]
        encrypted_blocks.append(engine.encrypt_block(block))
    return b"".join(encrypted_blocks) + data[full_len:]

def aes_decrypt_bytes_no_pad(ciphertext: bytes, key_str: str, sbox: List[int]) -> bytes:
    """Decrypt bytes without padding; tail bytes (len % 16) are left unchanged."""
    engine = AESEngine(_normalize_key(key_str), sbox)
    full_len = len(ciphertext) - (len(ciphertext) % 16)
    decrypted_blocks = []
    for i in range(0, full_len, 16):
        block = ciphertext[i:i+16]
        decrypted_blocks.append(engine.decrypt_block(block))
    return b"".join(decrypted_blocks) + ciphertext[full_len:]
