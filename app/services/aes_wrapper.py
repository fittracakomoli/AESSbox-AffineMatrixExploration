# app/services/aes_wrapper.py
from app.utils.aes_engine import AESEngine
from typing import List

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
    # 1. Prepare Key (Fix to 16 bytes/128 bit)
    key_bytes = key_str.encode('utf-8')
    if len(key_bytes) > 16:
        key_bytes = key_bytes[:16]
    else:
        key_bytes = key_bytes.ljust(16, b'\0') # Padding nol jika kurang

    # 2. Init Engine
    engine = AESEngine(key_bytes, sbox)
    
    # 3. Prepare Plaintext (Padding)
    pt_bytes = pad(plaintext_str.encode('utf-8'))
    
    # 4. Encrypt Block by Block (ECB Mode Simplification)
    encrypted_blocks = []
    for i in range(0, len(pt_bytes), 16):
        block = pt_bytes[i:i+16]
        encrypted_blocks.append(engine.encrypt_block(block))
        
    return b"".join(encrypted_blocks).hex()

def aes_decrypt_custom(ciphertext_hex: str, key_str: str, sbox: List[int]) -> str:
    # 1. Prepare Key
    key_bytes = key_str.encode('utf-8')
    if len(key_bytes) > 16:
        key_bytes = key_bytes[:16]
    else:
        key_bytes = key_bytes.ljust(16, b'\0')

    # 2. Init Engine
    engine = AESEngine(key_bytes, sbox)
    
    # 3. Decode Hex
    try:
        ct_bytes = bytes.fromhex(ciphertext_hex)
    except:
        return "Error: Invalid Hex"

    # 4. Decrypt Block by Block
    decrypted_blocks = []
    for i in range(0, len(ct_bytes), 16):
        block = ct_bytes[i:i+16]
        decrypted_blocks.append(engine.decrypt_block(block))
        
    full_decrypted = b"".join(decrypted_blocks)
    
    # 5. Unpad
    return unpad(full_decrypted).decode('utf-8', errors='ignore')