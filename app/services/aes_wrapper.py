from typing import List
from app.utils.aes_engine import AESEngine

# --- FUNGSI PADDING (PKCS#7) ---
def pad(data: bytes) -> bytes:
    block_size = 16
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([padding_len] * padding_len)
    return data + padding

def unpad(data: bytes) -> bytes:
    padding_len = data[-1]
    if padding_len > 16 or padding_len == 0:
        return data # Safety return jika padding rusak
    return data[:-padding_len]

# --- FUNGSI UTAMA SESUAI PERMINTAAN ---

def aes_encrypt_custom(plaintext: str, sbox: List[int], key: str) -> str:
    """
    Enkripsi AES-128 dengan S-box Custom.
    Params:
      plaintext (str): Teks asli.
      sbox (List[int]): Array 256 integer.
      key (str): Kunci rahasia (string bebas).
    Returns:
      str: Ciphertext dalam format Hexadesimal.
    """
    # 1. Format Key menjadi 16 Bytes
    key_bytes = key.encode('utf-8')
    if len(key_bytes) > 16:
        key_bytes = key_bytes[:16]
    else:
        key_bytes = key_bytes.ljust(16, b'\0')

    # 2. Inisialisasi Engine
    engine = AESEngine(key_bytes, sbox)

    # 3. Padding Plaintext
    pt_bytes = pad(plaintext.encode('utf-8'))

    # 4. Enkripsi per Blok (Mode ECB)
    encrypted_bytes = bytearray()
    for i in range(0, len(pt_bytes), 16):
        block = pt_bytes[i : i+16]
        encrypted_block = engine.encrypt_block(block)
        encrypted_bytes.extend(encrypted_block)

    # 5. Return Hex String
    return encrypted_bytes.hex()


def aes_decrypt_custom(ciphertext: str, sbox: List[int], key: str) -> str:
    """
    Dekripsi AES-128 dengan S-box Custom.
    Params:
      ciphertext (str): Hex string hasil enkripsi.
      sbox (List[int]): Array 256 integer (HARUS SAMA dengan saat enkripsi).
      key (str): Kunci rahasia (HARUS SAMA).
    Returns:
      str: Plaintext asli.
    """
    # 1. Format Key menjadi 16 Bytes
    key_bytes = key.encode('utf-8')
    if len(key_bytes) > 16:
        key_bytes = key_bytes[:16]
    else:
        key_bytes = key_bytes.ljust(16, b'\0')

    # 2. Inisialisasi Engine (Otomatis generate Inverse S-box)
    engine = AESEngine(key_bytes, sbox)

    # 3. Decode Hex ke Bytes
    try:
        ct_bytes = bytes.fromhex(ciphertext)
    except ValueError:
        return "Error: Ciphertext bukan format Hex yang valid."

    # 4. Dekripsi per Blok
    decrypted_bytes = bytearray()
    for i in range(0, len(ct_bytes), 16):
        block = ct_bytes[i : i+16]
        decrypted_block = engine.decrypt_block(block)
        decrypted_bytes.extend(decrypted_block)

    # 5. Unpad dan Return String
    return unpad(decrypted_bytes).decode('utf-8', errors='ignore')