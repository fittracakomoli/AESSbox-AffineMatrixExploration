from pydantic import BaseModel, field_validator
from typing import List, Optional

# --- Model untuk Request Enkripsi ---
class EncryptRequest(BaseModel):
    sbox: List[int]      # Array S-box custom (harus 256 angka)
    plaintext: str       # Teks biasa yang ingin dienkripsi
    key: str             # Kunci rahasia (akan dipadding/truncate otomatis jadi 16 byte)

    # Validator: Memastikan panjang S-box tepat 256
    @field_validator('sbox')
    def check_sbox_length(cls, v):
        if len(v) != 256:
            raise ValueError('S-box harus memiliki tepat 256 elemen sesuai standar AES.')
        return v

# --- Model untuk Request Dekripsi ---
class DecryptRequest(BaseModel):
    sbox: List[int]      # S-box yang SAMA saat enkripsi
    ciphertext: str      # String Hexadesimal hasil enkripsi
    key: str             # Kunci yang SAMA

    @field_validator('sbox')
    def check_sbox_length(cls, v):
        if len(v) != 256:
            raise ValueError('S-box harus memiliki tepat 256 elemen sesuai standar AES.')
        return v

# --- Model untuk Response (Output) ---
class CipherResponse(BaseModel):
    result: str          # Berisi Ciphertext (Hex) saat enkripsi, atau Plaintext saat dekripsi

# --- Model untuk Request Enkripsi Gambar ---
class EncryptImageRequest(BaseModel):
    sbox: List[int]
    image_base64: str
    key: str
    mime_type: Optional[str] = None
    filename: Optional[str] = None

    @field_validator('sbox')
    def check_image_sbox_length(cls, v):
        if len(v) != 256:
            raise ValueError('S-box harus memiliki tepat 256 elemen sesuai standar AES.')
        return v

# --- Model untuk Request Dekripsi Gambar ---
class DecryptImageRequest(BaseModel):
    sbox: List[int]
    ciphertext_base64: str
    key: str
    mime_type: Optional[str] = None

    @field_validator('sbox')
    def check_image_sbox_length(cls, v):
        if len(v) != 256:
            raise ValueError('S-box harus memiliki tepat 256 elemen sesuai standar AES.')
        return v

class ImageCipherResponse(BaseModel):
    result: str
    mime_type: Optional[str] = None
    filename: Optional[str] = None
