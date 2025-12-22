# app/schemas/sbox.py
from pydantic import BaseModel, field_validator
from typing import List, Optional
from enum import Enum

class SBoxResponse(BaseModel):
    affine_matrix: List[List[int]]
    affine_vector: Optional[List[int]] = None
    sbox: List[int]
    is_bijective: bool
    is_balanced: bool

class SBoxCheckRequest(BaseModel):
    sbox: List[int]

    # Validasi input: Pastikan panjang array harus 256
    @field_validator('sbox')
    def check_length(cls, v):
        if len(v) != 256:
            raise ValueError('S-box harus memiliki tepat 256 elemen.')
        return v

class SBoxCheckResponse(BaseModel):
    is_bijective: bool
    is_balanced: bool
    bit_counts: List[int] # Menampilkan detail jumlah bit '1' per posisi

class SBoxUploadResponse(BaseModel):
    filename: str
    sbox: List[int]
    message: str

class ExportFormat(str, Enum):
    JSON = "json"
    CSV = "csv"
    TXT = "txt"
    XLSX = "xlsx"

class SBoxDownloadRequest(BaseModel):
    sbox: List[int]
    format: ExportFormat = ExportFormat.JSON

    @field_validator('sbox')
    def check_len(cls, v):
        if len(v) != 256:
            raise ValueError("S-box harus 256 elemen.")
        return v
