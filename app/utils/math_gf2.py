# app/utils/math_gf2.py
import random
from typing import List
from app.core.constants import AES_IRREDUCIBLE_POLY, AES_CONSTANT

def gmul_inverse(val: int) -> int:
    """Menghitung Invers Multiplikatif di GF(2^8)."""
    if val == 0: return 0
    for i in range(1, 256):
        a, b, p = val, i, 0
        for _ in range(8):
            if b & 1: p ^= a
            hi_bit = a & 0x80
            a <<= 1
            if hi_bit: a ^= AES_IRREDUCIBLE_POLY
            b >>= 1
        if (p % 256) == 1: return i
    return 0

# Pre-compute tabel invers saat modul di-load
INVERSE_TABLE = [gmul_inverse(x) for x in range(256)]

def generate_random_affine_matrix() -> List[List[int]]:
    """Generate matriks 8x8 random (0/1)."""
    return [[random.randint(0, 1) for _ in range(8)] for _ in range(8)]

def is_invertible_gf2(matrix: List[List[int]]) -> bool:
    """Cek apakah matriks invertible (Determinan != 0) di GF(2)."""
    n = 8
    m = [row[:] for row in matrix] # Copy matrix
    for col in range(n):
        pivot = -1
        for row in range(col, n):
            if m[row][col] == 1:
                pivot = row
                break
        if pivot == -1: return False
        m[col], m[pivot] = m[pivot], m[col]
        for row in range(n):
            if row != col and m[row][col] == 1:
                for k in range(n):
                    m[row][k] ^= m[col][k]
    return True

def apply_affine_transform(byte_val: int, matrix: List[List[int]]) -> int:
    """Rumus: B(x) = (K * X^-1 + C) mod 2"""
    result = 0
    bits = [(byte_val >> i) & 1 for i in range(8)]
    for row in range(8):
        val = 0
        for col in range(8):
            val ^= matrix[row][col] & bits[col]
        val ^= (AES_CONSTANT >> row) & 1
        if val: result |= (1 << row)
    return result