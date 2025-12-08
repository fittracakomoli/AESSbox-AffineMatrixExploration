# app/utils/validation.py
from typing import List, Dict

def check_sbox(sbox: List[int]) -> Dict:
    """Logika pengecekan Balance dan Bijective."""
    
    # 1. Cek Bijektif
    unique_values = set(sbox)
    is_bijective = (len(unique_values) == 256) and \
                   (min(unique_values) == 0) and \
                   (max(unique_values) == 255)

    # 2. Cek Balance
    bit_counts = [0] * 8
    for val in sbox:
        for i in range(8):
            if (val >> i) & 1:
                bit_counts[i] += 1
                
    # Balance terpenuhi jika setiap bit counter = 128
    is_balanced = all(count == 128 for count in bit_counts)

    return {
        "is_bijective": is_bijective,
        "is_balanced": is_balanced,
        "bit_counts": bit_counts
    }