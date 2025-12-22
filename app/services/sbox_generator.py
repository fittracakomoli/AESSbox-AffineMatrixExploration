# app/services/sbox_generator.py
from app.utils.math_gf2 import (
    generate_random_affine_matrix, 
    is_invertible_gf2, 
    apply_affine_transform, 
    INVERSE_TABLE
)
from app.core.constants import AES_CONSTANT

def find_valid_sbox():
    """
    Logika eksplorasi:
    Loop terus menerus generate matriks random sampai menemukan
    yang Invertible (valid), lalu bentuk S-box nya.
    """
    while True:
        # 1. Eksplorasi Random
        candidate_matrix = generate_random_affine_matrix()
        
        # 2. Filter Matriks (Syarat Utama Bijektif & Balance)
        if is_invertible_gf2(candidate_matrix):
            
            # 3. Konstruksi S-box
            sbox = []
            for x in range(256):
                inv = INVERSE_TABLE[x]
                val = apply_affine_transform(inv, candidate_matrix)
                sbox.append(val)
            
            # Return hasil berupa dictionary atau tuple
            return {
                "affine_matrix": candidate_matrix,
                "affine_vector": [(AES_CONSTANT >> i) & 1 for i in range(8)],
                "sbox": sbox,
                "is_bijective": True,
                "is_balanced": True
            }
