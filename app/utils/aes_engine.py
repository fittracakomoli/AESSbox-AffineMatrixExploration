# app/utils/aes_engine.py
from typing import List

class AESEngine:
    """
    Implementasi AES-128 (Pure Python) yang mendukung Custom S-box.
    Reference: FIPS 197
    """
    def __init__(self, key: bytes, sbox: List[int]):
        if len(key) != 16:
            raise ValueError("Key harus 16 bytes (128-bit) untuk implementasi ini.")
        
        self.key = key
        self.sbox = sbox
        self.inv_sbox = self._generate_inv_sbox(sbox)
        self.rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
        
        # Expand Key (Penting: Key Expansion juga menggunakan S-box)
        self.round_keys = self._key_expansion(self.key)

    def _generate_inv_sbox(self, sbox):
        inv = [0] * 256
        for i in range(256):
            inv[sbox[i]] = i
        return inv

    # --- Helper Functions (GF arithmetic & Transformation) ---
    def _sub_bytes(self, state):
        for r in range(4):
            for c in range(4):
                state[r][c] = self.sbox[state[r][c]]

    def _inv_sub_bytes(self, state):
        for r in range(4):
            for c in range(4):
                state[r][c] = self.inv_sbox[state[r][c]]

    def _shift_rows(self, state):
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
        state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]

    def _inv_shift_rows(self, state):
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
        state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]

    def _gmul(self, a, b):
        """Galois Field multiplication"""
        p = 0
        for _ in range(8):
            if b & 1: p ^= a
            hi_bit = a & 0x80
            a <<= 1
            if hi_bit: a ^= 0x1b
            b >>= 1
        return p % 256

    def _mix_columns(self, state):
        for i in range(4):
            s0 = state[0][i]
            s1 = state[1][i]
            s2 = state[2][i]
            s3 = state[3][i]
            state[0][i] = self._gmul(s0, 2) ^ self._gmul(s1, 3) ^ s2 ^ s3
            state[1][i] = s0 ^ self._gmul(s1, 2) ^ self._gmul(s2, 3) ^ s3
            state[2][i] = s0 ^ s1 ^ self._gmul(s2, 2) ^ self._gmul(s3, 3)
            state[3][i] = self._gmul(s0, 3) ^ s1 ^ s2 ^ self._gmul(s3, 2)

    def _inv_mix_columns(self, state):
        for i in range(4):
            s0 = state[0][i]
            s1 = state[1][i]
            s2 = state[2][i]
            s3 = state[3][i]
            state[0][i] = self._gmul(s0, 0x0e) ^ self._gmul(s1, 0x0b) ^ self._gmul(s2, 0x0d) ^ self._gmul(s3, 0x09)
            state[1][i] = self._gmul(s0, 0x09) ^ self._gmul(s1, 0x0e) ^ self._gmul(s2, 0x0b) ^ self._gmul(s3, 0x0d)
            state[2][i] = self._gmul(s0, 0x0d) ^ self._gmul(s1, 0x09) ^ self._gmul(s2, 0x0e) ^ self._gmul(s3, 0x0b)
            state[3][i] = self._gmul(s0, 0x0b) ^ self._gmul(s1, 0x0d) ^ self._gmul(s2, 0x09) ^ self._gmul(s3, 0x0e)

    def _add_round_key(self, state, round_key):
        for r in range(4):
            for c in range(4):
                state[r][c] ^= round_key[r][c]

    # --- Key Expansion ---
    def _key_expansion(self, key):
        # Mengubah key 16 byte menjadi matriks 4x4
        key_columns = []
        for i in range(4):
            key_columns.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])
        
        # Generate round keys (Total 44 words untuk AES-128)
        i = 4
        while i < 44:
            temp = key_columns[i-1][:] # Copy last word
            if i % 4 == 0:
                # RotWord
                temp = temp[1:] + temp[:1]
                # SubWord (Menggunakan S-box!)
                temp = [self.sbox[b] for b in temp]
                # XOR Rcon
                temp[0] ^= self.rcon[i // 4]
            
            # XOR dengan word 4 posisi sebelumnya
            prev = key_columns[i-4]
            new_word = [temp[j] ^ prev[j] for j in range(4)]
            key_columns.append(new_word)
            i += 1
            
        # Format menjadi list of 4x4 matrices (Round Keys)
        round_keys = []
        for r in range(11): # 0 to 10 rounds
            matrix = [[0]*4 for _ in range(4)]
            for c in range(4):
                word = key_columns[4*r + c]
                for row in range(4):
                    matrix[row][c] = word[row]
            round_keys.append(matrix)
        return round_keys

    # --- Main Encrypt/Decrypt ---
    def encrypt_block(self, plaintext: bytes) -> bytes:
        state = [[0]*4 for _ in range(4)]
        for r in range(4):
            for c in range(4):
                state[r][c] = plaintext[r + 4*c]

        self._add_round_key(state, self.round_keys[0])

        for round in range(1, 10):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, self.round_keys[round])

        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.round_keys[10])

        output = []
        for c in range(4):
            for r in range(4):
                output.append(state[r][c])
        return bytes(output)

    def decrypt_block(self, ciphertext: bytes) -> bytes:
        state = [[0]*4 for _ in range(4)]
        for r in range(4):
            for c in range(4):
                state[r][c] = ciphertext[r + 4*c]

        self._add_round_key(state, self.round_keys[10])

        for round in range(9, 0, -1):
            self._inv_shift_rows(state)
            self._inv_sub_bytes(state)
            self._add_round_key(state, self.round_keys[round])
            self._inv_mix_columns(state)

        self._inv_shift_rows(state)
        self._inv_sub_bytes(state)
        self._add_round_key(state, self.round_keys[0])

        output = []
        for c in range(4):
            for r in range(4):
                output.append(state[r][c])
        return bytes(output)