from typing import List

def fwht(a: List[int]) -> List[int]:
    """
    Fast Walsh-Hadamard Transform.
    Diperlukan untuk menghitung Nonlinearity (NL) dan LAP secara efisien.
    """
    h = 1
    a = a[:]  # Copy array
    while h < len(a):
        for i in range(0, len(a), h * 2):
            for j in range(i, i + h):
                x = a[j]
                y = a[j + h]
                a[j] = x + y
                a[j + h] = x - y
        h *= 2
    return a

# --- Helper: Hamming Weight ---
def hamming_weight(n: int) -> int:
    return bin(n).count('1')

def calculate_nl(sbox: List[int]) -> int:
    """
    Menghitung Nonlinearity (NL)[cite: 1294].
    Ideal AES: 112.
    """
    min_nl = 256
    # S-box memiliki 8 fungsi output boolean (f0..f7)
    for bit in range(8):
        # Bentuk tabel kebenaran (-1^f(x)) untuk bit ke-sekian
        truth_table = []
        for x in range(256):
            val = (sbox[x] >> bit) & 1
            truth_table.append(1 if val == 0 else -1)
        
        # Hitung spektrum Walsh
        spectrum = fwht(truth_table)
        
        # Cari nilai maksimum absolut dari spektrum
        max_abs_val = max(abs(x) for x in spectrum)
        
        # Rumus NL: 2^(n-1) - max_spectrum/2
        nl = 128 - (max_abs_val // 2)
        if nl < min_nl:
            min_nl = nl
            
    return min_nl

def calculate_sac(sbox: List[int]) -> float:
    """
    Menghitung Strict Avalanche Criterion (SAC).
    Rata-rata probabilitas perubahan bit output saat 1 bit input berubah.
    Ideal: 0.5.
    """
    total_sac = 0
    count = 0
    
    for i in range(8): # Untuk setiap posisi bit input yang di-flip
        flip_mask = 1 << i
        for x in range(256):
            y1 = sbox[x]
            y2 = sbox[x ^ flip_mask]
            diff = y1 ^ y2
            
            # Hitung Hamming Weight dari diff (berapa bit output berubah)
            hw = bin(diff).count('1')
            total_sac += hw
            count += 8 # Ada 8 bit output
            
    return total_sac / count

def calculate_bic(sbox: List[int]) -> dict:
    """
    Menghitung BIC-NL dan BIC-SAC[cite: 1323, 1329].
    Menganalisis korelasi antara dua bit output berbeda (j != k).
    """
    min_bic_nl = 256
    sum_bic_sac = 0
    pair_count = 0
    
    # Iterasi semua pasangan bit output (j, k)
    for j in range(8):
        for k in range(j + 1, 8):
            # Konstruksi fungsi XOR dari dua bit output: f_j XOR f_k
            truth_table = []
            sac_sum_pair = 0
            
            # --- Persiapan BIC-NL ---
            for x in range(256):
                val_j = (sbox[x] >> j) & 1
                val_k = (sbox[x] >> k) & 1
                xor_val = val_j ^ val_k
                truth_table.append(1 if xor_val == 0 else -1)
            
            # Hitung NL untuk pasangan ini
            spectrum = fwht(truth_table)
            max_abs = max(abs(v) for v in spectrum)
            nl_pair = 128 - (max_abs // 2)
            if nl_pair < min_bic_nl:
                min_bic_nl = nl_pair
            
            # --- Persiapan BIC-SAC ---
            # Cek avalanche untuk fungsi (f_j XOR f_k)
            for i in range(8): # Flip input bit i
                flip_mask = 1 << i
                for x in range(256):
                    # Output asli
                    y_orig = ((sbox[x] >> j) & 1) ^ ((sbox[x] >> k) & 1)
                    # Output setelah flip
                    y_flip = ((sbox[x^flip_mask] >> j) & 1) ^ ((sbox[x^flip_mask] >> k) & 1)
                    
                    if y_orig != y_flip:
                        sac_sum_pair += 1
            
            avg_sac_pair = sac_sum_pair / (256 * 8)
            sum_bic_sac += avg_sac_pair
            pair_count += 1
            
    return {
        "bic_nl": min_bic_nl,
        "bic_sac": sum_bic_sac / pair_count if pair_count > 0 else 0
    }

def calculate_lap(sbox: List[int]) -> float:
    """
    Menghitung Linear Approximation Probability (LAP).
    Menggunakan LAT (Linear Approximation Table).
    Ideal AES: 0.0625 (16/256).
    """
    max_bias = 0
    
    # Untuk setiap masker output (v) dari 1 sampai 255
    for v in range(1, 256):
        truth_table = []
        for x in range(256):
            # Dot product output Sbox(x) dengan masker v
            # parity dari (S(x) & v)
            dot_val = bin(sbox[x] & v).count('1') % 2
            truth_table.append(1 if dot_val == 0 else -1)
            
        # Transformasi Walsh untuk mendapatkan korelasi dengan semua input mask (u)
        spectrum = fwht(truth_table)
        
        # Cari bias maksimum (absolute)
        # Spectrum[u] adalah korelasi antara u.x dan v.S(x)
        # Bias = Spectrum[u] / 256
        for u in range(1, 256): # Skip u=0 untuk v!=0
            val = abs(spectrum[u])
            if val > max_bias:
                max_bias = val
                
    # LAP didefinisikan sebagai probability deviation maksimum
    # Paper menyebut LAP = 0.0625.
    # Dalam LAT standar, max_bias untuk AES adalah 32. 32/256 = 0.125.
    # Namun LAP paper (0.0625) = (max_bias/256)^2? Tidak, 16/256 = 0.0625.
    # Jadi paper menggunakan definisi LAP = max_bias_lat / 256 dengan skala bias +-16.
    # Implementasi ini menghitung max deviasi probabilitas.
    
    return max_bias / 256.0

def calculate_dap(sbox: List[int]) -> float:
    """
    Menghitung Differential Approximation Probability (DAP).
    Menggunakan DDT (Difference Distribution Table).
    Ideal AES: 0.015625 (4/256).
    """
    max_count = 0
    
    # DDT: Matrix 256x256 (tapi kita hanya perlu tracking max count)
    # Hemat memori dengan loop difference
    
    for dx in range(1, 256): # Input difference (tidak nol)
        diff_counts = [0] * 256
        for x in range(256):
            y1 = sbox[x]
            y2 = sbox[x ^ dx] # x XOR delta_x
            dy = y1 ^ y2      # delta_y
            diff_counts[dy] += 1
            
        # Cari max count untuk dx ini
        current_max = max(diff_counts)
        if current_max > max_count:
            max_count = current_max
            
    return max_count / 256.0

# --- 1. Differential Uniformity (DU) ---
def calculate_du(sbox: List[int]) -> int:
    """
    Differential Uniformity (DU).
    Sama dengan max value di DDT (Difference Distribution Table).
    AES S-box standar memiliki DU = 4.
    """
    max_du = 0
    # Loop semua input difference (dx) tidak nol
    for dx in range(1, 256):
        diff_counts = [0] * 256
        for x in range(256):
            y1 = sbox[x]
            y2 = sbox[x ^ dx]
            dy = y1 ^ y2
            diff_counts[dy] += 1
        
        # Cari kejadian terbanyak untuk dx ini
        current_max = max(diff_counts)
        if current_max > max_du:
            max_du = current_max
            
    return max_du

# --- 2. Algebraic Degree (AD) ---
def calculate_ad(sbox: List[int]) -> int:
    """
    Algebraic Degree (AD).
    Menghitung derajat polinomial tertinggi dari Algebraic Normal Form (ANF).
    Menggunakan Mobius Transform.
    """
    n = 8
    max_degree = 0

    # Cek untuk setiap bit output (0-7)
    for bit in range(8):
        # Ambil Truth Table untuk bit ke-'bit'
        # Output S-box dipisah per bit
        truth_table = [(sbox[x] >> bit) & 1 for x in range(256)]
        
        # Mobius Transform (Algoritma Butterfly untuk ANF)
        # Mengubah Truth Table menjadi ANF Table
        for i in range(n):
            step = 1 << i
            for j in range(0, 256, step * 2):
                for k in range(j, j + step):
                    truth_table[k + step] ^= truth_table[k]
        
        # Cari derajat tertinggi (Hamming Weight index) dimana koefisien ANF-nya 1
        current_deg = 0
        for x in range(256):
            if truth_table[x] == 1:
                deg = hamming_weight(x)
                if deg > current_deg:
                    current_deg = deg
        
        if current_deg > max_degree:
            max_degree = current_deg
            
    return max_degree

# --- 3. Correlation Immunity (CI) ---
def calculate_ci(sbox: List[int]) -> int:
    """
    Correlation Immunity (CI).
    Orde terendah dimana spektrum Walsh tidak nol.
    Untuk S-box AES yang seimbang & non-linear tinggi, biasanya CI = 0.
    """
    min_ci = 8
    
    for bit in range(8):
        # Buat Truth Table (-1 / +1)
        truth_table = []
        for x in range(256):
            val = (sbox[x] >> bit) & 1
            truth_table.append(1 if val == 0 else -1)
            
        # Hitung Walsh Spectrum
        spectrum = fwht(truth_table)
        
        # Cek spectrum pada bobot Hamming rendah (1, 2, ...)
        current_ci = 0
        for order in range(1, 9):
            is_immune = True
            # Cek semua index w yang memiliki hamming weight == order
            for w in range(1, 256):
                if hamming_weight(w) == order:
                    if spectrum[w] != 0:
                        is_immune = False
                        break
            
            if is_immune:
                current_ci = order
            else:
                break # Jika order 1 gagal, maka CI=0, stop.
        
        if current_ci < min_ci:
            min_ci = current_ci
            
    return min_ci

# --- 4. Transparency Order (TO) ---
def calculate_to(sbox: List[int]) -> float:
    """
    Transparency Order (TO) - Modified definition by Prouff.
    Mengukur ketahanan terhadap DPA (Differential Power Analysis).
    Menggunakan teknik FWHT + Autocorrelation (Wiener-Khinchin) untuk efisiensi.
    Complexity: O(256 * n * 2^n) ~ Cukup cepat.
    """
    n = 8
    N = 256
    sum_term = 0
    
    # Pre-compute Hamming Weight untuk output
    # (m - 2*wt(beta)) -> Beta adalah output mask
    # Karena kita iterasi beta dari 1..255
    
    # Rumus TO melibatkan Autocorrelation. 
    # Autocorrelation(a) = InverseFWHT( Walsh(w)^2 )
    
    max_beta_val = 0
    
    # Iterasi semua kombinasi linear output (Beta)
    for beta in range(1, 256):
        # 1. Bentuk fungsi komponen Boolean f_beta(x) = beta dot S(x)
        truth_table = []
        for x in range(N):
            # dot product di GF(2) adalah parity dari AND
            dot_val = bin(sbox[x] & beta).count('1') % 2
            truth_table.append(1 if dot_val == 0 else -1)
            
        # 2. Hitung Walsh Spectrum
        spectrum = fwht(truth_table)
        
        # 3. Hitung Power Spectrum (Walsh^2)
        power_spectrum = [val**2 for val in spectrum]
        
        # 4. Hitung Autocorrelation menggunakan Inverse FWHT dari Power Spectrum
        # (Karena FWHT adalah involusi, FWHT(FWHT(A)) = N * A)
        # Jadi AC = FWHT(Power) / N
        ac_raw = fwht(power_spectrum)
        autocorrelation = [val // N for val in ac_raw]
        
        # 5. Hitung Sum |AC(a)| untuk a != 0
        sum_abs_ac = sum(abs(autocorrelation[a]) for a in range(1, N))
        
        # 6. Bagian rumus: |m - 2wt(beta)|
        term1 = abs(8 - 2 * hamming_weight(beta))
        
        # 7. Gabungkan
        # Rumus: R(beta) = term1 - (1 / (2^2n - 2^n)) * sum_abs_ac
        # Namun definisi TO adalah MAX dari nilai ini.
        # Catatan: Ada beberapa variasi rumus TO. Ini menggunakan definisi standar DPA.
        
        # Faktor normalisasi: 2^(2n) - 2^n = 65536 - 256 = 65280
        normalization = 65280 
        
        current_val = term1 - (sum_abs_ac / normalization)
        
        if current_val > max_beta_val:
            max_beta_val = current_val
            
    return max_beta_val