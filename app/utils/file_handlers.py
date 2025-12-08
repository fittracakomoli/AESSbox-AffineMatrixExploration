import json
import csv
import io
import re
from typing import List
from fastapi import UploadFile, HTTPException

async def parse_uploaded_sbox(file: UploadFile) -> List[int]:
    """
    Membaca file upload (JSON/CSV/TXT) dan mengonversinya menjadi List[int].
    Mendukung format Desimal.
    """
    filename = file.filename.lower()
    content = await file.read()
    
    # Decode bytes ke string
    try:
        text_content = content.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(400, "File harus berupa text (UTF-8).")
    
    sbox_data = []

    try:
        # --- KASUS 1: File JSON ---
        if filename.endswith(".json"):
            data = json.loads(text_content)
            # Handle format { "sbox": [...] } atau langsung [...]
            if isinstance(data, dict) and "sbox" in data:
                sbox_data = data["sbox"]
            elif isinstance(data, list):
                sbox_data = data
            else:
                raise ValueError("JSON harus berisi array atau object dengan key 'sbox'.")

        # --- KASUS 2: File CSV (.csv) ---
        elif filename.endswith(".csv"):
            f = io.StringIO(text_content)
            reader = csv.reader(f)
            for row in reader:
                for item in row:
                    # Bersihkan whitespace dan parse int
                    clean_item = item.strip()
                    if clean_item:
                        try:
                            # Asumsi input adalah DESIMAL (basis 10)
                            sbox_data.append(int(clean_item))
                        except ValueError:
                            continue # Skip header atau text non-angka

        # --- KASUS 3: File Text (.txt) ---
        elif filename.endswith(".txt"):
            # TXT mungkin dipisah spasi, tab, atau enter.
            # Kita gunakan Regex untuk mencari semua angka dalam file.
            # \d+ cocok dengan angka desimal, -?\d+ jika ada negatif (tapi sbox unsigned)
            tokens = re.findall(r'\b\d+\b', text_content)
            sbox_data = [int(t) for t in tokens]

        else:
            raise HTTPException(400, "Format file tidak didukung. Gunakan .json, .csv, atau .txt")

    except json.JSONDecodeError:
        raise HTTPException(400, "File JSON rusak/tidak valid.")
    except Exception as e:
        raise HTTPException(400, f"Gagal membaca file: {str(e)}")

    # --- VALIDASI PENTING ---
    # S-box AES harus tepat 256 elemen
    if len(sbox_data) != 256:
        raise HTTPException(
            status_code=400, 
            detail=f"Jumlah data tidak valid. Ditemukan {len(sbox_data)} angka, seharusnya tepat 256."
        )

    # Validasi Range (Harus 0-255)
    if any(x < 0 or x > 255 for x in sbox_data):
        raise HTTPException(400, "Nilai S-box harus berada dalam rentang 0-255.")

    return sbox_data

def format_sbox_as_csv(sbox: List[int]) -> io.StringIO:
    """
    Mengubah S-box menjadi format CSV Grid 16x16 dalam bentuk DESIMAL.
    """
    output = io.StringIO()
    writer = csv.writer(output)
    
    for i in range(0, 256, 16):
        row_ints = sbox[i : i+16]
        # PERUBAHAN: Langsung tulis list integer, tidak perlu convert ke hex string
        writer.writerow(row_ints)
        
    output.seek(0)
    return output

def format_sbox_as_txt(sbox: List[int]) -> io.StringIO:
    """
    Mengubah S-box menjadi format TXT Grid 16x16 dalam bentuk DESIMAL.
    Dipisahkan dengan spasi.
    """
    output = io.StringIO()
    
    for i in range(0, 256, 16):
        row_ints = sbox[i : i+16]
        # PERUBAHAN: Convert ke string desimal biasa "99", "124", dst.
        row_str = " ".join([str(val) for val in row_ints])
        output.write(row_str + "\n")
        
    output.seek(0)
    return output