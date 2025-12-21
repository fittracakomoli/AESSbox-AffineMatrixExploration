# app/api/routes.py
from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse, JSONResponse
from app.services.sbox_generator import find_valid_sbox
from app.services.validation import check_sbox
from app.schemas.sbox import SBoxResponse, SBoxCheckRequest, SBoxCheckResponse, SBoxUploadResponse, SBoxDownloadRequest, ExportFormat
from app.schemas.analysis import AnalysisResponse
from app.utils.crypto_metrics import (
    calculate_nl, calculate_sac, calculate_bic, 
    calculate_lap, calculate_dap,
    calculate_du, calculate_ad, calculate_to, calculate_ci
)
from app.services.aes_wrapper import aes_encrypt_custom, aes_decrypt_custom
from app.schemas.cipher import EncryptRequest, DecryptRequest, CipherResponse
from app.utils.file_handlers import parse_uploaded_sbox, format_sbox_as_csv, format_sbox_as_txt

router = APIRouter()

@router.get("/status")
async def status():
    return {"status": "API is running"}

@router.get("/generate-sbox", response_model=SBoxResponse)
async def generate_single_sbox_endpoint():
    """
    Endpoint untuk meng-generate 1 S-box unik yang valid.
    """
    result = find_valid_sbox()
    return result

@router.post("/check-sbox", response_model=SBoxCheckResponse)
async def check_sbox_endpoint(payload: SBoxCheckRequest):
    """
    Mengecek validitas S-box yang dikirim oleh user.
    Input: JSON berisi array "sbox" [256 integer].
    Output: Status Balance & Bijektif beserta detail bit.
    """
    # Panggil fungsi logika dari services
    result = check_sbox(payload.sbox)
    
    return result

@router.post("/analyze-sbox", response_model=AnalysisResponse)
async def analyze_sbox_endpoint(payload: SBoxCheckRequest):
    """
    Menganalisa kekuatan kriptografi S-box.
    Menghitung NL, SAC, BIC, LAP, dan DAP sesuai standar Paper.
    Proses ini mungkin memakan waktu beberapa milidetik.
    """
    sbox = payload.sbox
    
    # 1. Hitung NL [cite: 1294]
    nl_val = calculate_nl(sbox)
    
    # 2. Hitung SAC 
    sac_val = calculate_sac(sbox)
    
    # 3. Hitung BIC (BIC-NL dan BIC-SAC) [cite: 1323, 1329]
    bic_res = calculate_bic(sbox)
    
    # 4. Hitung LAP 
    lap_val = calculate_lap(sbox)
    
    # 5. Hitung DAP 
    dap_val = calculate_dap(sbox)

    du_val = calculate_du(sbox)
    ad_val = calculate_ad(sbox)
    to_val = calculate_to(sbox)
    ci_val = calculate_ci(sbox)
    
    return AnalysisResponse(
        nl=nl_val,
        sac=sac_val,
        bic_nl=bic_res['bic_nl'],
        bic_sac=bic_res['bic_sac'],
        lap=lap_val,
        dap=dap_val,
        du=du_val,
        ad=ad_val,
        to=to_val,
        ci=ci_val
    )

@router.post("/encrypt", response_model=CipherResponse)
async def encrypt_endpoint(payload: EncryptRequest):
    """
    Endpoint Enkripsi AES.
    Menerima: plaintext, sbox, key.
    """
    # Panggil fungsi wrapper full
    result_hex = aes_encrypt_custom(
        plaintext=payload.plaintext,
        sbox=payload.sbox,
        key=payload.key
    )
    return CipherResponse(result=result_hex)

@router.post("/decrypt", response_model=CipherResponse)
async def decrypt_endpoint(payload: DecryptRequest):
    """
    Endpoint Dekripsi AES.
    Menerima: ciphertext (hex), sbox, key.
    """
    # Panggil fungsi wrapper full
    result_text = aes_decrypt_custom(
        ciphertext=payload.ciphertext,
        sbox=payload.sbox,
        key=payload.key
    )
    return CipherResponse(result=result_text)

@router.post("/upload-sbox", response_model=SBoxUploadResponse)
async def upload_sbox_endpoint(file: UploadFile = File(...)):
    """
    Endpoint Upload S-box.
    Menerima file (JSON/CSV/TXT), memparsing menjadi array, dan mengembalikan JSON.
    Gunakan response dari endpoint ini untuk menampilkan Tabel S-box di UI.
    """
    # 1. Parsing File
    sbox_array = await parse_uploaded_sbox(file)
    
    # 2. Return JSON ke Frontend
    return SBoxUploadResponse(
        filename=file.filename,
        sbox=sbox_array,
        message="S-box berhasil dimuat. Silakan cek tabel preview."
    )

@router.post("/download")
async def download_sbox_endpoint(payload: SBoxDownloadRequest):
    """
    Endpoint download S-box (Decimal Format).
    """
    
    # --- KASUS 1: Format JSON (Desimal) ---
    if payload.format == ExportFormat.JSON:
        # JSON secara standar menggunakan format desimal untuk integer
        clean_data = {
            "sbox": payload.sbox
        }
        return JSONResponse(
            content=clean_data,
            headers={"Content-Disposition": 'attachment; filename="sbox_data.json"'}
        )

    # --- KASUS 2: Format CSV (Desimal Grid 16x16) ---
    elif payload.format == ExportFormat.CSV:
        csv_buffer = format_sbox_as_csv(payload.sbox)
        return StreamingResponse(
            csv_buffer,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="sbox_matrix.csv"'}
        )

    # --- KASUS 3: Format TXT (Desimal Grid 16x16) ---
    elif payload.format == ExportFormat.TXT:
        txt_buffer = format_sbox_as_txt(payload.sbox)
        return StreamingResponse(
            txt_buffer,
            media_type="text/plain",
            headers={"Content-Disposition": 'attachment; filename="sbox_matrix.txt"'}
        )