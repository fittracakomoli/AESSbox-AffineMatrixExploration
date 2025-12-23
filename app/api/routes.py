from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import StreamingResponse, JSONResponse
import base64
import io
from PIL import Image
from app.services.sbox_generator import find_valid_sbox
from app.services.validation import check_sbox
from app.schemas.sbox import SBoxResponse, SBoxCheckRequest, SBoxCheckResponse, SBoxUploadResponse, SBoxDownloadRequest, ExportFormat
from app.schemas.analysis import AnalysisResponse
from app.utils.crypto_metrics import (
    calculate_nl, calculate_sac, calculate_bic,
    calculate_lap, calculate_du, calculate_ad,
    calculate_to, calculate_ci
)
from app.services.aes_wrapper import (
    aes_encrypt_custom,
    aes_decrypt_custom,
    aes_encrypt_bytes_no_pad,
    aes_decrypt_bytes_no_pad,
)
from app.schemas.cipher import (
    EncryptRequest,
    DecryptRequest,
    CipherResponse,
    EncryptImageRequest,
    DecryptImageRequest,
    ImageCipherResponse,
)
from app.utils.file_handlers import parse_uploaded_sbox, format_sbox_as_csv, format_sbox_as_txt, format_sbox_as_xlsx
from app.core.constants import AES_CONSTANT


AES_STANDARD_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

router = APIRouter()

def normalize_image_mode(image: Image.Image) -> Image.Image:
    if image.mode in ("RGBA", "LA"):
        return image.convert("RGBA")
    if image.mode == "P" and "transparency" in image.info:
        return image.convert("RGBA")
    if image.mode in ("L", "RGB"):
        return image
    return image.convert("RGB")

def get_affine_constant_vector():
    """Vector affine default AES (8 bit)."""
    return [(AES_CONSTANT >> i) & 1 for i in range(8)]

@router.get("/aes-standard-sbox")
async def get_aes_standard_sbox():
    """
    Endpoint untuk mengambil AES standard S-box (array 256 elemen).
    """
    return {"sbox": AES_STANDARD_SBOX}

@router.get("/status")
async def status():
    return {"status": "API is running"}

@router.get("/generate-sbox", response_model=SBoxResponse)
async def generate_single_sbox_endpoint():
    """
    Endpoint untuk meng-generate 1 S-box unik yang valid.
    """
    result = find_valid_sbox()
    return {**result, "affine_vector": get_affine_constant_vector()}

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
    
    # 5. Hitung DU & DAP
    du_val = calculate_du(sbox)
    dap_val = du_val / 256.0

    # 6. Hitung AD
    ad_val = calculate_ad(sbox)

    # 7. Hitung TO
    to_val = calculate_to(sbox)

    # 8. Hitung CI
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
async def encrypt_aes_endpoint(payload: EncryptRequest):
    """
    Melakukan Enkripsi AES-128 (ECB + PKCS7) menggunakan S-box Custom.
    """
    if len(payload.sbox) != 256:
        raise HTTPException(status_code=400, detail="S-box harus 256 elemen.")
        
    result_hex = aes_encrypt_custom(payload.plaintext, payload.key, payload.sbox)
    return CipherResponse(result=result_hex)

@router.post("/decrypt", response_model=CipherResponse)
async def decrypt_aes_endpoint(payload: DecryptRequest):
    """
    Melakukan Dekripsi AES-128 menggunakan S-box Custom yang sama.
    """
    if len(payload.sbox) != 256:
        raise HTTPException(status_code=400, detail="S-box harus 256 elemen.")
        
    result_text = aes_decrypt_custom(payload.ciphertext, payload.key, payload.sbox)
    return CipherResponse(result=result_text)

@router.post("/encrypt-image", response_model=ImageCipherResponse)
async def encrypt_image_endpoint(payload: EncryptImageRequest):
    """
    Enkripsi AES-128 untuk data gambar dalam bentuk Base64.
    """
    if len(payload.sbox) != 256:
        raise HTTPException(status_code=400, detail="S-box harus 256 elemen.")

    try:
        image_bytes = base64.b64decode(payload.image_base64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Base64 gambar tidak valid.")

    try:
        image = Image.open(io.BytesIO(image_bytes))
    except Exception:
        raise HTTPException(status_code=400, detail="Gambar tidak bisa dibaca.")

    image = normalize_image_mode(image)
    pixel_bytes = image.tobytes()
    encrypted_pixels = aes_encrypt_bytes_no_pad(pixel_bytes, payload.key, payload.sbox)
    encrypted_image = Image.frombytes(image.mode, image.size, encrypted_pixels)
    buffer = io.BytesIO()
    encrypted_image.save(buffer, format="PNG")
    encrypted_b64 = base64.b64encode(buffer.getvalue()).decode("ascii")
    return ImageCipherResponse(
        result=encrypted_b64,
        mime_type="image/png",
        filename=payload.filename,
    )

@router.post("/decrypt-image", response_model=ImageCipherResponse)
async def decrypt_image_endpoint(payload: DecryptImageRequest):
    """
    Dekripsi AES-128 untuk data gambar dalam bentuk Base64.
    """
    if len(payload.sbox) != 256:
        raise HTTPException(status_code=400, detail="S-box harus 256 elemen.")

    try:
        ciphertext_bytes = base64.b64decode(payload.ciphertext_base64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Base64 ciphertext tidak valid.")

    try:
        encrypted_image = Image.open(io.BytesIO(ciphertext_bytes))
    except Exception:
        raise HTTPException(status_code=400, detail="Ciphertext bukan gambar yang valid.")

    encrypted_image = normalize_image_mode(encrypted_image)
    encrypted_pixels = encrypted_image.tobytes()
    decrypted_pixels = aes_decrypt_bytes_no_pad(encrypted_pixels, payload.key, payload.sbox)
    decrypted_image = Image.frombytes(encrypted_image.mode, encrypted_image.size, decrypted_pixels)
    buffer = io.BytesIO()
    decrypted_image.save(buffer, format="PNG")
    decrypted_b64 = base64.b64encode(buffer.getvalue()).decode("ascii")
    return ImageCipherResponse(
        result=decrypted_b64,
        mime_type="image/png",
    )

@router.post("/upload-sbox", response_model=SBoxUploadResponse)
async def upload_sbox_endpoint(file: UploadFile = File(...)):
    """
    Endpoint Upload S-box.
    Menerima file (JSON/CSV/TXT/XLSX), memparsing menjadi array, dan mengembalikan JSON.
    Gunakan response dari endpoint ini untuk menampilkan Tabel S-box di UI.
    """
    # 1. Parsing File
    parsed = await parse_uploaded_sbox(file)
    sbox_array = parsed["sbox"]
    
    # 2. Return JSON ke Frontend
    return SBoxUploadResponse(
        filename=file.filename,
        sbox=sbox_array,
        affine_matrix=parsed["affine_matrix"],
        affine_vector=parsed["affine_vector"],
        message="S-box berhasil dimuat. Silakan cek tabel preview."
    )

@router.post("/download")
async def download_sbox_endpoint(payload: SBoxDownloadRequest):
    """
    Endpoint download S-box (Hex Format).
    """
    
    # --- KASUS 1: Format JSON (Hex) ---
    if payload.format == ExportFormat.JSON:
        clean_data = {
            "sbox": [f"{val:02X}" for val in payload.sbox]
        }
        if payload.affine_matrix is not None:
            clean_data["affine_matrix"] = payload.affine_matrix
        if payload.affine_vector is not None:
            clean_data["affine_vector"] = payload.affine_vector
        return JSONResponse(
            content=clean_data,
            headers={"Content-Disposition": 'attachment; filename="sbox_data.json"'}
        )

    # --- KASUS 2: Format CSV (Hex Grid 16x16) ---
    elif payload.format == ExportFormat.CSV:
        csv_buffer = format_sbox_as_csv(payload.sbox)
        return StreamingResponse(
            csv_buffer,
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="sbox_matrix.csv"'}
        )

    # --- KASUS 3: Format TXT (Hex Grid 16x16) ---
    elif payload.format == ExportFormat.TXT:
        txt_buffer = format_sbox_as_txt(payload.sbox)
        return StreamingResponse(
            txt_buffer,
            media_type="text/plain",
            headers={"Content-Disposition": 'attachment; filename="sbox_matrix.txt"'}
        )

    # --- KASUS 4: Format XLSX (Hex Grid 16x16) ---
    elif payload.format == ExportFormat.XLSX:
        xlsx_buffer = format_sbox_as_xlsx(payload.sbox)
        return StreamingResponse(
            xlsx_buffer,
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            headers={"Content-Disposition": 'attachment; filename="sbox_matrix.xlsx"'}
        )
