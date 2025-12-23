import uvicorn
from fastapi import FastAPI
# PERBAIKAN DI SINI: Tambahkan 'app.' di depan
from app.api.routes import router as api_router 
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Modular AES S-box Generator",
    description="API Modular untuk generate S-box menggunakan Eksplorasi Matriks Afin."
)

# KONFIGURASI CORS
# Catatan: Saat deploy, sebaiknya tambahkan "*" agar bisa diakses dari mana saja dulu untuk testing.
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:4173",
    "http://127.0.0.1:4173",
    "*"  # <--- SANGAT DISARANKAN tambahkan ini sementara agar tidak error CORS saat dibuka di HP/Browser lain
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Daftarkan router
app.include_router(api_router)

# Endpoint test
@app.get("/api/hello")
def hello():
    return {"message": "Hello from FastAPI running on Vercel!"}

# Bagian ini tidak dieksekusi oleh Vercel (hanya untuk local run), tapi tidak bikin error.
if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)