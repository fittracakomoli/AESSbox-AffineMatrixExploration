# app/main.py
import uvicorn
from fastapi import FastAPI
from app.api.routes import router as api_router
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Modular AES S-box Generator",
    description="API Modular untuk generate S-box menggunakan Eksplorasi Matriks Afin."
)

# Daftar origin yang diizinkan (alamat React kamu)
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,     # List origin di atas
    allow_credentials=True,
    allow_methods=["*"],       # Izinkan semua method (GET, POST, PUT, dll)
    allow_headers=["*"],       # Izinkan semua header
)

# Daftarkan router dari folder api
app.include_router(api_router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)