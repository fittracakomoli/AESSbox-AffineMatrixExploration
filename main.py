# app/main.py
import uvicorn
from fastapi import FastAPI
from app.api.routes import router as api_router
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="Modular AES S-box Generator",
    description="API Modular untuk generate S-box menggunakan Eksplorasi Matriks Afin."
)

origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)