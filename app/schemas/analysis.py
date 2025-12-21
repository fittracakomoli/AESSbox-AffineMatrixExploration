from pydantic import BaseModel

class AnalysisResponse(BaseModel):
    nl: int             # Nonlinearity (Target: 112)
    sac: float          # Strict Avalanche Criterion (Target: ~0.5)
    bic_nl: int         # Bit Independence Criterion - Nonlinearity (Target: 112)
    bic_sac: float      # Bit Independence Criterion - SAC (Target: ~0.5)
    lap: float          # Linear Approximation Probability (Target: 0.0625)
    dap: float          # Differential Approximation Probability (Target: 0.015625)

    du: int  # DU (Nilai mentah max difference, misal: 4)
    ad: int         # AD (Max: 7 untuk 8-bit)
    to: float     # TO (Ketahanan DPA)
    ci: int     # CI (Biasanya 0 untuk S-box AES)