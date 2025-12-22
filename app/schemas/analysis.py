from pydantic import BaseModel

class AnalysisResponse(BaseModel):
    nl: int             # Nonlinearity (Target: 112)
    sac: float          # Strict Avalanche Criterion (Target: ~0.5)
    bic_nl: int         # Bit Independence Criterion - Nonlinearity (Target: 112)
    bic_sac: float      # Bit Independence Criterion - SAC (Target: ~0.5)
    lap: float          # Linear Approximation Probability (Target: 0.0625)
    dap: float          # Differential Approximation Probability (Target: 0.015625)
    du: int             # Differential Uniformity (Target: 4)
    ad: int             # Algebraic Degree (Target: 7)
    to: float           # Transparency Order (Target: rendah)
    ci: int             # Correlation Immunity (Target: tinggi)
