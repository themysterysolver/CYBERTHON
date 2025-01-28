from pydantic import BaseModel

class Vulnerability(BaseModel):
    target: str
    v_type: str
    cvss: float
    exploitability: float
    asset_value: float
    risk_score: float
