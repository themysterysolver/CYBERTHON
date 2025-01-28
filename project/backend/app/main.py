from fastapi import FastAPI
from app.models import Vulnerability
from app.scanner import run_nmap_scan
from app.ml import calculate_risk

app = FastAPI()

@app.get("/")
def read_root():
    return {"message": "Welcome to the Web Vulnerability API"}

@app.get("/scan/")
def scan_target(target: str, cvss: float, asset_value: float, exploitability: float):
    # Example scan logic
    nmap_result = run_nmap_scan(target)
    risk_score = calculate_risk(cvss, asset_value, exploitability)
    vulnerability = Vulnerability(
        target=target,
        v_type="network",
        cvss=cvss,
        exploitability=exploitability,
        asset_value=asset_value,
        risk_score=risk_score
    )
    return {
        "nmap_result": nmap_result,
        "vulnerability": vulnerability.dict(),
    }
