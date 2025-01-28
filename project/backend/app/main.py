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

@app.get("/cve/{cve_id}")
def get_cve_data(cve_id: str):
    import requests
    response = requests.get(f"https://services.nvd.nist.gov/rest/json/cve/1.0/{cve_id}")
    if response.status_code == 200:
        return response.json()
    else:
        return {"error": f"Failed to fetch data for CVE ID: {cve_id}"}

@app.get("/webscan/")
def scan_web_app(target: str):
    import subprocess
    try:
        result = subprocess.run(
            ["zap-cli", "quick-scan", target],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        return {"result": result.stdout.decode("utf-8")}
    except Exception as e:
        return {"error": str(e)}

@app.post("/predict-risk/")
def predict_risk(data: dict):
    cvss = data.get("cvss", 0)
    asset_value = data.get("asset_value", 0)
    exploitability = data.get("exploitability", 0)

    risk_score = calculate_risk(cvss, asset_value, exploitability)
    return {"risk_score": risk_score}
