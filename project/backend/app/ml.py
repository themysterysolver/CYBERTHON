def calculate_risk(cvss: float, asset_value: float, exploitability: float) -> float:
    return (cvss * 0.6) + (asset_value * 0.25) + (exploitability * 0.15)
