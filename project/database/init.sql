CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    scan_data JSONB,
    risk_level VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);