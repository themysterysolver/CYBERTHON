CREATE DATABASE websec;

\c websec;

CREATE TABLE vulnerabilities (
    id SERIAL PRIMARY KEY,
    target VARCHAR(255),
    type VARCHAR(50),
    cvss FLOAT,
    exploitability FLOAT,
    asset_value FLOAT,
    risk_score FLOAT,
    status VARCHAR(50) DEFAULT 'Open'
);
