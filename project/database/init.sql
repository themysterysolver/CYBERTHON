CREATE DATABASE IF NOT EXISTS websec;

\c websec;

-- Table creation
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id SERIAL PRIMARY KEY,
    target VARCHAR(255),
    type VARCHAR(50),
    cvss FLOAT,
    exploitability FLOAT,
    asset_value FLOAT,
    risk_score FLOAT,
    status VARCHAR(50) DEFAULT 'Open'
);

-- Data insertion
INSERT INTO vulnerabilities (target, type, cvss, exploitability, asset_value, risk_score)
VALUES 
    ('127.0.0.1', 'network', 9.8, 8.5, 7.2, 8.8),
    ('192.168.0.1', 'web', 7.5, 6.8, 7.0, 7.4);
