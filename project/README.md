# Web Vulnerability Dashboard

This project provides an AI-powered vulnerability prioritization dashboard with automated risk scoring and actionable remediation steps.

## Features
- Automated scanning using Nmap and mock Burp Suite results.
- Risk scoring with a simplified ML model.
- Interactive React.js dashboard to view vulnerabilities.

## Tech Stack
- Backend: FastAPI, Python
- Frontend: React.js, D3.js
- Database: PostgreSQL

## Setup
1. Clone the repository.
2. Build and run the project using Docker Compose.
3. Access the frontend at `http://localhost:3000` and backend at `http://localhost:8000`.

## Future Enhancements
- Integrate Burp Suite/ZAP for web app vulnerability detection.
- Add Neo4j for attack graph visualization.
