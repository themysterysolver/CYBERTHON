# Cyberthon Security Platform

## Setup Instructions

1. Install Docker & Docker Compose:

   
   sudo apt update && sudo apt install docker docker-compose -y
   sudo systemctl start docker
   sudo systemctl enable docker
   

2. Start the entire project:

   
   docker-compose up -d
   

3. Verify running containers:

   
   docker ps
   

4. Test AI Model API:

   
   curl -X POST "http://localhost:8000/classify_vulnerability/" -H "Content-Type: application/json"
   

5. Open `http://localhost:3000` to access the security dashboard.


---

### *How to Run the Project*
1. Clone the repository.
2. Run:
   bash
   docker-compose up -d
   
3. Access:
   - AI API: http://localhost:8000
   - Dashboard: http://localhost:3000
   - OpenVAS UI: http://localhost:9392