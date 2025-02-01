from fastapi import FastAPI, HTTPException
import pandas as pd
import joblib
from transformers import pipeline
from sqlalchemy import create_engine, Column, Integer, String, JSON, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime

# Database setup
DATABASE_URL = "postgresql://admin:password@postgres_db/security_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)
    scan_data = Column(JSON)
    risk_level = Column(String)
    created_at = Column(TIMESTAMP, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# Load pre-trained vulnerability classifier
model = joblib.load("vuln_classifier.pkl")

# Load LLM for summarization and solutions
summarizer = pipeline("summarization", model="facebook/bart-large-cnn")

app = FastAPI()

def save_scan_results(scan_data, risk_level):
    db = SessionLocal()
    db.add(Vulnerability(scan_data=scan_data, risk_level=risk_level))
    db.commit()
    db.close()

@app.post("/classify_vulnerability/")
def classify_vuln(data: dict):
    try:
        # Classify vulnerability
        df = pd.DataFrame([data])
        prediction = model.predict(df)[0]

        # Summarize findings using LLM
        summary = summarizer(data.get("scan_results", ""), max_length=130, min_length=30, do_sample=False)

        # Generate solutions using LLM
        solutions = summarizer(f"Provide solutions for: {data.get('scan_results', '')}", max_length=130, min_length=30, do_sample=False)

        # Save results to the database
        save_scan_results(data.get("scan_results", ""), prediction)

        return {
            "risk_level": prediction,
            "summary": summary[0]["summary_text"],
            "solutions": solutions[0]["summary_text"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))