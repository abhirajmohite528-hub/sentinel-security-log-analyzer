
from fastapi import FastAPI
from pydantic import BaseModel
from typing import List

from detectors.login_detector import detect_brute_force

app = FastAPI(
    title="Sentinel",
    description="Cybersecurity Log Analyzer API",
    version="1.0.0"
)


class LoginLog(BaseModel):
    timestamp: str
    ip_address: str
    status: str


class LogBatch(BaseModel):
    logs: List[LoginLog]


@app.get("/")
def home():
    return {
        "project": "Sentinel",
        "status": "running",
        "message": "Cybersecurity Log Analyzer is ready"
    }


@app.get("/health")
def health_check():
    return {"status": "healthy"}


@app.post("/analyze")
def analyze_logs(batch: LogBatch):
    logs = [log.model_dump() for log in batch.logs]
    alerts = detect_brute_force(logs)

    return {
        "logs_analyzed": len(logs),
        "alerts_found": len(alerts),
        "alerts": alerts
    }
