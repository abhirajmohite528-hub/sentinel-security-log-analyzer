
from contextlib import asynccontextmanager
from typing import List

from fastapi import FastAPI, Query
from pydantic import BaseModel

from database.db import (
    initialize_database,
    save_logs,
    save_alerts,
    get_connection,
)
from detectors.login_detector import detect_brute_force


# Initialize the database when the application starts.
@asynccontextmanager
async def lifespan(app: FastAPI):
    initialize_database()
    yield


app = FastAPI(
    title="Sentinel",
    description="Cybersecurity Log Analyzer API",
    version="1.0.0",
    lifespan=lifespan,
)


# Request models
class LoginLog(BaseModel):
    timestamp: str
    ip_address: str
    status: str


class LogBatch(BaseModel):
    logs: List[LoginLog]


# Home endpoint
@app.get("/")
def home():
    return {
        "project": "Sentinel",
        "status": "running",
        "message": "Cybersecurity Log Analyzer is ready",
    }


# Health check endpoint
@app.get("/health")
def health_check():
    return {"status": "healthy"}


# Analyze and save login logs
@app.post("/analyze")
def analyze_logs(batch: LogBatch):
    logs = [log.model_dump() for log in batch.logs]

    alerts = detect_brute_force(logs)

    save_logs(logs)
    save_alerts(alerts)

    return {
        "logs_analyzed": len(logs),
        "alerts_found": len(alerts),
        "alerts": alerts,
        "database_saved": True,
    }


# Retrieve and filter stored security alerts
@app.get("/alerts")
def get_alerts(
    severity: str | None = Query(
        default=None,
        description="Filter by severity, e.g. High",
    ),
    reviewed: bool | None = Query(
        default=None,
        description="Filter by review status: true or false",
    ),
):
    query = "SELECT * FROM alerts WHERE 1=1"
    parameters = []

    if severity:
        query += " AND LOWER(severity) = LOWER(?)"
        parameters.append(severity)

    if reviewed is not None:
        query += " AND reviewed = ?"
        parameters.append(int(reviewed))

    query += " ORDER BY id DESC"

    with get_connection() as connection:
        rows = connection.execute(query, parameters).fetchall()

    return {
        "total_alerts": len(rows),
        "alerts": [dict(row) for row in rows],
    }


@app.patch("/alerts/{alert_id}/review")
def mark_alert_reviewed(alert_id: int):
    with get_connection() as connection:
        cursor = connection.execute(
            "UPDATE alerts SET reviewed = 1 WHERE id = ?",
            (alert_id,),
        )

        if cursor.rowcount == 0:
            return {
                "success": False,
                "message": f"Alert with ID {alert_id} not found",
            }

    return {
        "success": True,
        "message": f"Alert {alert_id} marked as reviewed",
    }
