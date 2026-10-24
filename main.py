
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

from detectors.login_detector import (
    detect_brute_force,
    detect_multiple_account_targeting,
)


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


# Data models

class LoginLog(BaseModel):
    timestamp: str
    ip_address: str
    status: str
    username: str = "unknown"


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


# Analyze login logs

@app.post("/analyze")
def analyze_logs(batch: LogBatch):
    logs = [log.model_dump() for log in batch.logs]

    # Detection rule 1: repeated failed logins
    alerts = detect_brute_force(logs)

    # Detection rule 2: one IP targeting multiple usernames
    account_targeting_alerts = detect_multiple_account_targeting(logs)
    alerts.extend(account_targeting_alerts)

    # Save logs and alerts to the database
    save_logs(logs)
    save_alerts(alerts)

    return {
        "logs_analyzed": len(logs),
        "alerts_found": len(alerts),
        "alerts": alerts,
        "database_saved": True,
    }


# Get alerts with optional filters

@app.get("/alerts")
def get_alerts(
    severity: str | None = Query(default=None),
    reviewed: bool | None = Query(default=None),
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


# Mark an alert as reviewed

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


# Get login logs with optional filters

@app.get("/logs")
def get_logs(
    status: str | None = Query(default=None),
    ip_address: str | None = Query(default=None),
):
    query = "SELECT * FROM login_logs WHERE 1=1"
    parameters = []

    if status:
        query += " AND LOWER(status) = LOWER(?)"
        parameters.append(status)

    if ip_address:
        query += " AND ip_address = ?"
        parameters.append(ip_address)

    query += " ORDER BY id DESC"

    with get_connection() as connection:
        rows = connection.execute(query, parameters).fetchall()

    return {
        "total_logs": len(rows),
        "logs": [dict(row) for row in rows],
    }


# Dashboard summary

@app.get("/dashboard")
def get_dashboard():
    with get_connection() as connection:
        total_logs = connection.execute(
            "SELECT COUNT(*) FROM login_logs"
        ).fetchone()[0]

        failed_logins = connection.execute(
            "SELECT COUNT(*) FROM login_logs "
            "WHERE LOWER(status) = 'failed'"
        ).fetchone()[0]

        successful_logins = connection.execute(
            "SELECT COUNT(*) FROM login_logs "
            "WHERE LOWER(status) = 'success'"
        ).fetchone()[0]

        total_alerts = connection.execute(
            "SELECT COUNT(*) FROM alerts"
        ).fetchone()[0]

        unreviewed_alerts = connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE reviewed = 0"
        ).fetchone()[0]

        high_severity_alerts = connection.execute(
            "SELECT COUNT(*) FROM alerts "
            "WHERE LOWER(severity) = 'high'"
        ).fetchone()[0]

    return {
        "total_logs": total_logs,
        "failed_logins": failed_logins,
        "successful_logins": successful_logins,
        "total_alerts": total_alerts,
        "unreviewed_alerts": unreviewed_alerts,
        "high_severity_alerts": high_severity_alerts,
    }
