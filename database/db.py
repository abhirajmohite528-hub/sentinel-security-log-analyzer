
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "sentinel.db"


def get_connection():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS login_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                status TEXT NOT NULL,
                username TEXT NOT NULL DEFAULT 'unknown'
            )
        """)

        # Safely upgrade databases created by earlier versions.
        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(login_logs)"
            ).fetchall()
        }

        if "username" not in columns:
            connection.execute("""
                ALTER TABLE login_logs
                ADD COLUMN username TEXT NOT NULL DEFAULT 'unknown'
            """)

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                failed_attempts INTEGER NOT NULL,
                window_minutes INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                message TEXT NOT NULL,
                reviewed INTEGER NOT NULL DEFAULT 0
            )
        """)


def save_logs(logs):
    with get_connection() as connection:
        connection.executemany("""
            INSERT INTO login_logs
                (timestamp, ip_address, status, username)
            VALUES
                (:timestamp, :ip_address, :status, :username)
        """, [
            {**log, "username": log.get("username") or "unknown"}
            for log in logs
        ])


def save_alerts(alerts):
    with get_connection() as connection:
        connection.executemany("""
            INSERT INTO alerts (
                alert_type, severity, ip_address, failed_attempts,
                window_minutes, timestamp, message
            )
            VALUES (
                :type, :severity, :ip_address, :failed_attempts,
                :window_minutes, :timestamp, :message
            )
        """, alerts)
