import os
import sqlite3
from datetime import datetime, timezone

# Keep the database in logs/ at the project root, no matter where the script is run from
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(PROJECT_ROOT, "logs", "automation.db")

def get_connection():
    """Create a connection to the automation database."""

    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    connection = sqlite3.connect(DB_PATH)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS processed_alerts (
            alert_id TEXT PRIMARY KEY,
            processed_at TEXT NOT NULL
        )
    """)

    connection.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            alert_id TEXT NOT NULL,
            rule_id TEXT,
            severity TEXT,
            action TEXT,
            source_ip TEXT,
            agent TEXT,
            response_result TEXT
        )
    """)

    connection.commit()

    return connection

def is_processed(alert_id):
    """Return True if an alert has already been processed."""

    connection = get_connection()

    cursor = connection.execute(
        "SELECT 1 FROM processed_alerts WHERE alert_id = ?",
        (alert_id,)
    )

    result = cursor.fetchone()

    connection.close()

    return result is not None

def mark_processed(alert_id):
    """Mark an alert as processed."""

    connection = get_connection()

    connection.execute(
        """
        INSERT OR IGNORE INTO processed_alerts
        (alert_id, processed_at)
        VALUES (?, ?)
        """,
        (
            alert_id,
            datetime.now(timezone.utc).isoformat()
        )
    )

    connection.commit()
    connection.close()

def log_action(
    alert_id,
    rule_id,
    severity,
    action,
    source_ip,
    agent,
    response_result
):
    """Record an automation decision and response result."""

    connection = get_connection()

    connection.execute(
        """
        INSERT INTO audit_log
        (
            timestamp,
            alert_id,
            rule_id,
            severity,
            action,
            source_ip,
            agent,
            response_result
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            datetime.now(timezone.utc).isoformat(),
            alert_id,
            rule_id,
            severity,
            action,
            source_ip,
            agent,
            response_result
        )
    )

    connection.commit()
    connection.close()
