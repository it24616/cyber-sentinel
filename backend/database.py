
import sqlite3
import json
from datetime import datetime

DATABASE = "security.db"


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database():
    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_data TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            detected_threats TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            status TEXT DEFAULT 'Open',
            is_read INTEGER DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


def save_alert(event_data, result):
    connection = get_connection()

    connection.execute("""
        INSERT INTO security_alerts (
            event_data,
            risk_score,
            risk_level,
            detected_threats,
            recommendation,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        event_data,
        result["risk_score"],
        result["risk_level"],
        json.dumps(result["detected_threats"]),
        result["recommendation"],
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    connection.commit()
    connection.close()


def get_all_alerts():
    connection = get_connection()

    rows = connection.execute("""
        SELECT * FROM security_alerts
        ORDER BY id DESC
    """).fetchall()

    connection.close()

    alerts = []
    for row in rows:
        alert = dict(row)
        alert["detected_threats"] = json.loads(
            alert["detected_threats"]
        )
        alert["is_read"] = bool(alert["is_read"])
        alerts.append(alert)

    return alerts


def update_alert(alert_id, status=None, is_read=None):
    connection = get_connection()

    if status is not None:
        connection.execute(
            "UPDATE security_alerts SET status = ? WHERE id = ?",
            (status, alert_id)
        )

    if is_read is not None:
        connection.execute(
            "UPDATE security_alerts SET is_read = ? WHERE id = ?",
            (int(is_read), alert_id)
        )

    connection.commit()
    changed = connection.total_changes
    connection.close()

    return changed > 0


def delete_alert(alert_id):
    connection = get_connection()

    cursor = connection.execute(
        "DELETE FROM security_alerts WHERE id = ?",
        (alert_id,)
    )

    connection.commit()
    deleted = cursor.rowcount > 0
    connection.close()

    return deleted
