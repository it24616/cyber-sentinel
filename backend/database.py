"""Small SQLite persistence layer for security alerts."""

import json
import os
import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATABASE = Path(os.getenv("CYBER_SENTINEL_DB", Path(__file__).with_name("security.db")))


@contextmanager
def get_connection():
    DATABASE.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(DATABASE), timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=10000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database():
    with get_connection() as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("""CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            source TEXT NOT NULL,
            event_type TEXT NOT NULL DEFAULT 'security_event',
            external_id TEXT,
            event_data TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            received_at TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            detected_threats TEXT NOT NULL,
            matched_rules TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            UNIQUE(owner_id, source, external_id)
        )""")
        connection.execute("""CREATE TABLE IF NOT EXISTS security_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_data TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            detected_threats TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'Open',
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )""")
        connection.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            phone TEXT NOT NULL DEFAULT '',
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )""")
        # security_events references users, so ensure this works for older databases
        # where the users table was not part of the original schema.
        connection.execute("""CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL UNIQUE,
            key_prefix TEXT NOT NULL,
            created_at TEXT NOT NULL,
            last_used_at TEXT,
            revoked_at TEXT
        )""")
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(security_alerts)")}
        if "matched_rules" not in columns:
            connection.execute("ALTER TABLE security_alerts ADD COLUMN matched_rules TEXT NOT NULL DEFAULT '[]'")
        if "owner_id" not in columns:
            connection.execute("ALTER TABLE security_alerts ADD COLUMN owner_id INTEGER REFERENCES users(id)")
        if "source" not in columns:
            connection.execute("ALTER TABLE security_alerts ADD COLUMN source TEXT NOT NULL DEFAULT 'manual'")
        if "event_id" not in columns:
            connection.execute("ALTER TABLE security_alerts ADD COLUMN event_id INTEGER")
        if "updated_at" not in columns:
            connection.execute("ALTER TABLE security_alerts ADD COLUMN updated_at TEXT")
        if "resolved_at" not in columns:
            connection.execute("ALTER TABLE security_alerts ADD COLUMN resolved_at TEXT")
        if "resolution_note" not in columns:
            connection.execute("ALTER TABLE security_alerts ADD COLUMN resolution_note TEXT NOT NULL DEFAULT ''")
        if "is_deleted" not in columns:
            connection.execute("ALTER TABLE security_alerts ADD COLUMN is_deleted INTEGER NOT NULL DEFAULT 0")
        if "deleted_at" not in columns:
            connection.execute("ALTER TABLE security_alerts ADD COLUMN deleted_at TEXT")
        connection.execute("""CREATE TABLE IF NOT EXISTS alert_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id INTEGER NOT NULL REFERENCES security_alerts(id) ON DELETE CASCADE,
            actor_id INTEGER REFERENCES users(id),
            action TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        )""")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_created ON security_alerts(id DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status_level ON security_alerts(status, risk_level)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_alerts_owner_created ON security_alerts(owner_id, id DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_events_owner_created ON security_events(owner_id, id DESC)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_owner ON api_keys(owner_id, revoked_at)")


def database_ready():
    try:
        with get_connection() as connection:
            connection.execute("SELECT 1 FROM users LIMIT 1").fetchone()
            connection.execute("SELECT 1 FROM security_events LIMIT 1").fetchone()
            connection.execute("SELECT 1 FROM security_alerts LIMIT 1").fetchone()
        return True
    except sqlite3.Error:
        return False


def create_user(full_name, email, phone, password_hash):
    try:
        with get_connection() as connection:
            cursor = connection.execute("""INSERT INTO users (full_name, email, phone, password_hash, created_at)
                VALUES (?, ?, ?, ?, ?)""", (
                full_name, email.strip().lower(), phone, password_hash,
                datetime.now(timezone.utc).isoformat(timespec="seconds")
            ))
            user_id = cursor.lastrowid
            user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            if user_count == 1:
                # Alerts created before account support have no owner. Claim them
                # once for the first local account and record the migration.
                legacy_ids = [row["id"] for row in connection.execute(
                    "SELECT id FROM security_alerts WHERE owner_id IS NULL AND is_deleted = 0").fetchall()]
                if legacy_ids:
                    connection.execute("UPDATE security_alerts SET owner_id = ? WHERE owner_id IS NULL AND is_deleted = 0", (user_id,))
                    migrated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
                    connection.executemany("""INSERT INTO alert_activity
                        (alert_id, actor_id, action, details, created_at)
                        VALUES (?, ?, 'legacy_imported', '{\"source\":\"pre-authentication database\"}', ?)""",
                        [(alert_id, user_id, migrated_at) for alert_id in legacy_ids])
            return user_id
    except sqlite3.IntegrityError:
        return None


def get_user_by_email(email):
    with get_connection() as connection:
        row = connection.execute("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email.strip(),)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id):
    with get_connection() as connection:
        row = connection.execute("SELECT id, full_name, email, phone, role, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def update_password_hash(user_id, password_hash):
    with get_connection() as connection:
        connection.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))


def create_api_key(owner_id, name, raw_key):
    with get_connection() as connection:
        cursor = connection.execute("""INSERT INTO api_keys (owner_id, name, key_hash, key_prefix, created_at)
            VALUES (?, ?, ?, ?, ?)""", (
            owner_id, name, hashlib.sha256(raw_key.encode()).hexdigest(), raw_key[:18],
            datetime.now(timezone.utc).isoformat(timespec="seconds")
        ))
        return cursor.lastrowid


def list_api_keys(owner_id):
    with get_connection() as connection:
        rows = connection.execute("""SELECT id, name, key_prefix, created_at, last_used_at, revoked_at
            FROM api_keys WHERE owner_id = ? ORDER BY id DESC""", (owner_id,)).fetchall()
        return [dict(row) for row in rows]


def count_active_api_keys(owner_id):
    with get_connection() as connection:
        return connection.execute("SELECT COUNT(*) FROM api_keys WHERE owner_id = ? AND revoked_at IS NULL",
                                  (owner_id,)).fetchone()[0]


def get_api_key(raw_key):
    digest = hashlib.sha256(raw_key.encode()).hexdigest()
    with get_connection() as connection:
        row = connection.execute("""SELECT id, owner_id, name FROM api_keys
            WHERE key_hash = ? AND revoked_at IS NULL""", (digest,)).fetchone()
        return dict(row) if row else None


def mark_api_key_used(key_id):
    with get_connection() as connection:
        connection.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                           (datetime.now(timezone.utc).isoformat(timespec="seconds"), key_id))


def revoke_api_key(owner_id, key_id):
    with get_connection() as connection:
        cursor = connection.execute("""UPDATE api_keys SET revoked_at = ?
            WHERE owner_id = ? AND id = ? AND revoked_at IS NULL""",
            (datetime.now(timezone.utc).isoformat(timespec="seconds"), owner_id, key_id))
        return cursor.rowcount > 0


def record_event(owner_id, source, event_type, external_id, event_data, observed_at, result, alert_min_score=1):
    """Store an assessed event; open an alert when its risk score reaches alert_min_score."""
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    try:
        with get_connection() as connection:
            cursor = connection.execute("""INSERT INTO security_events
                (owner_id, source, event_type, external_id, event_data, observed_at, received_at,
                 risk_score, risk_level, detected_threats, matched_rules, recommendation)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (
                owner_id, source, event_type, external_id, event_data, observed_at, now,
                result["risk_score"], result["risk_level"], json.dumps(result["detected_threats"]),
                json.dumps(result["matched_rules"]), result["recommendation"]
            ))
            event_id = cursor.lastrowid
            alert_id = None
            if result["risk_score"] >= alert_min_score:
                alert = connection.execute("""INSERT INTO security_alerts
                    (event_data, risk_score, risk_level, detected_threats, recommendation,
                     matched_rules, created_at, owner_id, source, event_id, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", (
                    event_data, result["risk_score"], result["risk_level"],
                    json.dumps(result["detected_threats"]), result["recommendation"],
                    json.dumps(result["matched_rules"]), now, owner_id, source, event_id, now
                ))
                alert_id = alert.lastrowid
                connection.execute("INSERT INTO alert_activity (alert_id, actor_id, action, details, created_at) VALUES (?, ?, 'created', ?, ?)",
                                   (alert_id, owner_id, json.dumps({"source": source, "risk_score": result["risk_score"]}), now))
            return {"event_id": event_id, "alert_id": alert_id, "duplicate": False}
    except sqlite3.IntegrityError as error:
        # A stable external id is an idempotency key per account and source.
        if external_id is None:
            raise
        with get_connection() as connection:
            existing = connection.execute("""SELECT id FROM security_events
                WHERE owner_id = ? AND source = ? AND external_id = ?""",
                (owner_id, source, external_id)).fetchone()
        if existing:
            return {"event_id": existing["id"], "alert_id": None, "duplicate": True}
        raise error


def get_recent_events(owner_id, page=1, per_page=50, risk_level=None, source=None):
    clauses, params = ["owner_id = ?"], [owner_id]
    if risk_level:
        clauses.append("risk_level = ?")
        params.append(risk_level.upper())
    if source:
        clauses.append("source = ?")
        params.append(source)
    where = " WHERE " + " AND ".join(clauses)
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM security_events" + where, params).fetchone()[0]
        rows = connection.execute("SELECT * FROM security_events" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
                                  params + [per_page, (page - 1) * per_page]).fetchall()
    events = []
    for row in rows:
        event = dict(row)
        event["detected_threats"] = json.loads(event["detected_threats"])
        event["matched_rules"] = json.loads(event["matched_rules"])
        events.append(event)
    return events, total


def get_all_alerts(owner_id, status=None, risk_level=None, is_read=None, page=1, per_page=50):
    clauses, params = ["owner_id = ?", "is_deleted = 0"], [owner_id]
    if status:
        clauses.append("status = ?")
        params.append(status)
    if risk_level:
        clauses.append("risk_level = ?")
        params.append(risk_level.upper())
    if is_read is not None:
        clauses.append("is_read = ?")
        params.append(int(is_read == "true"))
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM security_alerts" + where, params).fetchone()[0]
        rows = connection.execute("SELECT * FROM security_alerts" + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
                                  params + [per_page, (page - 1) * per_page]).fetchall()
    alerts = []
    for row in rows:
        alert = dict(row)
        alert["detected_threats"] = json.loads(alert["detected_threats"])
        alert["matched_rules"] = json.loads(alert.get("matched_rules") or "[]")
        alert["is_read"] = bool(alert["is_read"])
        alerts.append(alert)
    return alerts, total


def get_alert_status(owner_id, alert_id):
    with get_connection() as connection:
        row = connection.execute("SELECT status FROM security_alerts WHERE owner_id = ? AND id = ? AND is_deleted = 0",
                                 (owner_id, alert_id)).fetchone()
        return row["status"] if row else None


def get_alert_stats(owner_id):
    with get_connection() as connection:
        total = connection.execute("SELECT COUNT(*) FROM security_alerts WHERE owner_id = ? AND is_deleted = 0", (owner_id,)).fetchone()[0]
        total_events = connection.execute("SELECT COUNT(*) FROM security_events WHERE owner_id = ?", (owner_id,)).fetchone()[0]
        open_count = connection.execute("SELECT COUNT(*) FROM security_alerts WHERE owner_id = ? AND is_deleted = 0 AND status NOT IN ('Resolved', 'False Positive')", (owner_id,)).fetchone()[0]
        unread = connection.execute("SELECT COUNT(*) FROM security_alerts WHERE owner_id = ? AND is_deleted = 0 AND is_read = 0", (owner_id,)).fetchone()[0]
        levels = {row["risk_level"]: row["count"] for row in connection.execute(
            "SELECT risk_level, COUNT(*) AS count FROM security_alerts WHERE owner_id = ? AND is_deleted = 0 GROUP BY risk_level", (owner_id,))}
        event_levels = {row["risk_level"]: row["count"] for row in connection.execute(
            "SELECT risk_level, COUNT(*) AS count FROM security_events WHERE owner_id = ? GROUP BY risk_level", (owner_id,))}
        recent = connection.execute("SELECT COUNT(*) FROM security_alerts WHERE owner_id = ? AND is_deleted = 0 AND created_at >= ?",
                                    (owner_id, datetime.now(timezone.utc).date().isoformat())).fetchone()[0]
        today_events = connection.execute("SELECT COUNT(*) FROM security_events WHERE owner_id = ? AND received_at >= ?",
                                          (owner_id, datetime.now(timezone.utc).date().isoformat())).fetchone()[0]
        # Keep the last 24 UTC hours available for the monitoring chart.
        current_hour = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        start = current_hour - timedelta(hours=23)
        hourly = {row["hour"]: row["count"] for row in connection.execute(
            "SELECT substr(received_at, 1, 13) AS hour, COUNT(*) AS count "
            "FROM security_events WHERE owner_id = ? AND risk_score > 0 AND received_at >= ? GROUP BY hour",
            (owner_id, start.isoformat(timespec="seconds")))}
        trend = [{"hour": (start + timedelta(hours=offset)).strftime("%Y-%m-%dT%H"),
                  "count": hourly.get((start + timedelta(hours=offset)).strftime("%Y-%m-%dT%H"), 0)}
                 for offset in range(24)]
        # Last 7 UTC days of events with at least one indicator, for the dashboard chart.
        first_day = datetime.now(timezone.utc).date() - timedelta(days=6)
        daily_counts = {row["day"]: row["count"] for row in connection.execute(
            "SELECT substr(received_at, 1, 10) AS day, COUNT(*) AS count "
            "FROM security_events WHERE owner_id = ? AND risk_score > 0 AND received_at >= ? GROUP BY day",
            (owner_id, first_day.isoformat()))}
        daily = [{"day": (first_day + timedelta(days=offset)).isoformat(),
                  "count": daily_counts.get((first_day + timedelta(days=offset)).isoformat(), 0)}
                 for offset in range(7)]
        open_levels = {row["risk_level"]: row["count"] for row in connection.execute(
            "SELECT risk_level, COUNT(*) AS count FROM security_alerts WHERE owner_id = ? AND is_deleted = 0 "
            "AND status NOT IN ('Resolved', 'False Positive') GROUP BY risk_level", (owner_id,))}
        last_event_at = connection.execute("SELECT MAX(received_at) FROM security_events WHERE owner_id = ?",
                                           (owner_id,)).fetchone()[0]
    open_by_level = {level: open_levels.get(level, 0) for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    # Posture = highest severity among alerts that still need attention.
    posture = next((level for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if open_by_level[level]), "CLEAR")
    return {"total": total, "open": open_count, "unread": unread,
            "open_by_risk_level": open_by_level, "posture": posture,
            "daily": daily, "last_event_at": last_event_at,
            "by_risk_level": {level: levels.get(level, 0) for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
            "event_by_risk_level": {level: event_levels.get(level, 0) for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
            "total_events": total_events, "today": recent, "today_events": today_events, "hourly": trend}


def update_alert(owner_id, actor_id, alert_id, status=None, is_read=None, resolution_note=None):
    fields, params = [], []
    if status is not None:
        fields.append("status = ?")
        params.append(status)
    if is_read is not None:
        fields.append("is_read = ?")
        params.append(int(is_read))
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with get_connection() as connection:
        existing = connection.execute("SELECT status, is_read FROM security_alerts WHERE id = ? AND owner_id = ? AND is_deleted = 0",
                                      (alert_id, owner_id)).fetchone()
        if not existing:
            return False
        if status is not None and status != existing["status"]:
            fields.extend(("updated_at = ?", "resolved_at = ?", "resolution_note = ?"))
            params.extend((now, now if status in ("Resolved", "False Positive") else None, resolution_note or ""))
        params.extend((alert_id, owner_id))
        cursor = connection.execute(f"UPDATE security_alerts SET {', '.join(fields)} WHERE id = ? AND owner_id = ? AND is_deleted = 0", params)
        if status is not None and status != existing["status"]:
            connection.execute("INSERT INTO alert_activity (alert_id, actor_id, action, details, created_at) VALUES (?, ?, 'status_changed', ?, ?)",
                               (alert_id, actor_id, json.dumps({"from": existing["status"], "to": status, "note": resolution_note or ""}), now))
        if is_read is not None and int(is_read) != existing["is_read"]:
            action = "marked_read" if is_read else "marked_unread"
            connection.execute("INSERT INTO alert_activity (alert_id, actor_id, action, details, created_at) VALUES (?, ?, ?, '', ?)",
                               (alert_id, actor_id, action, now))
        return cursor.rowcount > 0


def delete_alert(owner_id, actor_id, alert_id):
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    with get_connection() as connection:
        cursor = connection.execute("UPDATE security_alerts SET is_deleted = 1, deleted_at = ? WHERE id = ? AND owner_id = ? AND is_deleted = 0",
                                    (now, alert_id, owner_id))
        if cursor.rowcount:
            connection.execute("INSERT INTO alert_activity (alert_id, actor_id, action, details, created_at) VALUES (?, ?, 'archived', '', ?)",
                               (alert_id, actor_id, now))
            return True
        return False


def get_alert_activity(owner_id, alert_id):
    with get_connection() as connection:
        rows = connection.execute("""SELECT aa.id, aa.action, aa.details, aa.created_at, u.full_name AS actor
            FROM alert_activity aa JOIN security_alerts a ON a.id = aa.alert_id
            LEFT JOIN users u ON u.id = aa.actor_id
            WHERE a.owner_id = ? AND aa.alert_id = ? ORDER BY aa.id DESC""",
            (owner_id, alert_id)).fetchall()
        return [{**dict(row), "details": json.loads(row["details"] or "{}")} for row in rows]


def get_recent_activity(owner_id, limit=10):
    """Newest alert activity across the account, for the dashboard feed."""
    with get_connection() as connection:
        rows = connection.execute("""SELECT aa.id, aa.alert_id, aa.action, aa.details, aa.created_at,
                   u.full_name AS actor, a.risk_level, a.detected_threats, a.source
            FROM alert_activity aa JOIN security_alerts a ON a.id = aa.alert_id
            LEFT JOIN users u ON u.id = aa.actor_id
            WHERE a.owner_id = ? ORDER BY aa.id DESC LIMIT ?""", (owner_id, limit)).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        item["details"] = json.loads(item["details"] or "{}")
        item["detected_threats"] = json.loads(item["detected_threats"] or "[]")
        items.append(item)
    return items


def get_detection_overview(owner_id, since_id=0, limit=25):
    """Rolling 24-hour detection metrics plus the newest events for live polling."""
    window_start = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
    with get_connection() as connection:
        totals = connection.execute("""SELECT COUNT(*) AS events,
                COALESCE(SUM(risk_score > 0), 0) AS detections,
                COALESCE(MAX(risk_score), 0) AS max_score
            FROM security_events WHERE owner_id = ? AND received_at >= ?""",
            (owner_id, window_start)).fetchone()
        levels = {row["risk_level"]: row["count"] for row in connection.execute(
            """SELECT risk_level, COUNT(*) AS count FROM security_events
               WHERE owner_id = ? AND received_at >= ? GROUP BY risk_level""", (owner_id, window_start))}
        top_rules = [dict(row) for row in connection.execute(
            """SELECT j.value AS rule_id, COUNT(*) AS count
               FROM security_events e, json_each(e.matched_rules) j
               WHERE e.owner_id = ? AND e.received_at >= ?
               GROUP BY j.value ORDER BY count DESC, rule_id LIMIT 10""", (owner_id, window_start))]
        top_sources = [dict(row) for row in connection.execute(
            """SELECT source, COUNT(*) AS count, MAX(risk_score) AS max_score
               FROM security_events WHERE owner_id = ? AND received_at >= ? AND risk_score > 0
               GROUP BY source ORDER BY count DESC, source LIMIT 5""", (owner_id, window_start))]
        latest_id = connection.execute("SELECT COALESCE(MAX(id), 0) FROM security_events WHERE owner_id = ?",
                                       (owner_id,)).fetchone()[0]
        rows = connection.execute(
            """SELECT e.id, e.source, e.event_type, e.event_data, e.observed_at, e.received_at,
                      e.risk_score, e.risk_level, e.detected_threats, e.matched_rules, e.recommendation,
                      a.id AS alert_id, a.status AS alert_status
               FROM security_events e
               LEFT JOIN security_alerts a ON a.event_id = e.id AND a.owner_id = e.owner_id AND a.is_deleted = 0
               WHERE e.owner_id = ? AND e.id > ? ORDER BY e.id DESC LIMIT ?""",
            (owner_id, since_id, limit)).fetchall()
    events = []
    for row in rows:
        event = dict(row)
        event["event_data"] = event["event_data"][:500]
        event["detected_threats"] = json.loads(event["detected_threats"])
        event["matched_rules"] = json.loads(event["matched_rules"])
        events.append(event)
    return {
        "window_hours": 24,
        "events_24h": totals["events"],
        "detections_24h": totals["detections"],
        "max_score_24h": totals["max_score"],
        "by_risk_level_24h": {level: levels.get(level, 0) for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
        "top_rules": top_rules,
        "top_sources": top_sources,
        "latest_id": latest_id,
        "events": events,
    }
