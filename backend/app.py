"""Cyber Sentinel API: rule-based event assessment and alert management."""

import os
import re
import secrets
from datetime import datetime, timedelta, timezone
import json
from functools import wraps

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from flask import Flask, jsonify, request, session
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

load_dotenv()

try:  # Support both `python backend/app.py` and `python -m backend.app`.
    from .database import (
        count_active_api_keys, create_api_key, create_user, database_ready, delete_alert, get_all_alerts, get_alert_stats,
        get_alert_activity, get_alert_status, get_api_key, get_detection_overview, get_recent_events, get_user_by_email, get_user_by_id,
        initialize_database, list_api_keys, mark_api_key_used, record_event, update_password_hash,
        revoke_api_key, update_alert,
    )
    from .detection import ENGINE_NAME, ENGINE_VERSION, assess_risk, rule_catalog
except ImportError:
    from detection import ENGINE_NAME, ENGINE_VERSION, assess_risk, rule_catalog
    from database import (
        count_active_api_keys, create_api_key, create_user, database_ready, delete_alert, get_all_alerts, get_alert_stats,
        get_alert_activity, get_alert_status, get_api_key, get_detection_overview, get_recent_events, get_user_by_email, get_user_by_id,
        initialize_database, list_api_keys, mark_api_key_used, record_event, update_password_hash,
        revoke_api_key, update_alert,
    )

app = Flask(__name__)
environment = os.getenv("APP_ENV", "development").lower()
secret_key = os.getenv("SECRET_KEY")
if environment == "production" and not secret_key:
    raise RuntimeError("SECRET_KEY must be set in production.")
if environment == "production" and len(secret_key) < 32:
    raise RuntimeError("Production SECRET_KEY must contain at least 32 characters.")
cors_origins = [origin.strip() for origin in os.getenv(
    "CORS_ORIGINS", "http://127.0.0.1:5500,http://localhost:5500"
).split(",") if origin.strip()]
if environment == "production" and (not cors_origins or "*" in cors_origins):
    raise RuntimeError("Set explicit CORS_ORIGINS in production; wildcard origins are not allowed.")
app.secret_key = secret_key or "local-development-only-change-this-secret"
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "1" if environment == "production" else "0") == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
CORS(app, resources={r"/api/*": {"origins": cors_origins, "supports_credentials": True}})
initialize_database()
password_hasher = PasswordHasher()
dummy_password_hash = password_hasher.hash(secrets.token_urlsafe(32))
limiter = Limiter(key_func=get_remote_address, app=app,
                  default_limits=["120 per hour"],
                  storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"))


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.errorhandler(413)
def request_too_large(_error):
    return jsonify(success=False, error="Request body is too large."), 413


@app.errorhandler(429)
def rate_limit_exceeded(_error):
    return jsonify(success=False, error="Rate limit exceeded. Try again shortly."), 429


def require_auth(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        user = get_user_by_id(session.get("user_id")) if session.get("user_id") else None
        if not user or not user["is_active"]:
            session.clear()
            return jsonify(success=False, error="Authentication required."), 401
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            sent_token = request.headers.get("X-CSRF-Token", "")
            expected_token = session.get("csrf_token", "")
            if not expected_token or not secrets.compare_digest(sent_token, expected_token):
                return jsonify(success=False, error="Invalid or missing CSRF token."), 403
        request.current_user = user
        return handler(*args, **kwargs)
    return wrapped


def api_key_principal():
    authorization = request.headers.get("Authorization", "")
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.startswith("cs_live_") or len(token) > 160:
        return None
    key = get_api_key(token)
    if key:
        mark_api_key_used(key["id"])
    return key


def normalize_event(item, default_source):
    if not isinstance(item, dict):
        return None, "Each event must be a JSON object."
    raw_data = item.get("event_data", item.get("message"))
    if isinstance(raw_data, str):
        event_data = raw_data.strip()
    elif isinstance(raw_data, (dict, list)):
        event_data = json.dumps(raw_data, ensure_ascii=False, separators=(",", ":"))
    else:
        return None, "event_data must be text, an object, or an array."
    if not event_data or len(event_data) > 10000:
        return None, "event_data must contain 1 to 10,000 characters."

    source = item.get("source", default_source)
    event_type = item.get("event_type", "security_event")
    external_id = item.get("external_id")
    if not isinstance(source, str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,80}", source):
        return None, "source may contain letters, numbers, dot, underscore, colon, and dash (max 80)."
    if not isinstance(event_type, str) or not event_type.strip() or len(event_type) > 100:
        return None, "event_type must contain 1 to 100 characters."
    if external_id is not None and (not isinstance(external_id, str) or not external_id.strip() or len(external_id) > 200):
        return None, "external_id must be non-empty text up to 200 characters."
    observed_at = item.get("observed_at")
    if observed_at is None:
        parsed_time = datetime.now(timezone.utc)
    elif isinstance(observed_at, str):
        try:
            parsed_time = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
            if parsed_time.tzinfo is None:
                parsed_time = parsed_time.replace(tzinfo=timezone.utc)
        except ValueError:
            return None, "observed_at must be an ISO 8601 timestamp."
    else:
        return None, "observed_at must be an ISO 8601 timestamp."
    normalized = {
        "source": source,
        "event_type": event_type.strip(),
        "external_id": external_id.strip() if external_id else None,
        "event_data": event_data,
        "observed_at": parsed_time.astimezone(timezone.utc).isoformat(timespec="seconds"),
    }
    return normalized, None


@app.route("/api/auth/register", methods=["POST"])
@limiter.limit("5 per hour")
def register():
    signup_default = "0" if environment == "production" else "1"
    if os.getenv("ALLOW_SIGNUP", signup_default) != "1":
        return jsonify(success=False, error="Account registration is disabled."), 403
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(success=False, error="Expected a JSON object."), 400
    full_name = data.get("full_name", "").strip() if isinstance(data.get("full_name"), str) else ""
    email = data.get("email", "").strip().lower() if isinstance(data.get("email"), str) else ""
    phone = data.get("phone", "").strip() if isinstance(data.get("phone", ""), str) else ""
    password = data.get("password")
    if not full_name or len(full_name) > 120:
        return jsonify(success=False, error="Enter a name between 1 and 120 characters."), 400
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 254:
        return jsonify(success=False, error="Enter a valid email address."), 400
    if len(phone) > 40:
        return jsonify(success=False, error="Phone number is too long."), 400
    if not isinstance(password, str) or len(password) < 12 or len(password) > 128:
        return jsonify(success=False, error="Password must be 12 to 128 characters."), 400
    user_id = create_user(full_name, email, phone, password_hasher.hash(password))
    if not user_id:
        return jsonify(success=False, error="An account with that email already exists."), 409
    return jsonify(success=True, message="Account created. Sign in to continue."), 201


@app.route("/api/auth/login", methods=["POST"])
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True)
    email = data.get("email", "").strip() if isinstance(data, dict) and isinstance(data.get("email"), str) else ""
    password = data.get("password") if isinstance(data, dict) else None
    user = get_user_by_email(email) if email else None
    candidate_password = password if isinstance(password, str) and len(password) <= 128 else ""
    try:
        stored_hash = user["password_hash"] if user else dummy_password_hash
        verified = password_hasher.verify(stored_hash, candidate_password)
        valid = bool(user and user["is_active"] and isinstance(password, str) and len(password) <= 128 and verified)
    except (InvalidHashError, VerifyMismatchError, ValueError):
        valid = False
    if not valid:
        return jsonify(success=False, error="Email or password is incorrect."), 401
    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    if password_hasher.check_needs_rehash(user["password_hash"]):
        update_password_hash(user["id"], password_hasher.hash(candidate_password))
    return jsonify(success=True, user={"id": user["id"], "full_name": user["full_name"], "email": user["email"], "role": user["role"]}, csrf_token=session["csrf_token"])


@app.route("/api/auth/me", methods=["GET"])
@require_auth
def current_user():
    return jsonify(success=True, user=request.current_user, csrf_token=session.get("csrf_token"))


@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def logout():
    session.clear()
    return jsonify(success=True, message="Signed out.")


@app.route("/", methods=["GET"])
@app.route("/api/health", methods=["GET"])
def health():
    ready = database_ready()
    response = jsonify(success=ready, service="Cyber Sentinel API",
                       status="ready" if ready else "not_ready",
                       checks={"database": "ok" if ready else "unavailable"},
                       time=datetime.now(timezone.utc).isoformat())
    return response, 200 if ready else 503


@app.route("/api/health/live", methods=["GET"])
def liveness():
    return jsonify(success=True, service="Cyber Sentinel API", status="live",
                   time=datetime.now(timezone.utc).isoformat())


@app.route("/api/assess-risk", methods=["POST"])
@limiter.limit("20 per minute")
@require_auth
def risk_assessment():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(success=False, error="Expected a JSON object."), 400
    event_data = data.get("event_data")
    if not isinstance(event_data, str) or not event_data.strip():
        return jsonify(success=False, error="Please provide non-empty event_data text."), 400
    if len(event_data) > 10000:
        return jsonify(success=False, error="event_data must be 10,000 characters or fewer."), 400
    input_type = data.get("event_type", "general")
    if input_type not in ("general", "url", "request", "log"):
        return jsonify(success=False, error="event_type must be general, url, request, or log."), 400
    normalized, error = normalize_event({"event_data": event_data, "source": "manual-ui",
                                         "event_type": f"manual_{input_type}"}, "manual-ui")
    if error:
        return jsonify(success=False, error=error), 400
    result = assess_risk(normalized["event_data"])
    saved = record_event(request.current_user["id"], normalized["source"], normalized["event_type"],
                         None, normalized["event_data"], normalized["observed_at"], result)
    return jsonify(success=True, message="Assessment completed.", result=result, alert_id=saved["alert_id"], event_id=saved["event_id"])


@app.route("/api/detection/rules", methods=["GET"])
@require_auth
def detection_rules():
    return jsonify(success=True, engine={"name": ENGINE_NAME, "version": ENGINE_VERSION}, rules=rule_catalog())


@app.route("/api/detection/overview", methods=["GET"])
@limiter.limit("240 per minute")
@require_auth
def detection_overview():
    """Single polling endpoint for the live Threat Detection view."""
    try:
        since_id = int(request.args.get("since_id", 0))
        limit = min(50, max(1, int(request.args.get("limit", 25))))
    except ValueError:
        return jsonify(success=False, error="since_id and limit must be integers."), 400
    overview = get_detection_overview(request.current_user["id"], since_id=max(0, since_id), limit=limit)
    overview["engine"] = {"name": ENGINE_NAME, "version": ENGINE_VERSION, "rule_count": len(rule_catalog())}
    overview["server_time"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return jsonify(success=True, overview=overview)


@app.route("/api/integrations/keys", methods=["GET", "POST"])
@require_auth
def integration_keys():
    owner_id = request.current_user["id"]
    if request.method == "GET":
        return jsonify(success=True, api_keys=list_api_keys(owner_id))
    data = request.get_json(silent=True)
    name = data.get("name", "").strip() if isinstance(data, dict) and isinstance(data.get("name"), str) else ""
    if not name or len(name) > 80:
        return jsonify(success=False, error="Give this integration a name between 1 and 80 characters."), 400
    if count_active_api_keys(owner_id) >= 25:
        return jsonify(success=False, error="This account has reached the 25 active integration key limit. Revoke an unused key first."), 409
    raw_key = "cs_live_" + secrets.token_urlsafe(36)
    key_id = create_api_key(owner_id, name, raw_key)
    return jsonify(success=True, api_key={"id": key_id, "name": name, "key": raw_key,
                                          "prefix": raw_key[:18],
                                          "message": "Copy this key now. It will not be shown again."}), 201


@app.route("/api/integrations/keys/<int:key_id>", methods=["DELETE"])
@require_auth
def remove_integration_key(key_id):
    if not revoke_api_key(request.current_user["id"], key_id):
        return jsonify(success=False, error="API key not found or already revoked."), 404
    return jsonify(success=True, message="API key revoked.")


@app.route("/api/events/ingest", methods=["POST"])
@limiter.limit("300 per minute")
def ingest_events():
    principal = api_key_principal()
    if not principal:
        return jsonify(success=False, error="A valid Authorization: Bearer API key is required."), 401
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(success=False, error="Expected a JSON object."), 400
    events = data.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= 100:
        return jsonify(success=False, error="events must be an array containing 1 to 100 events."), 400
    normalized_events = []
    default_source = re.sub(r"[^A-Za-z0-9_.:-]+", "_", principal["name"]).strip("_")[:80] or "integration"
    for index, item in enumerate(events):
        normalized, error = normalize_event(item, default_source)
        if error:
            return jsonify(success=False, error=f"events[{index}]: {error}"), 400
        normalized_events.append(normalized)
    results = []
    for event in normalized_events:
        assessment = assess_risk(event["event_data"])
        saved = record_event(principal["owner_id"], event["source"], event["event_type"],
                             event["external_id"], event["event_data"], event["observed_at"], assessment)
        results.append({"event_id": saved["event_id"], "alert_id": saved["alert_id"],
                        "duplicate": saved["duplicate"], "risk_score": assessment["risk_score"],
                        "risk_level": assessment["risk_level"], "matched_rules": assessment["matched_rules"]})
    accepted = sum(not result["duplicate"] for result in results)
    return jsonify(success=True, accepted=accepted, duplicates=len(results) - accepted,
                   alerts_created=sum(bool(result["alert_id"]) and not result["duplicate"] for result in results),
                   results=results), 202


@app.route("/api/events", methods=["GET"])
@limiter.limit("240 per minute")
@require_auth
def events():
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        return jsonify(success=False, error="page and per_page must be integers."), 400
    level = request.args.get("risk_level")
    if level is not None and level.upper() not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return jsonify(success=False, error="Invalid risk_level."), 400
    source = request.args.get("source")
    if source is not None and (not source or len(source) > 80):
        return jsonify(success=False, error="Invalid source filter."), 400
    items, total = get_recent_events(request.current_user["id"], page=page, per_page=per_page,
                                     risk_level=level, source=source)
    return jsonify(success=True, events=items,
                   pagination={"page": page, "per_page": per_page, "total": total,
                               "pages": (total + per_page - 1) // per_page})


@app.route("/api/alerts", methods=["GET"])
@require_auth
def alerts():
    try:
        page = max(1, int(request.args.get("page", 1)))
        per_page = min(100, max(1, int(request.args.get("per_page", 50))))
    except ValueError:
        return jsonify(success=False, error="page and per_page must be integers."), 400
    status = request.args.get("status")
    level = request.args.get("risk_level")
    is_read = request.args.get("is_read")
    allowed_statuses = ("Open", "Acknowledged", "In Progress", "Resolved", "False Positive")
    if status not in (None, *allowed_statuses):
        return jsonify(success=False, error=f"status must be one of: {', '.join(allowed_statuses)}."), 400
    if level is not None and level.upper() not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        return jsonify(success=False, error="Invalid risk_level."), 400
    if is_read not in (None, "true", "false"):
        return jsonify(success=False, error="is_read must be true or false."), 400
    items, total = get_all_alerts(request.current_user["id"], status=status, risk_level=level, is_read=is_read, page=page, per_page=per_page)
    return jsonify(success=True, alerts=items, pagination={"page": page, "per_page": per_page, "total": total, "pages": (total + per_page - 1) // per_page})


@app.route("/api/stats", methods=["GET"])
@limiter.limit("240 per minute")
@require_auth
def stats():
    return jsonify(success=True, stats=get_alert_stats(request.current_user["id"]))


@app.route("/api/alerts/<int:alert_id>", methods=["PATCH"])
@require_auth
def update_alert_status(alert_id):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(success=False, error="Expected a JSON object."), 400
    status, is_read = data.get("status"), data.get("is_read")
    resolution_note = data.get("resolution_note", "")
    allowed_statuses = ("Open", "Acknowledged", "In Progress", "Resolved", "False Positive")
    if status is not None and status not in allowed_statuses:
        return jsonify(success=False, error=f"status must be one of: {', '.join(allowed_statuses)}."), 400
    if is_read is not None and not isinstance(is_read, bool):
        return jsonify(success=False, error="is_read must be true or false."), 400
    if not isinstance(resolution_note, str) or len(resolution_note) > 2000:
        return jsonify(success=False, error="resolution_note must be text up to 2,000 characters."), 400
    if status in ("Resolved", "False Positive") and not resolution_note.strip():
        return jsonify(success=False, error="A resolution note is required for this status."), 400
    if status is None and is_read is None:
        return jsonify(success=False, error="Provide status and/or is_read."), 400
    owner_id = request.current_user["id"]
    current_status = get_alert_status(owner_id, alert_id)
    if current_status is None:
        return jsonify(success=False, error="Alert not found."), 404
    transitions = {
        "Open": {"Acknowledged", "Resolved", "False Positive"},
        "Acknowledged": {"Open", "In Progress", "Resolved", "False Positive"},
        "In Progress": {"Acknowledged", "Resolved", "False Positive"},
        "Resolved": {"Open"},
        "False Positive": {"Open"},
    }
    if status is not None and status != current_status and status not in transitions[current_status]:
        return jsonify(success=False, error=f"Cannot move alert from {current_status} to {status}."), 409
    if not update_alert(owner_id, owner_id, alert_id, status=status, is_read=is_read,
                        resolution_note=resolution_note.strip()):
        return jsonify(success=False, error="Alert not found."), 404
    return jsonify(success=True, message="Alert updated.")


@app.route("/api/alerts/<int:alert_id>/activity", methods=["GET"])
@require_auth
def alert_activity(alert_id):
    items = get_alert_activity(request.current_user["id"], alert_id)
    if not items:
        if get_alert_status(request.current_user["id"], alert_id) is None:
            return jsonify(success=False, error="Alert not found."), 404
    return jsonify(success=True, activity=items)


@app.route("/api/alerts/<int:alert_id>", methods=["DELETE"])
@require_auth
def remove_alert(alert_id):
    if not delete_alert(request.current_user["id"], request.current_user["id"], alert_id):
        return jsonify(success=False, error="Alert not found."), 404
    return jsonify(success=True, message="Alert archived from the active queue.")


if __name__ == "__main__":
    app.run(host=os.getenv("HOST", "127.0.0.1"), port=int(os.getenv("PORT", "5000")), debug=environment != "production" and os.getenv("FLASK_DEBUG") == "1")
