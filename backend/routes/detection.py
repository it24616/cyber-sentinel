"""Manual event assessment, the rule catalog and the live detection overview."""

from datetime import datetime, timezone

from flask import Blueprint, jsonify, request
from flask import make_response

from backend.constants import MANUAL_EVENT_TYPES, MAX_EVENT_CHARS
from backend.database import get_detection_overview, record_event
from backend.detection import ENGINE_NAME, ENGINE_VERSION, assess_risk, rule_catalog
from backend.extensions import limiter
from backend.security import current_user_id, error, require_auth
from backend.validation import json_object, normalize_event, parse_bounded_int
from backend.site_check import SiteCheckError, check_site
from backend.pdf_report import build_site_report_pdf

bp = Blueprint("detection", __name__, url_prefix="/api")

MANUAL_SOURCE = "manual-ui"


@bp.post("/site-check")
@limiter.limit("10 per minute")
@require_auth
def site_check():
    data, problem = json_object(request)
    if problem:
        return error(problem, 400)
    try:
        report = check_site(data.get("url"))
    except SiteCheckError as exc:
        return error(str(exc), 400)
    assessment = {
        "risk_score": report["risk_score"], "risk_level": report["risk_level"],
        "detected_threats": [c["title"] for c in report["checks"] if c["status"] in ("fail", "warn")],
        "matched_rules": [c["id"] for c in report["checks"] if c["status"] in ("fail", "warn")],
        "recommendation": next((c["fix"] for c in report["checks"] if c["fix"] and c["status"] in ("fail", "warn")), "No action needed. Re-check after site changes."),
    }
    event_data = report["url"]
    saved = record_event(current_user_id(), MANUAL_SOURCE, "manual_url", None, event_data,
                         datetime.now(timezone.utc).isoformat(timespec="seconds"), assessment)
    report.update(event_id=saved["event_id"], alert_id=saved["alert_id"])
    return jsonify(success=True, report=report)


@bp.post("/site-check/report")
@limiter.limit("20 per minute")
@require_auth
def site_check_report():
    data, problem = json_object(request)
    if problem:
        return error(problem, 400)
    report = data.get("report")
    if not isinstance(report, dict) or not isinstance(report.get("checks"), list):
        return error("A completed website scan report is required.", 400)
    response = make_response(build_site_report_pdf(report))
    response.headers["Content-Type"] = "application/pdf"
    response.headers["Content-Disposition"] = 'attachment; filename="website-security-report.pdf"'
    return response


@bp.post("/assess-risk")
@limiter.limit("20 per minute")
@require_auth
def assess():
    data, problem = json_object(request)
    if problem:
        return error(problem, 400)
    event_data = data.get("event_data")
    if not isinstance(event_data, str) or not event_data.strip():
        return error("Please provide non-empty event_data text.", 400)
    if len(event_data) > MAX_EVENT_CHARS:
        return error("event_data must be 10,000 characters or fewer.", 400)
    input_type = data.get("event_type", "general")
    if input_type not in MANUAL_EVENT_TYPES:
        return error("event_type must be general, url, request, or log.", 400)

    event, problem = normalize_event({"event_data": event_data, "source": MANUAL_SOURCE,
                                      "event_type": f"manual_{input_type}"}, MANUAL_SOURCE)
    if problem:
        return error(problem, 400)
    result = assess_risk(event["event_data"])
    saved = record_event(current_user_id(), event["source"], event["event_type"], None,
                         event["event_data"], event["observed_at"], result)
    return jsonify(success=True, message="Assessment completed.", result=result,
                   alert_id=saved["alert_id"], event_id=saved["event_id"])


@bp.get("/detection/rules")
@require_auth
def rules():
    return jsonify(success=True, engine={"name": ENGINE_NAME, "version": ENGINE_VERSION}, rules=rule_catalog())


@bp.get("/detection/overview")
@limiter.limit("240 per minute")
@require_auth
def overview():
    """Single polling endpoint for the Live Detection view."""
    since_id, problem = parse_bounded_int(request.args, "since_id", 0, 0, 2**63 - 1)
    limit, problem_limit = parse_bounded_int(request.args, "limit", 25, 1, 50)
    if problem or problem_limit:
        return error("since_id and limit must be integers.", 400)
    data = get_detection_overview(current_user_id(), since_id=since_id, limit=limit)
    data["engine"] = {"name": ENGINE_NAME, "version": ENGINE_VERSION, "rule_count": len(rule_catalog())}
    data["server_time"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    return jsonify(success=True, overview=data)
