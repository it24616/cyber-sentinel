"""Batch event ingestion (API key) and the authenticated event history."""

import re

from flask import Blueprint, jsonify, request

from backend.constants import MAX_BATCH_EVENTS
from backend.database import get_recent_events, record_event
from backend.detection import assess_risk
from backend.extensions import limiter
from backend.security import api_key_principal, current_user_id, error, require_auth
from backend.validation import json_object, normalize_event, pagination_meta, parse_pagination, parse_risk_level

bp = Blueprint("events", __name__, url_prefix="/api/events")


@bp.post("/ingest")
@limiter.limit("300 per minute")
def ingest():
    principal = api_key_principal()
    if not principal:
        return error("A valid Authorization: Bearer API key is required.", 401)
    data, problem = json_object(request)
    if problem:
        return error(problem, 400)
    events = data.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_BATCH_EVENTS:
        return error("events must be an array containing 1 to 100 events.", 400)

    # Validate the whole batch first so a bad item never leaves a partial import.
    default_source = re.sub(r"[^A-Za-z0-9_.:-]+", "_", principal["name"]).strip("_")[:80] or "integration"
    normalized = []
    for index, item in enumerate(events):
        event, problem = normalize_event(item, default_source)
        if problem:
            return error(f"events[{index}]: {problem}", 400)
        normalized.append(event)

    results = []
    for event in normalized:
        assessment = assess_risk(event["event_data"])
        saved = record_event(principal["owner_id"], event["source"], event["event_type"],
                             event["external_id"], event["event_data"], event["observed_at"], assessment)
        results.append({"event_id": saved["event_id"], "alert_id": saved["alert_id"],
                        "duplicate": saved["duplicate"], "risk_score": assessment["risk_score"],
                        "risk_level": assessment["risk_level"], "matched_rules": assessment["matched_rules"]})
    accepted = sum(not result["duplicate"] for result in results)
    return jsonify(success=True, accepted=accepted, duplicates=len(results) - accepted,
                   alerts_created=sum(bool(r["alert_id"]) and not r["duplicate"] for r in results),
                   results=results), 202


@bp.get("")
@limiter.limit("240 per minute")
@require_auth
def history():
    paging, problem = parse_pagination(request.args)
    if problem:
        return error(problem, 400)
    level, problem = parse_risk_level(request.args.get("risk_level"))
    if problem:
        return error(problem, 400)
    source = request.args.get("source")
    if source is not None and (not source or len(source) > 80):
        return error("Invalid source filter.", 400)
    page, per_page = paging
    items, total = get_recent_events(current_user_id(), page=page, per_page=per_page,
                                     risk_level=level, source=source)
    return jsonify(success=True, events=items, pagination=pagination_meta(page, per_page, total))
