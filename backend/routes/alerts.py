"""Alert queue, triage workflow, statistics and the activity feed."""

from flask import Blueprint, jsonify, request

from backend.constants import ALERT_STATUSES, ALERT_TRANSITIONS, TERMINAL_STATUSES
from backend.database import (
    delete_alert, get_alert_activity, get_alert_stats, get_alert_status, get_all_alerts, get_recent_activity, update_alert,
)
from backend.extensions import limiter
from backend.security import current_user_id, error, require_auth
from backend.validation import json_object, pagination_meta, parse_bounded_int, parse_pagination, parse_risk_level

bp = Blueprint("alerts", __name__, url_prefix="/api")

STATUS_CHOICES = ", ".join(ALERT_STATUSES)


@bp.get("/alerts")
@require_auth
def list_alerts():
    paging, problem = parse_pagination(request.args)
    if problem:
        return error(problem, 400)
    status = request.args.get("status")
    if status not in (None, *ALERT_STATUSES):
        return error(f"status must be one of: {STATUS_CHOICES}.", 400)
    level, problem = parse_risk_level(request.args.get("risk_level"))
    if problem:
        return error(problem, 400)
    is_read = request.args.get("is_read")
    if is_read not in (None, "true", "false"):
        return error("is_read must be true or false.", 400)
    page, per_page = paging
    items, total = get_all_alerts(current_user_id(), status=status, risk_level=level, is_read=is_read,
                                  page=page, per_page=per_page)
    return jsonify(success=True, alerts=items, pagination=pagination_meta(page, per_page, total))


@bp.get("/stats")
@limiter.limit("240 per minute")
@require_auth
def stats():
    return jsonify(success=True, stats=get_alert_stats(current_user_id()))


@bp.get("/activity")
@limiter.limit("240 per minute")
@require_auth
def recent_activity():
    limit, problem = parse_bounded_int(request.args, "limit", 10, 1, 50)
    if problem:
        return error(problem, 400)
    return jsonify(success=True, activity=get_recent_activity(current_user_id(), limit=limit))


@bp.patch("/alerts/<int:alert_id>")
@require_auth
def update(alert_id):
    data, problem = json_object(request)
    if problem:
        return error(problem, 400)
    status, is_read = data.get("status"), data.get("is_read")
    note = data.get("resolution_note", "")
    if status is not None and status not in ALERT_STATUSES:
        return error(f"status must be one of: {STATUS_CHOICES}.", 400)
    if is_read is not None and not isinstance(is_read, bool):
        return error("is_read must be true or false.", 400)
    if not isinstance(note, str) or len(note) > 2000:
        return error("resolution_note must be text up to 2,000 characters.", 400)
    if status in TERMINAL_STATUSES and not note.strip():
        return error("A resolution note is required for this status.", 400)
    if status is None and is_read is None:
        return error("Provide status and/or is_read.", 400)

    owner_id = current_user_id()
    current_status = get_alert_status(owner_id, alert_id)
    if current_status is None:
        return error("Alert not found.", 404)
    if status is not None and status != current_status and status not in ALERT_TRANSITIONS[current_status]:
        return error(f"Cannot move alert from {current_status} to {status}.", 409)
    if not update_alert(owner_id, owner_id, alert_id, status=status, is_read=is_read, resolution_note=note.strip()):
        return error("Alert not found.", 404)
    return jsonify(success=True, message="Alert updated.")


@bp.get("/alerts/<int:alert_id>/activity")
@require_auth
def alert_activity(alert_id):
    owner_id = current_user_id()
    items = get_alert_activity(owner_id, alert_id)
    if not items and get_alert_status(owner_id, alert_id) is None:
        return error("Alert not found.", 404)
    return jsonify(success=True, activity=items)


@bp.delete("/alerts/<int:alert_id>")
@require_auth
def archive(alert_id):
    owner_id = current_user_id()
    if not delete_alert(owner_id, owner_id, alert_id):
        return error("Alert not found.", 404)
    return jsonify(success=True, message="Alert archived from the active queue.")
