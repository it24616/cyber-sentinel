"""Request parsing helpers. Each returns (value, error_message)."""

import json
import re
from datetime import datetime, timezone

from backend.constants import MAX_EVENT_CHARS, RISK_LEVELS

SOURCE_PATTERN = re.compile(r"[A-Za-z0-9_.:-]{1,80}")


def parse_pagination(args, default_per_page=50, max_per_page=100):
    try:
        page = max(1, int(args.get("page", 1)))
        per_page = min(max_per_page, max(1, int(args.get("per_page", default_per_page))))
    except ValueError:
        return None, "page and per_page must be integers."
    return (page, per_page), None


def pagination_meta(page, per_page, total):
    return {"page": page, "per_page": per_page, "total": total, "pages": (total + per_page - 1) // per_page}


def parse_bounded_int(args, name, default, minimum, maximum):
    try:
        return min(maximum, max(minimum, int(args.get(name, default)))), None
    except ValueError:
        return None, f"{name} must be an integer."


def parse_risk_level(value):
    if value is None:
        return None, None
    if value.upper() not in RISK_LEVELS:
        return None, "Invalid risk_level."
    return value.upper(), None


def json_object(request):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, "Expected a JSON object."
    return data, None


def normalize_event(item, default_source):
    """Validate one ingested or manual event and return it in storage form."""
    if not isinstance(item, dict):
        return None, "Each event must be a JSON object."
    raw_data = item.get("event_data", item.get("message"))
    if isinstance(raw_data, str):
        event_data = raw_data.strip()
    elif isinstance(raw_data, (dict, list)):
        event_data = json.dumps(raw_data, ensure_ascii=False, separators=(",", ":"))
    else:
        return None, "event_data must be text, an object, or an array."
    if not event_data or len(event_data) > MAX_EVENT_CHARS:
        return None, "event_data must contain 1 to 10,000 characters."

    source = item.get("source", default_source)
    event_type = item.get("event_type", "security_event")
    external_id = item.get("external_id")
    if not isinstance(source, str) or not SOURCE_PATTERN.fullmatch(source):
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
        except ValueError:
            return None, "observed_at must be an ISO 8601 timestamp."
        if parsed_time.tzinfo is None:
            parsed_time = parsed_time.replace(tzinfo=timezone.utc)
    else:
        return None, "observed_at must be an ISO 8601 timestamp."

    return {
        "source": source,
        "event_type": event_type.strip(),
        "external_id": external_id.strip() if external_id else None,
        "event_data": event_data,
        "observed_at": parsed_time.astimezone(timezone.utc).isoformat(timespec="seconds"),
    }, None
