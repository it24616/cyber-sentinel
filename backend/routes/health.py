"""Readiness and liveness probes (no authentication)."""

from datetime import datetime, timezone

from flask import Blueprint, jsonify

from backend.database import database_ready

bp = Blueprint("health", __name__)

SERVICE = "Cyber Sentinel API"


@bp.get("/")
@bp.get("/api/health")
def readiness():
    ready = database_ready()
    return jsonify(success=ready, service=SERVICE, status="ready" if ready else "not_ready",
                   checks={"database": "ok" if ready else "unavailable"},
                   time=datetime.now(timezone.utc).isoformat()), 200 if ready else 503


@bp.get("/api/health/live")
def liveness():
    return jsonify(success=True, service=SERVICE, status="live", time=datetime.now(timezone.utc).isoformat())
