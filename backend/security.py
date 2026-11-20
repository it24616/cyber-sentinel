"""Authentication, CSRF, API-key principals, response headers and error handlers."""

import secrets
from functools import wraps

from flask import jsonify, request, session

from backend.constants import API_KEY_PREFIX
from backend.database import get_api_key, get_user_by_id, mark_api_key_used

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def error(message, status):
    return jsonify(success=False, error=message), status


def require_auth(handler):
    """Session login required; state-changing requests must also carry the CSRF token."""
    @wraps(handler)
    def wrapped(*args, **kwargs):
        user = get_user_by_id(session.get("user_id")) if session.get("user_id") else None
        if not user or not user["is_active"]:
            session.clear()
            return error("Authentication required.", 401)
        if request.method not in SAFE_METHODS:
            sent_token = request.headers.get("X-CSRF-Token", "")
            expected_token = session.get("csrf_token", "")
            if not expected_token or not secrets.compare_digest(sent_token, expected_token):
                return error("Invalid or missing CSRF token.", 403)
        request.current_user = user
        return handler(*args, **kwargs)
    return wrapped


def current_user_id():
    return request.current_user["id"]


def api_key_principal():
    """Return the API key row for a valid `Authorization: Bearer cs_live_…` header, else None."""
    scheme, _, token = request.headers.get("Authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token.startswith(API_KEY_PREFIX) or len(token) > 160:
        return None
    key = get_api_key(token)
    if key:
        mark_api_key_used(key["id"])
    return key


def register_security(app):
    @app.after_request
    def security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        # API responses must never be framed. Frontend pages (served by Flask on Vercel) are
        # framed by the app shell (app.html), so allow same-origin framing for them.
        response.headers["X-Frame-Options"] = "DENY" if request.path.startswith("/api/") else "SAMEORIGIN"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(404)
    def not_found(_error):
        return error("Not found.", 404)

    @app.errorhandler(405)
    def method_not_allowed(_error):
        return error("Method not allowed.", 405)

    @app.errorhandler(413)
    def request_too_large(_error):
        return error("Request body is too large.", 413)

    @app.errorhandler(429)
    def rate_limit_exceeded(_error):
        return error("Rate limit exceeded. Try again shortly.", 429)
