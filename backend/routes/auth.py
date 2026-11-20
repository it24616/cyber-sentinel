"""Account registration, sign-in, session info and sign-out."""

import re
import secrets

from argon2.exceptions import InvalidHashError, VerifyMismatchError
from flask import Blueprint, current_app, jsonify, request, session

from backend.database import create_user, get_user_by_email, update_password_hash
from backend.extensions import dummy_password_hash, limiter, password_hasher
from backend.security import error, require_auth
from backend.validation import json_object

bp = Blueprint("auth", __name__, url_prefix="/api/auth")

EMAIL_PATTERN = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+")


def _text(data, name):
    value = data.get(name, "")
    return value.strip() if isinstance(value, str) else ""


@bp.post("/register")
@limiter.limit("5 per hour")
def register():
    if not current_app.config["SETTINGS"].allow_signup:
        return error("Account registration is disabled.", 403)
    data, problem = json_object(request)
    if problem:
        return error(problem, 400)
    full_name, email, phone = _text(data, "full_name"), _text(data, "email").lower(), _text(data, "phone")
    password = data.get("password")
    if not full_name or len(full_name) > 120:
        return error("Enter a name between 1 and 120 characters.", 400)
    if not EMAIL_PATTERN.fullmatch(email) or len(email) > 254:
        return error("Enter a valid email address.", 400)
    if len(phone) > 40:
        return error("Phone number is too long.", 400)
    if not isinstance(password, str) or not 12 <= len(password) <= 128:
        return error("Password must be 12 to 128 characters.", 400)
    if not create_user(full_name, email, phone, password_hasher.hash(password)):
        return error("An account with that email already exists.", 409)
    return jsonify(success=True, message="Account created. Sign in to continue."), 201


@bp.post("/login")
@limiter.limit("10 per minute")
def login():
    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    email = _text(data, "email")
    password = data.get("password")
    user = get_user_by_email(email) if email else None
    candidate = password if isinstance(password, str) and len(password) <= 128 else ""
    try:
        # Always run one Argon2 verification so response time does not reveal unknown emails.
        verified = password_hasher.verify(user["password_hash"] if user else dummy_password_hash, candidate)
        valid = bool(user and user["is_active"] and candidate and verified)
    except (InvalidHashError, VerifyMismatchError, ValueError):
        valid = False
    if not valid:
        return error("Email or password is incorrect.", 401)

    session.clear()
    session.permanent = True
    session["user_id"] = user["id"]
    session["csrf_token"] = secrets.token_urlsafe(32)
    if password_hasher.check_needs_rehash(user["password_hash"]):
        update_password_hash(user["id"], password_hasher.hash(candidate))
    return jsonify(success=True, csrf_token=session["csrf_token"], user={
        "id": user["id"], "full_name": user["full_name"], "email": user["email"], "role": user["role"]})


@bp.get("/me")
@require_auth
def me():
    return jsonify(success=True, user=request.current_user, csrf_token=session.get("csrf_token"))


@bp.post("/logout")
@require_auth
def logout():
    session.clear()
    return jsonify(success=True, message="Signed out.")
