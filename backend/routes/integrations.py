"""Per-account ingestion API keys. The raw key is returned once, at creation."""

import secrets

from flask import Blueprint, jsonify, request

from backend.constants import API_KEY_PREFIX, MAX_ACTIVE_API_KEYS
from backend.database import count_active_api_keys, create_api_key, list_api_keys, revoke_api_key
from backend.security import current_user_id, error, require_auth

bp = Blueprint("integrations", __name__, url_prefix="/api/integrations/keys")


@bp.get("")
@require_auth
def list_keys():
    return jsonify(success=True, api_keys=list_api_keys(current_user_id()))


@bp.post("")
@require_auth
def create_key():
    data = request.get_json(silent=True)
    name = data.get("name", "").strip() if isinstance(data, dict) and isinstance(data.get("name"), str) else ""
    if not name or len(name) > 80:
        return error("Give this integration a name between 1 and 80 characters.", 400)
    owner_id = current_user_id()
    if count_active_api_keys(owner_id) >= MAX_ACTIVE_API_KEYS:
        return error("This account has reached the 25 active integration key limit. Revoke an unused key first.", 409)
    raw_key = API_KEY_PREFIX + secrets.token_urlsafe(36)
    key_id = create_api_key(owner_id, name, raw_key)
    return jsonify(success=True, api_key={"id": key_id, "name": name, "key": raw_key, "prefix": raw_key[:18],
                                          "message": "Copy this key now. It will not be shown again."}), 201


@bp.delete("/<int:key_id>")
@require_auth
def revoke_key(key_id):
    if not revoke_api_key(current_user_id(), key_id):
        return error("API key not found or already revoked.", 404)
    return jsonify(success=True, message="API key revoked.")
