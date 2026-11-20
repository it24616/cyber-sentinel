"""Application factory: builds a configured Flask app."""

from datetime import timedelta
from pathlib import Path

from flask import Flask
from flask import send_from_directory
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix

from backend.config import DEV_SECRET_FALLBACK, Settings
from backend.database import initialize_database
from backend.extensions import limiter
from backend.routes import register_blueprints
from backend.security import register_security

MAX_REQUEST_BYTES = 64 * 1024


def create_app(settings=None):
    settings = (settings or Settings()).validate()
    app = Flask(__name__, static_folder=None)  # API only; the frontend is served separately
    app.secret_key = settings.secret_key or DEV_SECRET_FALLBACK
    app.config.update(
        SETTINGS=settings,
        MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SECURE=settings.cookie_secure,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
        RATELIMIT_STORAGE_URI=settings.ratelimit_storage_uri,
    )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    CORS(app, resources={r"/api/*": {"origins": list(settings.cors_origins), "supports_credentials": True}})

    initialize_database()
    limiter.init_app(app)
    register_security(app)
    register_blueprints(app)

    # Vercel deploys this Flask app as the API function. Serve the static UI
    # from the same origin so browser auth requests reach the Flask routes too.
    frontend_dir = Path(__file__).resolve().parent.parent / "frontend"

    # Static files are exempt from the API rate limits: one page load fetches ~10 files.
    @app.get("/")
    @limiter.exempt
    def frontend_home():
        return send_from_directory(frontend_dir, "index.html")

    @app.get("/favicon.ico")
    @limiter.exempt
    def favicon():
        return send_from_directory(frontend_dir / "assets" / "img", "favicon.svg", mimetype="image/svg+xml")

    @app.get("/<path:filename>")
    @limiter.exempt
    def frontend_file(filename):
        return send_from_directory(frontend_dir, filename)

    return app
