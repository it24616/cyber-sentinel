"""Shared test setup. Import this before anything from `backend`.

Points the app at a throwaway SQLite file (the database path is read at import
time) and offers helpers for authenticated test clients.
"""

import atexit
import os
import tempfile
import uuid
from pathlib import Path

_database_dir = tempfile.TemporaryDirectory(prefix="cyber-sentinel-tests-")
atexit.register(_database_dir.cleanup)
os.environ["CYBER_SENTINEL_DB"] = str(Path(_database_dir.name) / "security.db")
# Run the same suite against PostgreSQL with TEST_DATABASE_URL=postgresql://… (use an empty database).
if os.getenv("TEST_DATABASE_URL"):
    os.environ["DATABASE_URL"] = os.environ["TEST_DATABASE_URL"]
else:
    os.environ.pop("DATABASE_URL", None)
os.environ.setdefault("APP_ENV", "development")

from backend import app as app_module  # noqa: E402
from backend import database  # noqa: E402

app = app_module.app
limiter = app_module.limiter
app.config.update(TESTING=True)

CSRF = "test-csrf-token"


def new_user(name="Test User"):
    """Create a user directly in the database and return its id."""
    return database.create_user(name, f"{uuid.uuid4().hex}@example.test", "", "unused-hash")


def client_for(user_id):
    """Test client with a signed-in session for user_id. Send CSRF in X-CSRF-Token on writes."""
    client = app.test_client()
    with client.session_transaction() as session:
        session["user_id"] = user_id
        session["csrf_token"] = CSRF
    return client


def disable_rate_limits(test_case):
    limiter.enabled = False
    test_case.addCleanup(setattr, limiter, "enabled", True)
