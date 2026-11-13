"""Cyber Sentinel API entry point.

Development:  python backend/app.py   (or: python -m backend.app)
Production:   gunicorn --config gunicorn.conf.py backend.app:app
"""

import sys
from pathlib import Path

if __package__ in (None, ""):
    # Run as a script: make the project root importable so `backend.*` imports work.
    sys.path[0] = str(Path(__file__).resolve().parent.parent)

from backend.extensions import limiter  # noqa: E402  (re-exported for tests)
from backend.factory import create_app  # noqa: E402

app = create_app()

__all__ = ["app", "create_app", "limiter"]

if __name__ == "__main__":
    settings = app.config["SETTINGS"]
    app.run(host=settings.host, port=settings.port, debug=settings.debug)
