"""Environment-driven settings, validated once at startup."""

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv

load_dotenv()

DEV_SECRET_FALLBACK = "local-development-only-change-this-secret"


def _flag(name, default):
    return os.getenv(name, default) == "1"


@dataclass(frozen=True)
class Settings:
    environment: str = field(default_factory=lambda: os.getenv(
        "APP_ENV", "production" if os.getenv("VERCEL") == "1" else "development").lower())
    secret_key: str = field(default_factory=lambda: os.getenv("SECRET_KEY", ""))
    cors_origins: tuple = field(default_factory=lambda: tuple(
        origin.strip() for origin in os.getenv(
            "CORS_ORIGINS", "http://127.0.0.1:5500,http://localhost:5500").split(",") if origin.strip()))
    ratelimit_storage_uri: str = field(default_factory=lambda: os.getenv("RATELIMIT_STORAGE_URI", "memory://"))
    host: str = field(default_factory=lambda: os.getenv("HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(os.getenv("PORT", "5050")))
    flask_debug: bool = field(default_factory=lambda: _flag("FLASK_DEBUG", "0"))

    @property
    def is_production(self):
        return self.environment == "production"

    @property
    def cookie_secure(self):
        return _flag("COOKIE_SECURE", "1" if self.is_production else "0")

    @property
    def allow_signup(self):
        # Read at request time, so tests and operators see the current environment value.
        return _flag("ALLOW_SIGNUP", "0" if self.is_production else "1")

    @property
    def allow_private_url_scan(self):
        # Live website checks refuse private/local addresses (SSRF protection) unless explicitly allowed.
        return _flag("URL_SCAN_ALLOW_PRIVATE", "0")

    @property
    def debug(self):
        return not self.is_production and self.flask_debug

    def validate(self):
        if self.is_production and len(self.secret_key) < 32:
            raise RuntimeError("Production SECRET_KEY must be set and contain at least 32 characters.")
        if self.is_production and (not self.cors_origins or "*" in self.cors_origins):
            raise RuntimeError("Set explicit CORS_ORIGINS in production; wildcard origins are not allowed.")
        return self
