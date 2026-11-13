"""Flask extensions created once and bound to the app in create_app()."""

import secrets

from argon2 import PasswordHasher
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=["120 per hour"])
password_hasher = PasswordHasher()
# Verified against when the email is unknown, so login timing does not reveal which accounts exist.
dummy_password_hash = password_hasher.hash(secrets.token_urlsafe(32))
