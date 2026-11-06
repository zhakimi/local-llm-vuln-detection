import hashlib
import hmac
import os
import secrets


def hash_password(password: str) -> bytes:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return salt + digest


def verify_password(password: str, stored: bytes) -> bool:
    salt, digest = stored[:16], stored[16:]
    candidate = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return hmac.compare_digest(candidate, digest)


def make_reset_token() -> str:
    return secrets.token_urlsafe(32)
