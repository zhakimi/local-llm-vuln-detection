import hashlib
import random
import string


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def make_reset_token(length: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))
