"""Breached-password check that never sees a plaintext password.

The calling app sends the SHA-1 of the password (40 hex chars). We look it up in:
  1. a small local list of notorious passwords (works offline), and
  2. optionally the Have I Been Pwned "range" API using k-anonymity (only the first 5 hex chars leave
     this server) when ENABLE_HIBP=true.
"""
import hashlib
import urllib.request
from functools import lru_cache

from .config import settings

_COMMON = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", "1234", "111111", "1234567", "dragon",
    "123123", "baseball", "abc123", "football", "monkey", "letmein", "696969", "shadow", "master", "666666",
    "qwertyuiop", "123321", "mustang", "1234567890", "michael", "654321", "superman", "1qaz2wsx", "7777777",
    "121212", "000000", "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer", "zxcvbnm", "asdfgh",
    "hunter", "buster", "soccer", "harley", "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000",
    "charlie", "robert", "thomas", "hockey", "ranger", "daniel", "starwars", "klaster", "112233", "george",
    "computer", "michelle", "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", "131313", "freedom",
    "777777", "pass", "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda",
    "summer", "love", "ashley", "nicole", "chelsea", "biteme", "matthew", "access", "yankees", "987654321",
    "dallas", "austin", "thunder", "taylor", "matrix", "welcome", "admin", "admin123", "password1", "qwerty123",
    "Summer2026!", "Password1!", "Welcome1", "P@ssw0rd", "Passw0rd", "letmein123", "changeme",
]
_LOCAL = {hashlib.sha1(p.encode()).hexdigest().upper() for p in _COMMON}


def sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest().upper()


@lru_cache(maxsize=4096)
def _hibp_range(prefix: str) -> frozenset:
    req = urllib.request.Request(f"https://api.pwnedpasswords.com/range/{prefix}", headers={"Add-Padding": "true", "User-Agent": "cybermind-ai"})
    with urllib.request.urlopen(req, timeout=2.5) as r:
        body = r.read().decode()
    return frozenset(line.split(":")[0].strip().upper() for line in body.splitlines() if line and not line.endswith(":0"))


def is_breached(sha1: str | None) -> bool:
    if not sha1 or len(sha1) != 40:
        return False
    sha1 = sha1.upper()
    if sha1 in _LOCAL:
        return True
    if settings.enable_hibp:
        try:
            return sha1[5:] in _hibp_range(sha1[:5])
        except Exception:      # offline or rate limited: fail open, never block logins because the lookup failed
            return False
    return False
