"""
Secure JWT helpers for the FIXED version of the API.

Security controls applied:
  - Secret is loaded from the environment (API_LAB_SECRET), with a strong
    fallback that is clearly not "secret123".
  - Tokens always include issued-at (iat) and expiry (exp) claims.
  - decode_token enforces the signature and the HS256 algorithm ONLY.
    The "none" algorithm is rejected.
  - Expiry is verified; expired tokens are rejected.
"""

import os
from datetime import datetime, timedelta, timezone

import jwt  # PyJWT

# Load the signing secret from the environment. The fallback is long and
# random-looking so a misconfigured deployment still is not trivially weak.
SECRET_KEY = os.environ.get(
    "API_LAB_SECRET",
    "k3y-9Fb2!x7Qe#4Lm$8Zp^1Rt&6Wv*0Yc-strong-fallback",
)
ALGORITHM = "HS256"
TOKEN_TTL_MINUTES = 15


def create_token(user: dict) -> str:
    """Create a signed JWT that expires after TOKEN_TTL_MINUTES."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "role": user["role"],
        "iat": now,
        "exp": now + timedelta(minutes=TOKEN_TTL_MINUTES),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Strictly decode and validate a JWT.

    Raises jwt.InvalidTokenError (or a subclass) on any problem:
      - bad / missing signature
      - unexpected algorithm (including "none")
      - expired token
    """
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=[ALGORITHM],  # only HS256; "none" is refused
        options={
            "verify_signature": True,
            "verify_exp": True,
            "require": ["exp", "iat", "sub"],
        },
    )
