"""
JWT helper functions for the VULNERABLE version of the API.

Security problems baked in on purpose:
  - Hard-coded weak secret ("secret123").
  - Tokens are created without an expiry claim.
  - The decode helper does not verify expiry and allows the "none" algorithm.

These weaknesses are exploited in the Broken Authentication demos.
"""

import jwt  # PyJWT

# Intentionally weak, hard-coded secret. Easy to brute force or guess.
SECRET_KEY = "secret123"
ALGORITHM = "HS256"


def create_token(user: dict) -> str:
    """Create a JWT for a user.

    Note: no "exp" claim is added, so these tokens never expire.
    """
    payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "role": user["role"],
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode a JWT in the most permissive way possible.

    Vulnerabilities:
      - Accepts the "none" algorithm (unsigned tokens).
      - Does not verify the "exp" claim.
      - Disables signature verification requirements.
    """
    # "none" is accepted here, which lets an attacker forge unsigned tokens.
    return jwt.decode(
        token,
        SECRET_KEY,
        algorithms=["HS256", "none"],
        options={
            "verify_signature": False,  # signature not enforced
            "verify_exp": False,        # expiry not checked
        },
    )
