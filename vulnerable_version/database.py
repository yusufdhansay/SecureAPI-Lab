"""
Fake in-memory database for the vulnerable API lab.

This module simulates a real datastore using plain Python lists and dicts.
It intentionally stores sensitive fields (password hashes, Aadhaar numbers,
internal API keys) so the lab can demonstrate OWASP API security issues such
as Excessive Data Exposure.

WARNING: For educational use only. Never store data like this in production.
"""

import hashlib


def hash_password(password: str) -> str:
    """Create a simple SHA-256 hash of a password.

    Note: In a real system use a slow, salted hash such as bcrypt or argon2.
    SHA-256 is used here only to keep the lab dependency-free.
    """
    return hashlib.sha256(password.encode()).hexdigest()


# In-memory "users" table.
# Each record holds both public and highly sensitive fields on purpose.
USERS = [
    {
        "id": 1,
        "name": "Admin User",
        "email": "admin@apilab.com",
        "password_hash": hash_password("admin123"),
        "role": "admin",
        "secret_aadhaar": "1234-5678-9012",
        "internal_api_key": "ADMIN-KEY-9f8e7d6c5b4a",
    },
    {
        "id": 2,
        "name": "Alice Kumar",
        "email": "alice@apilab.com",
        "password_hash": hash_password("alice123"),
        "role": "user",
        "secret_aadhaar": "2345-6789-0123",
        "internal_api_key": "USER-KEY-1a2b3c4d5e6f",
    },
    {
        "id": 3,
        "name": "Bob Sharma",
        "email": "bob@apilab.com",
        "password_hash": hash_password("bob123"),
        "role": "user",
        "secret_aadhaar": "3456-7890-1234",
        "internal_api_key": "USER-KEY-6f5e4d3c2b1a",
    },
]


def get_user_by_id(user_id: int):
    """Return the user record matching the given id, or None."""
    for user in USERS:
        if user["id"] == user_id:
            return user
    return None


def get_user_by_email(email: str):
    """Return the user record matching the given email, or None."""
    for user in USERS:
        if user["email"] == email:
            return user
    return None


def add_user(name: str, email: str, password: str, role: str = "user"):
    """Create a new user record and append it to the in-memory table."""
    new_id = max((u["id"] for u in USERS), default=0) + 1
    user = {
        "id": new_id,
        "name": name,
        "email": email,
        "password_hash": hash_password(password),
        "role": role,
        # Demo-only generated sensitive fields.
        "secret_aadhaar": f"0000-0000-{new_id:04d}",
        "internal_api_key": f"USER-KEY-auto-{new_id}",
    }
    USERS.append(user)
    return user
