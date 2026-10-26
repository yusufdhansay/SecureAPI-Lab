"""
Fake in-memory database for the FIXED API lab.

Data shape is identical to the vulnerable version so the two apps are
directly comparable. The difference is purely in how the API layer
(main.py) exposes and protects this data.
"""

import hashlib


def hash_password(password: str) -> str:
    """SHA-256 hash of a password.

    Kept identical to the vulnerable version for a fair comparison. A real
    production system should use bcrypt or argon2 with a per-user salt.
    """
    return hashlib.sha256(password.encode()).hexdigest()


USERS = [
    {
        "id": 1,
        "name": "Admin User",
        "email": "admin@apilab.local",
        "password_hash": hash_password("admin123"),
        "role": "admin",
        "secret_aadhaar": "1234-5678-9012",
        "internal_api_key": "ADMIN-KEY-9f8e7d6c5b4a",
    },
    {
        "id": 2,
        "name": "Alice Kumar",
        "email": "alice@apilab.local",
        "password_hash": hash_password("alice123"),
        "role": "user",
        "secret_aadhaar": "2345-6789-0123",
        "internal_api_key": "USER-KEY-1a2b3c4d5e6f",
    },
    {
        "id": 3,
        "name": "Bob Sharma",
        "email": "bob@apilab.local",
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
        "secret_aadhaar": f"0000-0000-{new_id:04d}",
        "internal_api_key": f"USER-KEY-auto-{new_id}",
    }
    USERS.append(user)
    return user
