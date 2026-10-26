"""
Secure FastAPI application (FIXED version).

Same endpoints as vulnerable_version, but with proper authorization,
output filtering, strict token validation and basic rate limiting.

Run with:
    uvicorn fixed_version.main:app --reload --port 8001
"""

import time

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, EmailStr

from fixed_version import auth, database

app = FastAPI(
    title="Secure-by-Design API Lab - FIXED",
    description="Hardened version of the API with OWASP controls applied.",
    version="1.0.0",
)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class UserPublic(BaseModel):
    """FIX (Excessive Data Exposure): response model exposes safe fields only.

    Sensitive fields (password_hash, secret_aadhaar, internal_api_key) can
    never leak because FastAPI serialises the response against this model.
    """

    id: int
    name: str
    email: EmailStr


# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------
def get_current_user(authorization: str = Header(default=None)) -> dict:
    """Validate the bearer token strictly and return the user."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization.split(" ", 1)[1]
    try:
        # FIX (Broken Auth): strict signature + exp + algorithm checks.
        payload = auth.decode_token(token)
    except Exception:  # noqa: BLE001 - do not leak crypto error details
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = database.get_user_by_id(int(payload["sub"]))
    if not user:
        raise HTTPException(status_code=401, detail="Unknown user")
    return user


def require_admin_role(current_user: dict = Depends(get_current_user)) -> dict:
    """FIX (BFLA): dependency that enforces the admin role."""
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return current_user


# ---------------------------------------------------------------------------
# Simple in-memory rate limiter (FIX for Unrestricted Resource Consumption)
# ---------------------------------------------------------------------------
RATE_LIMIT = 5          # max requests
RATE_WINDOW = 60        # per this many seconds
_rate_store: dict[str, list[float]] = {}


def rate_limit(request: Request) -> None:
    """Allow at most RATE_LIMIT requests per client IP per RATE_WINDOW."""
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()

    hits = _rate_store.get(client_ip, [])
    # Keep only timestamps inside the current window.
    hits = [ts for ts in hits if now - ts < RATE_WINDOW]

    if len(hits) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many requests")

    hits.append(now)
    _rate_store[client_ip] = hits


# ---------------------------------------------------------------------------
# Basic endpoints
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    return {"status": "ok", "service": "fixed-api-lab"}


@app.post("/register")
def register(body: RegisterRequest):
    if database.get_user_by_email(body.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    user = database.add_user(body.name, body.email, body.password)
    return {"message": "registered", "token": auth.create_token(user)}


# ---------------------------------------------------------------------------
# 1. BOLA FIX  (API1:2023)
#    A user may read only their own record, unless they are an admin.
# ---------------------------------------------------------------------------
@app.get("/api/v1/users/{user_id}", response_model=UserPublic)
def get_user(user_id: int, current_user: dict = Depends(get_current_user)):
    if current_user["id"] != user_id and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")

    user = database.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user  # filtered through UserPublic


# ---------------------------------------------------------------------------
# 2. BFLA FIX  (API5:2023)
#    Delete is gated behind the require_admin_role dependency.
# ---------------------------------------------------------------------------
@app.delete("/api/v1/admin/users/{user_id}")
def delete_user(user_id: int, admin: dict = Depends(require_admin_role)):
    target = database.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    database.USERS.remove(target)
    return {"message": f"user {user_id} deleted", "deleted_by": admin["email"]}


# ---------------------------------------------------------------------------
# 3. Excessive Data Exposure FIX  (API3:2023)
#    Response model returns only id, name, email.
# ---------------------------------------------------------------------------
@app.get("/api/v1/users/me", response_model=UserPublic)
def read_me(current_user: dict = Depends(get_current_user)):
    return current_user


# ---------------------------------------------------------------------------
# 4. Rate Limiting FIX  (API4:2023)
#    Login is throttled to 5 requests / minute / IP.
# ---------------------------------------------------------------------------
@app.post("/api/v1/login", dependencies=[Depends(rate_limit)])
def api_login(body: LoginRequest):
    user = database.get_user_by_email(body.email)
    if not user or user["password_hash"] != database.hash_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"message": "login successful", "token": auth.create_token(user)}


# ---------------------------------------------------------------------------
# 5. Broken Authentication FIX  (API2:2023)
#    Token is validated strictly via get_current_user (no alg:none, exp
#    enforced, signature verified).
# ---------------------------------------------------------------------------
@app.get("/api/v1/secure-data")
def secure_data(current_user: dict = Depends(get_current_user)):
    return {
        "message": "top secret data",
        "accessed_by": current_user["email"],
        "role": current_user["role"],
    }
