"""
Vulnerable FastAPI application.

This app intentionally contains OWASP API Top 10 vulnerabilities for
educational use. Each vulnerable endpoint is clearly marked with the
[VULN] tag and a description of the weakness.

Run with:
    uvicorn vulnerable_version.main:app --reload --port 8000
"""

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, EmailStr

from vulnerable_version import auth, database

app = FastAPI(
    title="Secure-by-Design API Lab - VULNERABLE",
    description="Intentionally vulnerable API for learning the OWASP API Top 10.",
    version="0.1.0",
)


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


# ---------------------------------------------------------------------------
# Helper: "authenticate" the caller from the Authorization header.
#
# [VULN] This helper decodes the token with all verification disabled
# (see auth.decode_token). It will happily accept forged / unsigned / expired
# tokens. It is used by the endpoints below to show Broken Authentication.
# ---------------------------------------------------------------------------
def get_current_user(authorization: str = Header(default=None)):
    """Return the user referenced by the bearer token, without real checks."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    token = authorization.split(" ", 1)[1]
    try:
        payload = auth.decode_token(token)
    except Exception as exc:  # noqa: BLE001 - broad on purpose for the lab
        raise HTTPException(status_code=401, detail=f"Bad token: {exc}")

    user = database.get_user_by_id(int(payload["sub"]))
    if not user:
        raise HTTPException(status_code=401, detail="Unknown user")
    return user


# ---------------------------------------------------------------------------
# Basic endpoints
# ---------------------------------------------------------------------------
@app.get("/")
def root():
    """Health check / landing route."""
    return {"status": "ok", "service": "vulnerable-api-lab"}


@app.post("/register")
def register(body: RegisterRequest):
    """Register a new user and return a signed JWT."""
    if database.get_user_by_email(body.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    user = database.add_user(body.name, body.email, body.password)
    token = auth.create_token(user)
    return {"message": "registered", "token": token}


@app.post("/login")
def login(body: LoginRequest):
    """Authenticate a user by email + password and return a JWT."""
    user = database.get_user_by_email(body.email)
    if not user or user["password_hash"] != database.hash_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = auth.create_token(user)
    return {"message": "login successful", "token": token}


# ===========================================================================
# VULNERABLE ENDPOINTS (OWASP API Top 10)
# ===========================================================================

# ---------------------------------------------------------------------------
# NOTE on route order: /api/v1/users/me is declared BEFORE
# /api/v1/users/{user_id} so that the literal "me" is not parsed as an int.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 3. Excessive Data Exposure  (OWASP API3:2023)
#
# [VULN] /users/me returns the raw user object, including password_hash,
# secret_aadhaar and internal_api_key. The API relies on the client to
# filter fields, which it never should.
# ---------------------------------------------------------------------------
@app.get("/api/v1/users/me")
def read_me(current_user: dict = Depends(get_current_user)):
    """Return the full, unfiltered user object (Excessive Data Exposure)."""
    return current_user


# ---------------------------------------------------------------------------
# 1. BOLA / IDOR  (OWASP API1:2023 - Broken Object Level Authorization)
#
# [VULN] Any caller can fetch ANY user's full record just by changing the
# user_id in the URL. There is no authentication and no ownership check.
# ---------------------------------------------------------------------------
@app.get("/api/v1/users/{user_id}")
def get_user(user_id: int):
    """Return a user by id with NO authorization check (BOLA/IDOR)."""
    user = database.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    # Returns the entire record, including sensitive fields.
    return user


# ---------------------------------------------------------------------------
# 2. BFLA  (OWASP API5:2023 - Broken Function Level Authorization)
#
# [VULN] A destructive admin-only action (delete user) is exposed with no
# role check. Any authenticated user, even a normal one, can delete anyone.
# ---------------------------------------------------------------------------
@app.delete("/api/v1/admin/users/{user_id}")
def delete_user(user_id: int, current_user: dict = Depends(get_current_user)):
    """Delete any user. NO admin role check is performed (BFLA)."""
    target = database.get_user_by_id(user_id)
    if not target:
        raise HTTPException(status_code=404, detail="User not found")

    database.USERS.remove(target)
    return {
        "message": f"user {user_id} deleted",
        "deleted_by": current_user["email"],
    }


# ---------------------------------------------------------------------------
# 4. No Rate Limiting  (OWASP API4:2023 - Unrestricted Resource Consumption)
#
# [VULN] This login accepts unlimited attempts with no throttling, enabling
# brute-force / credential-stuffing attacks. It mirrors the top-level /login
# but is namespaced under the API path for the exploit scripts.
# ---------------------------------------------------------------------------
@app.post("/api/v1/login")
def api_login(body: LoginRequest):
    """Login with NO rate limiting (brute-force friendly)."""
    user = database.get_user_by_email(body.email)
    if not user or user["password_hash"] != database.hash_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = auth.create_token(user)
    return {"message": "login successful", "token": token}


# ---------------------------------------------------------------------------
# 5. Broken Authentication  (OWASP API2:2023)
#
# [VULN] This endpoint trusts auth.decode_token, which accepts alg:none,
# does not verify the signature, and ignores token expiry. A forged token
# with role=admin will be accepted.
# ---------------------------------------------------------------------------
@app.get("/api/v1/secure-data")
def secure_data(current_user: dict = Depends(get_current_user)):
    """Return 'protected' data using broken token validation."""
    return {
        "message": "top secret data",
        "accessed_by": current_user["email"],
        "role": current_user["role"],
        "flag": "FLAG{broken_auth_alg_none}",
    }
