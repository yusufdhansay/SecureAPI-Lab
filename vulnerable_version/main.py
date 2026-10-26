"""
Vulnerable FastAPI application - Phase 1 (boilerplate).

Only /register and /login are implemented in this phase. Vulnerable
endpoints are added in Phase 2.

Run with:
    uvicorn vulnerable_version.main:app --reload --port 8000
"""

from fastapi import FastAPI, HTTPException
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
