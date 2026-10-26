# Missing Rate Limiting

| Field | Value |
|-------|-------|
| OWASP Category | API4:2023 - Unrestricted Resource Consumption |
| Endpoint | `POST /api/v1/login` |
| Severity | **Medium** (CVSS ~5.3) |

## Description

The vulnerable login endpoint applies no throttling. An attacker can send
unlimited requests, enabling brute-force and credential-stuffing attacks
against user passwords, and can also exhaust server resources.

## Vulnerable Code Snippet

```python
# vulnerable_version/main.py
@app.post("/api/v1/login")
def api_login(body: LoginRequest):
    user = database.get_user_by_email(body.email)
    if not user or user["password_hash"] != database.hash_password(body.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {"token": auth.create_token(user)}
```

## Steps to Reproduce

```bash
uvicorn vulnerable_version.main:app --port 8000
```

Fire many attempts; none are blocked:

```python
import requests
for i in range(100):
    requests.post("http://127.0.0.1:8000/api/v1/login",
                  json={"email": "alice@apilab.com", "password": f"guess{i}"})
# every request is processed, no 429
```

Automated: `python exploits/exploit_rate_limit.py`

## Impact

- Password brute force / credential stuffing at scale.
- Resource exhaustion (CPU on hashing, denial of service).

## Fixed Code Snippet

```python
# fixed_version/main.py
RATE_LIMIT = 5      # requests
RATE_WINDOW = 60    # seconds
_rate_store: dict[str, list[float]] = {}

def rate_limit(request: Request) -> None:
    ip = request.client.host
    now = time.time()
    hits = [t for t in _rate_store.get(ip, []) if now - t < RATE_WINDOW]
    if len(hits) >= RATE_LIMIT:
        raise HTTPException(status_code=429, detail="Too many requests")
    hits.append(now)
    _rate_store[ip] = hits

@app.post("/api/v1/login", dependencies=[Depends(rate_limit)])
def api_login(body: LoginRequest):
    ...
```

## Remediation

- Enforce per-IP / per-account rate limits on authentication endpoints.
- In production use a shared store (Redis) or an API gateway / WAF, not an
  in-memory dict, so limits hold across multiple workers.
- Add exponential backoff, account lockout, and CAPTCHA for repeated failures.
- Monitor and alert on spikes in failed logins.
