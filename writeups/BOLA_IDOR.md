# BOLA / IDOR - Broken Object Level Authorization

| Field | Value |
|-------|-------|
| OWASP Category | API1:2023 - Broken Object Level Authorization |
| Endpoint | `GET /api/v1/users/{user_id}` |
| Severity | **Critical** (CVSS ~8.6) |

## Description

The endpoint returns a user record by its `user_id` path parameter. The
vulnerable version performs **no authentication and no ownership check**, so
any client can read any user's record (including the admin) just by changing
the id in the URL. This is a classic Insecure Direct Object Reference (IDOR).

## Vulnerable Code Snippet

```python
# vulnerable_version/main.py
@app.get("/api/v1/users/{user_id}")
def get_user(user_id: int):
    user = database.get_user_by_id(user_id)   # no auth, no ownership check
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
```

## Steps to Reproduce

Start the vulnerable server:

```bash
uvicorn vulnerable_version.main:app --port 8000
```

Read the admin record (id=1) without any token:

```bash
curl http://127.0.0.1:8000/api/v1/users/1
```

Python:

```python
import requests
print(requests.get("http://127.0.0.1:8000/api/v1/users/1").json())
```

Automated: `python exploits/exploit_bola.py`

## Impact

- Full account enumeration by iterating ids.
- Disclosure of other users' PII and secrets.
- No audit trail of unauthorized access.

## Fixed Code Snippet

```python
# fixed_version/main.py
@app.get("/api/v1/users/{user_id}", response_model=UserPublic)
def get_user(user_id: int, current_user: dict = Depends(get_current_user)):
    if current_user["id"] != user_id and current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    user = database.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user
```

## Remediation

- Require authentication on every object-level route.
- Enforce an ownership check: the caller must own the object, or hold a role
  that is explicitly allowed to access it.
- Prefer unpredictable identifiers (UUIDs) over sequential integers.
- Add logging and alerting on repeated authorization failures.
