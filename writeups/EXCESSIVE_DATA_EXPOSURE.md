# Excessive Data Exposure

| Field | Value |
|-------|-------|
| OWASP Category | API3:2023 - Broken Object Property Level Authorization (Excessive Data Exposure) |
| Endpoint | `GET /api/v1/users/me` |
| Severity | **High** (CVSS ~7.5) |

## Description

The vulnerable endpoint returns the raw user object straight from the data
layer. That object contains sensitive properties (`password_hash`,
`secret_aadhaar`, `internal_api_key`) that should never leave the server. The
API relies on the client to ignore them, which is never a valid control.

## Vulnerable Code Snippet

```python
# vulnerable_version/main.py
@app.get("/api/v1/users/me")
def read_me(current_user: dict = Depends(get_current_user)):
    return current_user   # full record, including secrets
```

## Steps to Reproduce

```bash
uvicorn vulnerable_version.main:app --port 8000
```

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@apilab.com","password":"alice123"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

curl http://127.0.0.1:8000/api/v1/users/me -H "Authorization: Bearer $TOKEN"
# response includes password_hash, secret_aadhaar, internal_api_key
```

Automated: `python exploits/exploit_data_exposure.py`

## Impact

- Leak of password hashes (offline cracking) and national ID numbers.
- Internal API keys exposed, enabling lateral movement.

## Fixed Code Snippet

```python
# fixed_version/main.py
class UserPublic(BaseModel):
    id: int
    name: str
    email: EmailStr

@app.get("/api/v1/users/me", response_model=UserPublic)
def read_me(current_user: dict = Depends(get_current_user)):
    return current_user   # serialised through UserPublic -> safe fields only
```

## Remediation

- Define explicit response schemas; never return raw ORM / DB objects.
- Whitelist fields rather than blacklisting sensitive ones.
- Keep secrets (hashes, keys, PII) out of any serialisable response model.
- Add tests asserting sensitive keys are absent from responses.
