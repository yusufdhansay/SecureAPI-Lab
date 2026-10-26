# BFLA - Broken Function Level Authorization

| Field | Value |
|-------|-------|
| OWASP Category | API5:2023 - Broken Function Level Authorization |
| Endpoint | `DELETE /api/v1/admin/users/{user_id}` |
| Severity | **High** (CVSS ~8.1) |

## Description

The delete endpoint is an administrative function, but the vulnerable version
only checks that the caller is authenticated, not that the caller holds the
`admin` role. Any logged-in normal user can delete any account.

## Vulnerable Code Snippet

```python
# vulnerable_version/main.py
@app.delete("/api/v1/admin/users/{user_id}")
def delete_user(user_id: int, current_user: dict = Depends(get_current_user)):
    target = database.get_user_by_id(user_id)      # no role check
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    database.USERS.remove(target)
    return {"message": f"user {user_id} deleted"}
```

## Steps to Reproduce

```bash
uvicorn vulnerable_version.main:app --port 8000
```

Log in as a normal user and delete someone else:

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"email":"alice@apilab.com","password":"alice123"}' | python -c "import sys,json;print(json.load(sys.stdin)['token'])")

curl -X DELETE http://127.0.0.1:8000/api/v1/admin/users/3 \
  -H "Authorization: Bearer $TOKEN"
```

Automated: `python exploits/exploit_bfla.py`

## Impact

- Any user can destroy other accounts (data loss, denial of service).
- Privilege boundaries between `user` and `admin` are meaningless.

## Fixed Code Snippet

```python
# fixed_version/main.py
def require_admin_role(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Admin role required")
    return current_user

@app.delete("/api/v1/admin/users/{user_id}")
def delete_user(user_id: int, admin: dict = Depends(require_admin_role)):
    ...
```

## Remediation

- Deny by default; grant administrative functions to admin roles only.
- Centralise role checks in a reusable dependency / middleware.
- Keep admin routes under a separate, consistently protected prefix.
- Add automated tests that assert non-admins receive 403.
