# Secure-by-Design API Lab

An intentionally vulnerable API lab for learning the **OWASP API Security Top 10**.

This project ships two parallel implementations of the same API so you can see,
exploit, and then fix each class of vulnerability:

- `vulnerable_version/` - insecure endpoints that can be exploited (port 8000).
- `fixed_version/` - the same endpoints hardened with proper controls (port 8001).
- `exploits/` - automated Python scripts that attack the vulnerable app and
  confirm the fixed app blocks the same attack.
- `writeups/` - per-vulnerability remediation guides.

It is built to demonstrate **both offensive (exploitation) and defensive
(remediation) understanding** of API security.

## OWASP API Top 10 coverage

| # | Vulnerability | OWASP ID | Endpoint | Exploit | Writeup |
|---|---------------|----------|----------|---------|---------|
| 1 | BOLA / IDOR | API1:2023 | `GET /api/v1/users/{id}` | `exploit_bola.py` | [BOLA_IDOR.md](writeups/BOLA_IDOR.md) |
| 2 | Broken Authentication | API2:2023 | `GET /api/v1/secure-data` | `exploit_auth.py` | [BROKEN_AUTH.md](writeups/BROKEN_AUTH.md) |
| 3 | Excessive Data Exposure | API3:2023 | `GET /api/v1/users/me` | `exploit_data_exposure.py` | [EXCESSIVE_DATA_EXPOSURE.md](writeups/EXCESSIVE_DATA_EXPOSURE.md) |
| 4 | Unrestricted Resource Consumption (no rate limit) | API4:2023 | `POST /api/v1/login` | `exploit_rate_limit.py` | [RATE_LIMITING.md](writeups/RATE_LIMITING.md) |
| 5 | BFLA | API5:2023 | `DELETE /api/v1/admin/users/{id}` | `exploit_bfla.py` | [BFLA.md](writeups/BFLA.md) |

## Architecture

```
            +---------------------+          +---------------------+
            |  vulnerable_version |          |    fixed_version    |
            |      (port 8000)    |          |      (port 8001)    |
            |                     |          |                     |
 exploits/  |  main.py  (routes)  |          |  main.py  (routes)  |
   *.py ----+  auth.py  (weak JWT)|          |  auth.py  (strict)  |
   attack   |  database.py (fake) |          |  database.py (fake) |
            +---------------------+          +---------------------+
                    |                                   |
            attack SUCCEEDS                     attack BLOCKED (401/403/429)
```

Both apps use a fake in-memory database (`database.py`) seeded with an admin
and two normal users. No external datastore is required.

## Tech stack

- Python
- FastAPI
- Pydantic
- PyJWT
- Uvicorn
- requests (exploit scripts)

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run the vulnerable API (port 8000)

```bash
uvicorn vulnerable_version.main:app --reload --port 8000
# docs: http://127.0.0.1:8000/docs
```

## Run the fixed API (port 8001)

```bash
# optional: set a strong secret for the hardened JWT auth
export API_LAB_SECRET="change-me-to-a-long-random-value"

uvicorn fixed_version.main:app --reload --port 8001
# docs: http://127.0.0.1:8001/docs
```

## Run the exploits

With both servers running, from the project root:

```bash
python exploits/exploit_bola.py
python exploits/exploit_bfla.py
python exploits/exploit_auth.py
python exploits/exploit_data_exposure.py
python exploits/exploit_rate_limit.py
```

Each script runs the attack twice:

- against **port 8000** (vulnerable) the attack **succeeds**, and
- against **port 8001** (fixed) the attack is **blocked** with `401` / `403` / `429`.

## Seeded accounts

| Role | Email | Password |
|------|-------|----------|
| admin | `admin@apilab.com` | `admin123` |
| user | `alice@apilab.com` | `alice123` |
| user | `bob@apilab.com` | `bob123` |

## Disclaimer

For **educational use only**. The `vulnerable_version` is insecure by design.
Run it locally, on an isolated machine. Never deploy it to a public server or
point it at real data.
