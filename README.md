# Secure-by-Design API Lab

An intentionally vulnerable API lab for learning the **OWASP API Security Top 10**.

This project ships two parallel implementations of the same API:

- `vulnerable_version/` - insecure endpoints that can be exploited.
- `fixed_version/` - the same endpoints with proper security controls.

It demonstrates both **offensive** (exploitation) and **defensive** (remediation) understanding.

> Full documentation, OWASP mapping, exploit scripts and writeups are added in later phases.

## Status

Work in progress. Built in phases:

1. Project setup + FastAPI boilerplate + fake DB  *(current)*
2. Vulnerable endpoints
3. Secure (fixed) version
4. Automated exploit scripts
5. Writeups + final docs

## Tech stack

- Python
- FastAPI
- Pydantic
- PyJWT
- Uvicorn

## Disclaimer

For educational use only. Run locally. Never deploy the vulnerable version to a public server.
