# SecureSight AI - Project Progress

## Stack
Python, FastAPI, Requests, Pydantic, SQLite + SQLAlchemy, HTML/CSS/JS, Claude API (with rule-based fallback), Pytest. Windows + VS Code.

## Folder Structure
app/ (main.py, api/, core/, scanner/, db/, ai/), frontend/, tests/, requirements.txt, pytest.ini, .env.example, .gitignore

## Decisions
- Run server from project root: `uvicorn app.main:app --reload`
- Tests: `pytest -v` (pytest.ini sets pythonpath to project root)
- API routes live under `/api/...`
- Secrets only via `.env` (never committed)

## Phase Status
- [x] Phase 1: Project initialization (pending user verification of Step 1.1)
- [ ] Phase 2: Backend development
- [ ] Phase 3: Security scanning engine
- [ ] Phase 4: Database
- [ ] Phase 5: Frontend
- [ ] Phase 6: Integration
- [ ] Phase 7: AI integration
- [ ] Phase 8: Testing and debugging
- [ ] Phase 9: Finalization

## Implemented Security Checks
None yet.

## OWASP Categories Not Yet Covered
All (scanner not yet built).

## Known Issues
None reported.

## - Phase 2: Backend development (config, URL validator, schemas, routes, error handlers done; scan endpoints come after the scanner exists)

- Settings: `app/core/config.py` -> `get_settings()`
- URL safety: `app/core/url_validator.py` -> `validate_target_url()` raises `UnsafeURLError`; allowed ports 80/443/8080/8443; every resolved IP must be public
- API: `app/api/schemas.py` (Pydantic models), `app/api/routes.py` (router with prefix `/api`: GET /health, POST /validate-url)
- Errors: `UnsafeURLError` -> HTTP 400 `{"detail": "..."}`; unexpected errors -> HTTP 500 generic message (details only in server log)

## - [~] Phase 3: Security scanning engine (3.1 models + HTTP client, 3.2 HTTPS/TLS, 3.3 security headers done; cookies, extra OWASP checks, engine pending)

- OWASP edition: 2025 (SSRF merged into A01). Names live in `OWASP_TOP_10` in `app/scanner/models.py`; verify A05-A08 names at owasp.org/Top10/2025
- Scanner data: `Finding`, `ScanResult`, `Severity` in `app/scanner/models.py`
- Fetching: `SafeHttpClient().fetch(url)` -> `FetchResult` in `app/scanner/http_client.py`; revalidates every redirect; raises `UnsafeURLError` (unsafe) or `FetchError` (network problem)
- Bad TLS certificate: client retries without verification only to read headers, and sets `tls_verified=False`

- SSRF: peer-IP check detects (not prevents) DNS-rebinding after connect; best effort only
- FetchError has no API handler yet (add when the scan endpoint is built)

## Implemented Security Checks
- HTTPS availability (https-unavailable)
- HTTP to HTTPS redirect (http-no-https-redirect)
- TLS certificate validity: expired, hostname mismatch, self-signed, untrusted chain, other failure
- TLS certificate expiry warnings (7/14/30 days) and a valid-certificate informational result
(All map to OWASP A04:2025 Cryptographic Failures; standard ports 80/443 only)

## OWASP 2025 Categories Not Yet Covered
A01, A02, A03, A05, A06, A07, A08, A09, A10 (A04 only partly: no cipher/protocol-version or revocation checks)

- HTTP security headers (A02:2025): HSTS, CSP (missing/weak), X-Content-Type-Options, clickjacking protection (X-Frame-Options / CSP frame-ancestors), Referrer-Policy, Permissions-Policy, server/technology version disclosure
  (single page only; simplified CSP review; HSTS skipped when final page is HTTP; page-level checks skipped for non-HTML responses)

  A02 partly covered (headers only; cookies, CORS, error pages, default files pending), A04 partly covered (no cipher/protocol/revocation checks). Not covered: A01, A03, A05, A06, A07, A08, A09, A10
