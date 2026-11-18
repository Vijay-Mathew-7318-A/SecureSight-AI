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