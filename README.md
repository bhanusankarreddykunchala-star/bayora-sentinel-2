# Bayora Sentinel 2.0

Bayora Sentinel 2.0 is a zero-trust AI safety testing and information leakage prevention platform built as a local proof of concept for the Hack in Hills '26 hackathon.

## Architecture overview

- Frontend: React + TypeScript + Vite + Tailwind CSS
- Backend: FastAPI + Pydantic
- Security model: local demo auth, RBAC, tenant gating, canary detection, audit hash chaining, isolated mock sessions
- Data model: in-memory dev state for quick local demo and testing
- Security alert acknowledgments are role-restricted and held in API process memory; they reset when the backend restarts.

## Quick start

### 1) Install frontend dependencies

```bash
npm install
```

### 2) Install backend dependencies

```bash
python -m pip install -r requirements.txt
```

### 3) Start the API server

```bash
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 4) Start the frontend

```bash
npm run dev -- --host 0.0.0.0
```

Open the Vite dashboard in the browser at:

- Frontend: http://127.0.0.1:5173
- API docs: http://127.0.0.1:8000/docs

## Demo accounts

- admin / adminpass
- red_ops / securepassword
- blue_ops / securepassword
- evaluator / auditpass

## Security test flow

1. Sign in as the red team user and trigger a canary scan.
2. Confirm the canary is detected at the observation boundary.
3. Attempt to fetch a blue-team policy as a red team user to confirm a 403 response.
4. Request the audit verification endpoint to confirm the hash chain is valid.
5. Review the dashboard metrics and event stream for evidence-backed telemetry.
6. Open Security Alerts and acknowledge an event as an Administrator or Blue Team Operator.

## Test commands

```bash
pytest backend/tests/test_security_boundaries.py
npm run build
```

## Limitations

This project is intentionally a local, evidence-based demo. It does not claim complete model isolation, full hardware side-channel mitigation, or production-grade cloud security controls.

The current API does not provide red-team test submission, model prompt execution, policy mutation, or isolation-test execution endpoints. Related pages expose only backend data that is actually available; alert acknowledgments are volatile process memory, not durable records.
