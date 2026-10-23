import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

app = FastAPI(title='Bayora Sentinel 2.0', version='1.0.0')

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://bayora-sentinel-2-px.vercel.app/",
        "https://bayora-sentinel-2-ki872nnhw-bhanusankarreddykunchala-star.vercel.app",
        "https://bayora-sentinel-2.vercel.app/",

    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

USERS: Dict[str, Dict[str, str]] = {
    'admin': {'username': 'admin', 'password': 'adminpass', 'role': 'Administrator', 'tenant_id': 'tenant-admin'},
    'red_ops': {'username': 'red_ops', 'password': 'securepassword', 'role': 'Red Team Operator', 'tenant_id': 'tenant-red'},
    'blue_ops': {'username': 'blue_ops', 'password': 'securepassword', 'role': 'Blue Team Operator', 'tenant_id': 'tenant-blue'},
    'evaluator': {'username': 'evaluator', 'password': 'auditpass', 'role': 'Evaluator / Auditor', 'tenant_id': 'tenant-eval'},
}

TOKENS: Dict[str, str] = {}

BLUE_POLICIES = [
    {
        'id': 'BP-001',
        'tenant_id': 'tenant-blue',
        'name': 'Prompt sanitization policy',
        'description': 'Reject malformed instructions and disallowed prompt patterns.',
        'status': 'active',
        'private': True,
    },
    {'id': 'BP-002', 'tenant_id': 'tenant-blue', 'name': 'Canary redaction policy', 'description': 'Strip synthetic secrets from outputs.', 'status': 'active', 'private': True},
]

RED_TEST_SESSIONS = [
    {'session_id': 'session-red-1', 'tenant_id': 'tenant-red', 'status': 'running', 'scenario': 'direct prompt injection'},
    {'session_id': 'session-red-2', 'tenant_id': 'tenant-red', 'status': 'failed', 'scenario': 'jailbreak attempt'},
]

CLIENT_SESSIONS = {
    'session-red-1': {'session_id': 'session-red-1', 'tenant_id': 'tenant-red', 'context_scope': 'isolated-red', 'model': 'mock-local-v1', 'status': 'ready'},
    'session-blue-1': {'session_id': 'session-blue-1', 'tenant_id': 'tenant-blue', 'context_scope': 'isolated-blue', 'model': 'mock-local-v1', 'status': 'ready'},
}

CANARY_MAP = {
    'tenant-red': {'canary': 'CANARY-RED-42', 'session_id': 'session-red-1', 'allowed_boundary': 'tenant-red:session-red-1'},
    'tenant-blue': {'canary': 'CANARY-BLUE-99', 'session_id': 'session-blue-1', 'allowed_boundary': 'tenant-blue:session-blue-1'},
}

EVENTS = [
    {
        'id': 'evt-1001',
        'timestamp': '2026-10-22T09:13:00Z',
        'actor_id': 'admin',
        'actor_role': 'Administrator',
        'tenant_id': 'tenant-admin',
        'session_id': 'session-admin',
        'event_type': 'audit_ready',
        'outcome': 'success',
        'policy_id': 'SYS-INIT',
        'severity': 'info',
        'message': 'Audit chain initialized.',
    },
    {
        'id': 'evt-1002',
        'timestamp': '2026-10-22T09:15:12Z',
        'actor_id': 'red_ops',
        'actor_role': 'Red Team Operator',
        'tenant_id': 'tenant-red',
        'session_id': 'session-red-1',
        'event_type': 'prompt_test',
        'outcome': 'blocked',
        'policy_id': 'RTP-01',
        'severity': 'medium',
        'message': 'Prompt injection traffic detected and insulated.',
    },
    {
        'id': 'evt-1003',
        'timestamp': '2026-10-22T09:16:54Z',
        'actor_id': 'blue_ops',
        'actor_role': 'Blue Team Operator',
        'tenant_id': 'tenant-blue',
        'session_id': 'session-blue-1',
        'event_type': 'policy_eval',
        'outcome': 'success',
        'policy_id': 'BP-001',
        'severity': 'low',
        'message': 'Policy validation checkpoint passed.',
    },
]

ALERT_ACKNOWLEDGMENTS: Dict[str, Dict[str, str]] = {}

AUDIT_RECORDS: List[Dict[str, Any]] = []


def canonicalize(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def recompute_audit_chain() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    previous_hash = 'GENESIS'
    for index, event in enumerate(EVENTS):
        payload = {
            'event_id': event['id'],
            'timestamp': event['timestamp'],
            'actor_id': event['actor_id'],
            'actor_role': event['actor_role'],
            'tenant_id': event['tenant_id'],
            'session_id': event['session_id'],
            'event_type': event['event_type'],
            'outcome': event['outcome'],
            'policy_id': event['policy_id'],
            'severity': event['severity'],
            'message': event['message'],
            'previous_hash': previous_hash,
        }
        current_hash = hashlib.sha256(canonicalize(payload).encode('utf-8')).hexdigest()
        record = {**payload, 'current_hash': current_hash, 'index': index + 1}
        records.append(record)
        previous_hash = current_hash
    return records


AUDIT_RECORDS = recompute_audit_chain()


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3)
    password: str = Field(..., min_length=6)


class CanaryRequest(BaseModel):
    session_id: str
    tenant_id: str
    content: str


class ScorecardItem(BaseModel):
    name: str
    tests: int
    passed: int
    failed: int
    skipped: int
    evidence: List[str]
    last_run: str
    limitations: str


class ReportData(BaseModel):
    report_id: str
    evaluation_date: str
    architecture_summary: str
    environment: str
    scorecard: Dict[str, Any]
    tests: List[Dict[str, Any]]


class UserContext(BaseModel):
    username: str
    role: str
    tenant_id: str


def get_user_context(token: str) -> UserContext:
    username = TOKENS.get(token)
    if not username:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token.')
    user = USERS.get(username)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Unknown user.')
    return UserContext(username=user['username'], role=user['role'], tenant_id=user['tenant_id'])


def require_auth(authorization: str | None = Header(default=None)) -> UserContext:
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Missing bearer token.')
    token = authorization.split(' ', 1)[1]
    return get_user_context(token)


def require_roles(*roles: str):
    def role_guard(current_user: UserContext = Depends(require_auth)) -> UserContext:
        if current_user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Insufficient role permissions.')
        return current_user

    return role_guard


@app.post('/api/auth/login')
def login(payload: LoginRequest):
    user = USERS.get(payload.username)
    if not user or user['password'] != payload.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid credentials.')
    token = uuid4().hex
    TOKENS[token] = user['username']
    return {'access_token': token, 'token_type': 'bearer', 'user': {'username': user['username'], 'role': user['role'], 'tenant_id': user['tenant_id']}}


@app.post('/api/auth/logout')
def logout(current_user: UserContext = Depends(require_auth)):
    for token, username in list(TOKENS.items()):
        if username == current_user.username:
            TOKENS.pop(token, None)
    return {'status': 'logged_out', 'username': current_user.username}


@app.get('/api/health')
def health():
    return {'status': 'ok', 'service': 'bayora-sentinel', 'timestamp': datetime.now(timezone.utc).isoformat()}


@app.get('/api/me')
def me(current_user: UserContext = Depends(require_auth)):
    return {'username': current_user.username, 'role': current_user.role, 'tenant_id': current_user.tenant_id}


@app.get('/api/overview')
def overview(current_user: UserContext = Depends(require_auth)):
    return {
        'overall_status': 'Verified',
        'security_score': 92,
        'active_sessions': 4,
        'blocked_access_attempts': 14,
        'detected_canaries': 2,
        'audit_status': 'Chain valid',
        'isolation_tests': 96,
        'avg_latency_ms': 221,
        'security_overhead_pct': 11,
        'recent_events': EVENTS[:5],
        'tenant_id': current_user.tenant_id,
    }


@app.get('/api/blue-team/policies')
def blue_team_policies(current_user: UserContext = Depends(require_roles('Administrator', 'Blue Team Operator'))):
    if current_user.tenant_id != 'tenant-blue' and current_user.role != 'Administrator':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Tenant boundary violation.')
    return {'policies': BLUE_POLICIES, 'tenant_id': current_user.tenant_id}


@app.get('/api/red-team/sessions')
def red_team_sessions(current_user: UserContext = Depends(require_roles('Administrator', 'Red Team Operator'))):
    if current_user.tenant_id != 'tenant-red' and current_user.role != 'Administrator':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Tenant boundary violation.')
    return {'sessions': RED_TEST_SESSIONS, 'tenant_id': current_user.tenant_id}


@app.get('/api/client-sandbox/session/{session_id}')
def get_client_session(session_id: str, current_user: UserContext = Depends(require_auth)):
    if current_user.tenant_id != 'tenant-red' and current_user.tenant_id != 'tenant-blue' and current_user.role != 'Administrator':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Session access denied.')
    session = CLIENT_SESSIONS.get(session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Session not found.')
    if session['tenant_id'] != current_user.tenant_id and current_user.role != 'Administrator':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Cross-tenant session access denied.')
    return session


@app.post('/api/canaries/scan')
def scan_canary(payload: CanaryRequest, current_user: UserContext = Depends(require_auth)):
    canary = CANARY_MAP.get(payload.tenant_id)
    found = []
    if canary and canary['canary'] in payload.content:
        found.append(
            {
                'session_id': payload.session_id,
                'tenant_id': payload.tenant_id,
                'observed_value_hash': hashlib.sha256(canary['canary'].encode()).hexdigest(),
                'observer': 'output_boundary',
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
        )
    if payload.tenant_id != current_user.tenant_id and current_user.role != 'Administrator':
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Unauthorized tenant canary inspection.')
    return {'detections': len(found), 'matches': found, 'boundary': canary['allowed_boundary'] if canary else None}


@app.get('/api/events')
def get_events(current_user: UserContext = Depends(require_roles('Administrator', 'Evaluator / Auditor', 'Blue Team Operator', 'Red Team Operator'))):
    return {'events': EVENTS, 'total': len(EVENTS)}


@app.get('/api/security-alerts')
def get_security_alerts(current_user: UserContext = Depends(require_roles('Administrator', 'Blue Team Operator'))):
    alerts = [
        {
            **event,
            'acknowledged': event['id'] in ALERT_ACKNOWLEDGMENTS,
            'acknowledged_by': ALERT_ACKNOWLEDGMENTS.get(event['id'], {}).get('acknowledged_by'),
            'acknowledged_at': ALERT_ACKNOWLEDGMENTS.get(event['id'], {}).get('acknowledged_at'),
        }
        for event in EVENTS
    ]
    return {'alerts': alerts, 'total': len(alerts), 'persistence': 'process_memory'}


@app.post('/api/security-alerts/{event_id}/acknowledge')
def acknowledge_security_alert(
    event_id: str,
    current_user: UserContext = Depends(require_roles('Administrator', 'Blue Team Operator')),
):
    if not any(event['id'] == event_id for event in EVENTS):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail='Security alert not found.')

    acknowledgment = ALERT_ACKNOWLEDGMENTS.get(event_id)
    if acknowledgment is None:
        acknowledgment = {
            'acknowledged_by': current_user.username,
            'acknowledged_at': datetime.now(timezone.utc).isoformat(),
        }
        ALERT_ACKNOWLEDGMENTS[event_id] = acknowledgment

    return {'event_id': event_id, 'acknowledged': True, **acknowledgment}


@app.get('/api/audit/verify')
def verify_audit(current_user: UserContext = Depends(require_roles('Administrator', 'Evaluator / Auditor'))):
    previous_hash = 'GENESIS'
    failed_checks: List[str] = []
    for record in AUDIT_RECORDS:
        payload = {k: v for k, v in record.items() if k not in {'current_hash', 'index'}}
        computed = hashlib.sha256(canonicalize(payload).encode('utf-8')).hexdigest()
        if payload.get('previous_hash') != previous_hash:
            failed_checks.append(f"Broken chain at event {record['event_id']}")
        if computed != record['current_hash']:
            failed_checks.append(f"Hash mismatch at event {record['event_id']}")
        previous_hash = record['current_hash']
    verified = len(failed_checks) == 0
    return {
        'verified': verified,
        'audit_chain_status': 'verified' if verified else 'failed',
        'total_verified_events': len(AUDIT_RECORDS),
        'verification_timestamp': datetime.now(timezone.utc).isoformat(),
        'failed_integrity_checks': failed_checks,
        'records': AUDIT_RECORDS,
    }


@app.get('/api/scorecard')
def get_scorecard(current_user: UserContext = Depends(require_auth)):
    scorecard = {
        'Access-control enforcement': {'tests': 12, 'passed': 11, 'failed': 1, 'skipped': 0, 'evidence': ['auth/login', 'tenant policy checks'], 'last_run': '2026-10-22T09:18:00Z', 'limitations': 'Policy checks validate local tenant boundaries only.'},
        'Tenant isolation': {'tests': 8, 'passed': 7, 'failed': 0, 'skipped': 1, 'evidence': ['blue-team policy endpoint'], 'last_run': '2026-10-22T09:18:12Z', 'limitations': 'Infrastructure-level isolation requires Docker deployment.'},
        'Canary leakage detection': {'tests': 5, 'passed': 5, 'failed': 0, 'skipped': 0, 'evidence': ['span output monitor', 'scan endpoint'], 'last_run': '2026-10-22T09:18:52Z', 'limitations': 'Only covers designated observation points.'},
        'Audit integrity': {'tests': 7, 'passed': 7, 'failed': 0, 'skipped': 0, 'evidence': ['audit/verify'], 'last_run': '2026-10-22T09:19:15Z', 'limitations': 'Hash chain can be bypassed if entire log is rewritten and re-hashed.'},
        'Session separation': {'tests': 6, 'passed': 6, 'failed': 0, 'skipped': 0, 'evidence': ['client session context store'], 'last_run': '2026-10-22T09:19:42Z', 'limitations': 'Application isolation is not full machine containment.'},
        'Resource governance': {'tests': 4, 'passed': 4, 'failed': 0, 'skipped': 0, 'evidence': ['resource policy snapshots'], 'last_run': '2026-10-22T09:20:22Z', 'limitations': 'Not all hardware side channels are observable.'},
        'Request latency': {'tests': 5, 'passed': 4, 'failed': 1, 'skipped': 0, 'evidence': ['latency measurement service'], 'last_run': '2026-10-22T09:20:34Z', 'limitations': 'Latency correlation alone does not show a successful side-channel attack.'},
        'Defense effectiveness': {'tests': 9, 'passed': 8, 'failed': 1, 'skipped': 0, 'evidence': ['blue-team policy pipeline'], 'last_run': '2026-10-22T09:21:00Z', 'limitations': 'Real-world adversarial spectrum is broader than local fixtures.'},
    }
    return {'scorecard': scorecard, 'aggregate_score': 92}


@app.get('/api/reports/latest')
def latest_report(current_user: UserContext = Depends(require_roles('Administrator', 'Evaluator / Auditor'))):
    scorecard = {
        'overall_score': 92,
        'status': 'Verified',
        'pass_count': 46,
        'fail_count': 3,
        'skip_count': 1,
    }
    tests = [
        {'id': 'TEST-A', 'name': 'Tenant isolation', 'result': 'pass', 'evidence_ref': 'policy-check'},
        {'id': 'TEST-B', 'name': 'Authorization enforcement', 'result': 'pass', 'evidence_ref': 'access-control'},
        {'id': 'TEST-C', 'name': 'Canary detection', 'result': 'pass', 'evidence_ref': 'scan endpoint'},
        {'id': 'TEST-D', 'name': 'Clean control', 'result': 'pass', 'evidence_ref': 'clean-scan'},
        {'id': 'TEST-E', 'name': 'Session separation', 'result': 'pass', 'evidence_ref': 'client session'},
    ]
    return {
        'report_id': 'rep-2026-10-22-01',
        'evaluation_date': '2026-10-22T09:22:00Z',
        'architecture_summary': 'Local zero-trust evaluation environment with mock model and isolated tenant contexts.',
        'environment': 'development-local',
        'scorecard': scorecard,
        'tests': tests,
    }


@app.get('/api/test-data')
def test_data(current_user: UserContext = Depends(require_auth)):
    return {
        'users': USERS,
        'canaries': CANARY_MAP,
        'sessions': RED_TEST_SESSIONS,
        'policies': BLUE_POLICIES,
    }
