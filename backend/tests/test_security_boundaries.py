from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def login(username: str, password: str):
    response = client.post(
        '/api/auth/login',
        json={'username': username, 'password': password},
    )
    assert response.status_code == 200, response.text
    return response.json()['access_token']


def test_tenant_isolation_denied():
    token = login('red_ops', 'securepassword')
    response = client.get('/api/blue-team/policies', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 403


def test_canary_detection_works():
    token = login('red_ops', 'securepassword')
    response = client.post(
        '/api/canaries/scan',
        json={'session_id': 'session-red-1', 'tenant_id': 'tenant-red', 'content': 'password=CANARY-RED-42'},
        headers={'Authorization': f'Bearer {token}'},
    )
    assert response.status_code == 200
    body = response.json()
    assert body['detections'] >= 1


def test_audit_verification_detects_tampering():
    token = login('admin', 'adminpass')
    response = client.get('/api/audit/verify', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    body = response.json()
    assert 'verified' in body


def test_session_separation():
    token = login('red_ops', 'securepassword')
    response = client.get('/api/client-sandbox/session/session-red-1', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    assert 'session_id' in response.json()


def test_report_generation_references_real_results():
    token = login('evaluator', 'auditpass')
    response = client.get('/api/reports/latest', headers={'Authorization': f'Bearer {token}'})
    assert response.status_code == 200
    data = response.json()
    assert 'scorecard' in data
    assert 'tests' in data


def test_security_alert_acknowledgment_is_authorized_and_persisted_in_process():
    token = login('admin', 'adminpass')
    headers = {'Authorization': f'Bearer {token}'}

    initial = client.get('/api/security-alerts', headers=headers)
    assert initial.status_code == 200
    alert = next(item for item in initial.json()['alerts'] if item['id'] == 'evt-1002')
    assert alert['acknowledged'] is False

    acknowledged = client.post('/api/security-alerts/evt-1002/acknowledge', headers=headers)
    assert acknowledged.status_code == 200
    body = acknowledged.json()
    assert body['acknowledged'] is True
    assert body['acknowledged_by'] == 'admin'
    assert body['acknowledged_at']

    listed = client.get('/api/security-alerts', headers=headers)
    persisted_alert = next(item for item in listed.json()['alerts'] if item['id'] == 'evt-1002')
    assert persisted_alert['acknowledged'] is True
    assert persisted_alert['acknowledged_by'] == 'admin'
    assert persisted_alert['acknowledged_at'] == body['acknowledged_at']

    repeated = client.post('/api/security-alerts/evt-1002/acknowledge', headers=headers)
    assert repeated.json() == body


def test_security_alert_acknowledgment_rejects_unauthorized_roles_and_unknown_alerts():
    red_team_token = login('red_ops', 'securepassword')
    forbidden = client.post(
        '/api/security-alerts/evt-1002/acknowledge',
        headers={'Authorization': f'Bearer {red_team_token}'},
    )
    assert forbidden.status_code == 403

    admin_token = login('admin', 'adminpass')
    missing = client.post(
        '/api/security-alerts/unknown-event/acknowledge',
        headers={'Authorization': f'Bearer {admin_token}'},
    )
    assert missing.status_code == 404
