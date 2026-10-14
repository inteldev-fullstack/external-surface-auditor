import pytest
from fastapi.testclient import TestClient
from app import main

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('ESA_SCOPE_FILE', str(tmp_path / 'scope.json'))
    monkeypatch.setenv('ESA_DATA_DIR', str(tmp_path / 'data'))
    main._last.clear()
    main._active.clear()
    with TestClient(main.app, base_url='http://localhost') as client:
        yield client

@pytest.fixture
def sample_report():
    return {
        'target': 'staging.example.test', 'environment': 'staging',
        'started_at': '2026-10-14T00:00:00+00:00', 'completed_at': '2026-10-14T00:00:01+00:00',
        'dns': {'A': ['93.184.216.34']}, 'resolved_addresses': ['93.184.216.34'],
        'dns_warnings': [], 'probes': [], 'findings': [{
            'id': 'header', 'title': 'Header absent', 'severity': 'low', 'category': 'http-configuration',
            'confidence': 'high', 'summary': 'Missing header in approved endpoint.',
            'evidence': ['<test> & observation'], 'remediation': 'Review and configure the header.'
        }], 'summary': {'critical': 0, 'high': 0, 'medium': 0, 'low': 1, 'info': 0},
        'notes': ['Limited HEAD checks; redirects not followed.']
    }
