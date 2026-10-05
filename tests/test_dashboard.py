from fastapi.testclient import TestClient
from scripts.siarc_api import app

client = TestClient(app)

def test_dashboard_is_served():
    r = client.get('/dashboard')
    assert r.status_code == 200
    assert 'SIARC — Dashboard de Governança e Risco' in r.text


def test_research_summary_is_public_and_aggregated():
    r = client.get('/dashboard/research-summary')
    assert r.status_code == 200
    data = r.json()
    assert data['pii']['cases'] == 125
    assert data['load']['total_requests'] == 43369
