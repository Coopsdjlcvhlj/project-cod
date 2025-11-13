import os
import pytest
from main1.main import app, load_config, METRICS_ENABLED

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c

def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data.get("status") == "ok"

def test_ready(client):
    # при нормальній роботі повертає 200
    resp = client.get("/ready")
    assert resp.status_code in (200, 503)
    data = resp.get_json()
    assert "status" in data

def test_docs(client):
    resp = client.get("/docs")
    assert resp.status_code == 200
    data = resp.get_json()
    assert "routes" in data

def test_metrics(client):
    resp = client.get("/metrics")
    # може бути 200 (якщо prometheus-client встановлений) або 503 (якщо немає)
    assert resp.status_code in (200, 503)

def test_load_config():
    cfg = load_config()
    assert "FLASK_HOST" in cfg
    assert "FLASK_PORT" in cfg
