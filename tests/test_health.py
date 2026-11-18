from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_root_returns_welcome_message():
    response = client.get("/")
    assert response.status_code == 200
    assert "SecureSight AI" in response.json()["message"]


def test_health_check_returns_ok():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["app"] == "SecureSight AI"