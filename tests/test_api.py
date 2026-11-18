from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_validate_url_accepts_public_ip():
    response = client.post("/api/validate-url", json={"url": "http://8.8.8.8"})
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["hostname"] == "8.8.8.8"
    assert data["scheme"] == "http"
    assert data["port"] == 80


def test_validate_url_adds_https():
    response = client.post("/api/validate-url", json={"url": "8.8.8.8"})
    assert response.status_code == 200
    assert response.json()["url"] == "https://8.8.8.8"


def test_validate_url_blocks_localhost():
    response = client.post("/api/validate-url", json={"url": "localhost"})
    assert response.status_code == 400
    assert "not allowed" in response.json()["detail"]


def test_validate_url_blocks_private_ip():
    response = client.post("/api/validate-url", json={"url": "http://10.0.0.5"})
    assert response.status_code == 400
    assert "private" in response.json()["detail"]


def test_validate_url_rejects_empty_url():
    response = client.post("/api/validate-url", json={"url": "   "})
    assert response.status_code == 400


def test_validate_url_rejects_bad_scheme():
    response = client.post("/api/validate-url", json={"url": "ftp://example.com"})
    assert response.status_code == 400


def test_validate_url_missing_field_returns_422():
    response = client.post("/api/validate-url", json={})
    assert response.status_code == 422