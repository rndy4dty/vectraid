"""Phase 9a - FastAPI app setup and health check tests (test-first)."""
from fastapi.testclient import TestClient

from app.main import create_app


def test_health_endpoint_returns_ok():
    app = create_app()
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_openapi_docs_available():
    app = create_app()
    client = TestClient(app)
    response = client.get("/openapi.json")
    assert response.status_code == 200
    data = response.json()
    assert data["info"]["title"] == "VECTRAID"


def test_fresh_app_isolated_state():
    """Two apps must not share state."""
    app1 = create_app()
    app2 = create_app()
    assert app1 is not app2
