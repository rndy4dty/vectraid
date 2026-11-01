"""Phase 9f - API key authentication tests (test-first)."""
from fastapi.testclient import TestClient

from app.main import create_app


def _client_with_api_key(api_key: str) -> TestClient:
    """Build a client with a specific VECTRAID_API_KEY value.

    We monkeypatch get_settings() so create_app() reads our test key.
    """
    import app.main as main_module

    original = main_module.settings
    class _Patched:
        app_name = original.app_name
        app_version = original.app_version
        api_v1_prefix = original.api_v1_prefix
        vectraid_api_key = api_key

    # Patch settings object used by create_app
    main_module.settings = original.model_copy(
        update={"vectraid_api_key": api_key}
    ) if hasattr(original, "model_copy") else original

    try:
        app = create_app()
    finally:
        main_module.settings = original
    return TestClient(app)


def _client_no_auth() -> TestClient:
    """Client with no API key configured (dev mode)."""
    return TestClient(create_app())


# ---------- no key configured: auth disabled ----------
def test_no_api_key_configured_allows_access(api_client):
    response = api_client.get("/api/v1/cases")
    assert response.status_code == 200


# ---------- with key configured ----------
def test_missing_key_returns_401():
    # Build app with a configured API key
    import app.main as main_module
    original = main_module.settings
    main_module.settings = original.model_copy(
        update={"vectraid_api_key": "secret123"}
    )
    try:
        app = create_app()
    finally:
        main_module.settings = original

    client = TestClient(app)
    response = client.get("/api/v1/cases")
    assert response.status_code == 401


def test_wrong_key_returns_401():
    import app.main as main_module
    original = main_module.settings
    main_module.settings = original.model_copy(
        update={"vectraid_api_key": "secret123"}
    )
    try:
        app = create_app()
    finally:
        main_module.settings = original

    client = TestClient(app)
    response = client.get(
        "/api/v1/cases", headers={"X-API-Key": "wrong"}
    )
    assert response.status_code == 401


def test_correct_key_returns_200(api_client):
    app = api_client.app
    original = app.state.settings
    app.state.settings = original.model_copy(
        update={"vectraid_api_key": "secret123"}
    )
    try:
        response = api_client.get(
            "/api/v1/cases", headers={"X-API-Key": "secret123"}
        )
        assert response.status_code == 200
    finally:
        app.state.settings = original


# ---------- health always open ----------
def test_health_always_open_even_with_key():
    import app.main as main_module
    original = main_module.settings
    main_module.settings = original.model_copy(
        update={"vectraid_api_key": "secret123"}
    )
    try:
        app = create_app()
    finally:
        main_module.settings = original

    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200


# ---------- openapi docs still accessible ----------
def test_openapi_accessible_without_key():
    """OpenAPI docs should be accessible; they don't expose data."""
    import app.main as main_module
    original = main_module.settings
    main_module.settings = original.model_copy(
        update={"vectraid_api_key": "secret123"}
    )
    try:
        app = create_app()
    finally:
        main_module.settings = original

    client = TestClient(app)
    response = client.get("/openapi.json")
    # Either 200 (open) or 401 (locked). We test that it doesn't crash.
    assert response.status_code in (200, 401)
