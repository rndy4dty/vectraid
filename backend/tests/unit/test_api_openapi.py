"""Phase 9h - OpenAPI documentation verification tests.

These tests validate that the auto-generated OpenAPI schema is complete
and accurate. They are integration tests against FastAPI's schema
generation, not unit tests of our own code.
"""
from fastapi.testclient import TestClient

from app.main import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def _openapi() -> dict:
    return _client().get("/openapi.json").json()


# ---------- top-level schema ----------
def test_openapi_accessible():
    response = _client().get("/openapi.json")
    assert response.status_code == 200


def test_openapi_info_section():
    schema = _openapi()
    assert schema["info"]["title"] == "VECTRAID"
    assert schema["info"]["version"]
    assert "description" in schema["info"]


def test_openapi_has_security_scheme_for_api_key():
    """X-API-Key should appear as a security scheme or header parameter."""
    schema = _openapi()
    # FastAPI may not auto-detect Header-based auth as a security scheme,
    # so we accept either: (a) registered as security scheme, or
    # (b) present as X-API-Key header parameter on at least one operation.
    registered = "securitySchemes" in schema.get("components", {})
    has_header = False
    for path, ops in schema.get("paths", {}).items():
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            params = op.get("parameters", [])
            for p in params:
                if p.get("name", "").lower() == "x-api-key":
                    has_header = True
                    break
            if has_header:
                break
        if has_header:
            break
    assert registered or has_header, (
        "X-API-Key should be registered as security scheme or documented as a header"
    )


# ---------- endpoint coverage ----------
EXPECTED_PATHS = [
    "/health",
    "/api/v1/cases",
    "/api/v1/cases/{case_id}",
    "/api/v1/cases/{case_id}/transition",
    "/api/v1/cases/{case_id}/assign",
    "/api/v1/cases/{case_id}/notes",
    "/api/v1/cases/{case_id}/decisions",
    "/api/v1/cases/{case_id}/evidence",
    "/api/v1/cases/{case_id}/evidence/{evidence_id}",
    "/api/v1/cases/{case_id}/report",
    "/api/v1/evidence",
    "/api/v1/evidence/{evidence_id}",
    "/api/v1/investigate",
    "/api/v1/analyze/ioc",
    "/api/v1/analyze/email",
    "/api/v1/analyze/file",
    "/api/v1/hunt/logs",
]


def test_all_expected_paths_documented():
    schema = _openapi()
    documented = set(schema["paths"].keys())
    for path in EXPECTED_PATHS:
        assert path in documented, f"missing path in OpenAPI: {path}"


def test_all_paths_have_at_least_one_method():
    schema = _openapi()
    for path, ops in schema["paths"].items():
        methods = [m for m in ops if m in {"get", "post", "put", "delete", "patch"}]
        assert len(methods) >= 1, f"path {path} has no methods"


# ---------- request bodies documented ----------
def test_post_endpoints_have_request_body():
    schema = _openapi()
    post_endpoints_with_body = [
        ("/api/v1/cases", "post"),
        ("/api/v1/evidence", "post"),
        ("/api/v1/investigate", "post"),
        ("/api/v1/analyze/ioc", "post"),
        ("/api/v1/analyze/email", "post"),
        ("/api/v1/analyze/file", "post"),
        ("/api/v1/hunt/logs", "post"),
    ]
    for path, method in post_endpoints_with_body:
        op = schema["paths"][path][method]
        assert "requestBody" in op, f"{method.upper()} {path} missing requestBody"
        assert "content" in op["requestBody"]


# ---------- response models documented ----------
def test_get_cases_has_response_schema():
    schema = _openapi()
    op = schema["paths"]["/api/v1/cases"]["get"]
    assert "responses" in op
    assert "200" in op["responses"]
    content = op["responses"]["200"]["content"]
    assert "application/json" in content


def test_create_case_returns_201():
    schema = _openapi()
    op = schema["paths"]["/api/v1/cases"]["post"]
    assert "201" in op["responses"]


# ---------- tags ----------
def test_endpoints_have_tags():
    """All business endpoints should be grouped under tags."""
    schema = _openapi()
    tagged = 0
    for path, ops in schema["paths"].items():
        if not path.startswith("/api/v1"):
            continue
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            if method not in {"get", "post", "delete"}:
                continue
            assert "tags" in op, f"{method.upper()} {path} has no tags"
            tagged += 1
    assert tagged > 0


# ---------- components ----------
def test_schemas_registered():
    schema = _openapi()
    components = schema.get("components", {}).get("schemas", {})
    # At least some of our schemas should be registered
    expected_schemas = [
        "CaseResponse",
        "EvidenceResponse",
        "InvestigationReportResponse",
    ]
    for name in expected_schemas:
        assert name in components, f"schema {name} not registered"


# ---------- parameterized endpoints ----------
def test_path_parameters_documented():
    schema = _openapi()
    # /api/v1/cases/{case_id} should document case_id as path parameter
    op = schema["paths"]["/api/v1/cases/{case_id}"]["get"]
    params = op.get("parameters", [])
    case_id_param = next(
        (p for p in params if p.get("name") == "case_id"), None
    )
    assert case_id_param is not None
    assert case_id_param["in"] == "path"
    assert case_id_param["required"] is True
