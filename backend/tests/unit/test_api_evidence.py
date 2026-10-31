"""Phase 9c - Evidence API endpoints tests (test-first)."""
from fastapi.testclient import TestClient

from app.main import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def _create_case(client: TestClient, case_id: str = "CASE-2026-0001") -> str:
    """Create a case via API and return its generated id."""
    r = client.post(
        "/api/v1/cases",
        json={"title": "T", "priority": "medium", "created_by": "a@x.com"},
    )
    assert r.status_code == 201
    return r.json()["case_id"]


def _evidence_payload(case_id: str, eid: str = "ev-001") -> dict:
    return {
        "evidence_id": eid,
        "case_id": case_id,
        "source_module": "phishtrace",
        "evidence_type": "email_analysis",
        "raw_reference": f"raw:{eid}",
        "finding": "Suspicious email",
        "timestamp": "2026-11-01T09:00:00Z",
        "confidence": 85,
        "provenance": {"ioc_value": "evil.test"},
    }


# ---------- create evidence ----------
def test_create_evidence():
    client = _client()
    case_id = _create_case(client)
    response = client.post(
        "/api/v1/evidence", json=_evidence_payload(case_id)
    )
    assert response.status_code == 201
    data = response.json()
    assert data["evidence_id"] == "ev-001"
    assert data["case_id"] == case_id


def test_create_evidence_duplicate_returns_409():
    client = _client()
    case_id = _create_case(client)
    client.post("/api/v1/evidence", json=_evidence_payload(case_id))
    response = client.post(
        "/api/v1/evidence", json=_evidence_payload(case_id)
    )
    assert response.status_code == 409


def test_create_evidence_invalid_confidence_returns_422():
    client = _client()
    case_id = _create_case(client)
    payload = _evidence_payload(case_id)
    payload["confidence"] = 150
    response = client.post("/api/v1/evidence", json=payload)
    assert response.status_code == 422


def test_create_evidence_invalid_type_returns_422():
    client = _client()
    case_id = _create_case(client)
    payload = _evidence_payload(case_id)
    payload["evidence_type"] = "invalid_type"
    response = client.post("/api/v1/evidence", json=payload)
    assert response.status_code == 422


# ---------- get evidence ----------
def test_get_evidence():
    client = _client()
    case_id = _create_case(client)
    client.post("/api/v1/evidence", json=_evidence_payload(case_id))
    response = client.get("/api/v1/evidence/ev-001")
    assert response.status_code == 200
    assert response.json()["evidence_id"] == "ev-001"


def test_get_missing_evidence_returns_404():
    client = _client()
    response = client.get("/api/v1/evidence/ev-999")
    assert response.status_code == 404


# ---------- list evidence by case ----------
def test_list_evidence_by_case():
    client = _client()
    case_id = _create_case(client)
    client.post("/api/v1/evidence", json=_evidence_payload(case_id, "ev-001"))
    client.post("/api/v1/evidence", json=_evidence_payload(case_id, "ev-002"))
    response = client.get(f"/api/v1/evidence?case_id={case_id}")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2


# ---------- link evidence to case ----------
def test_link_evidence_to_case():
    client = _client()
    case_id = _create_case(client)
    client.post("/api/v1/evidence", json=_evidence_payload(case_id))
    response = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        json={"evidence_id": "ev-001", "by": "analyst@example.com"},
    )
    assert response.status_code == 200
    assert "ev-001" in response.json()["evidence_ids"]


def test_link_missing_evidence_returns_404():
    client = _client()
    case_id = _create_case(client)
    response = client.post(
        f"/api/v1/cases/{case_id}/evidence",
        json={"evidence_id": "ev-999", "by": "a@x.com"},
    )
    assert response.status_code == 404


def test_link_missing_case_returns_404():
    client = _client()
    response = client.post(
        "/api/v1/cases/CASE-2099-9999/evidence",
        json={"evidence_id": "ev-001", "by": "a@x.com"},
    )
    assert response.status_code == 404


# ---------- unlink ----------
def test_unlink_evidence_from_case():
    client = _client()
    case_id = _create_case(client)
    client.post("/api/v1/evidence", json=_evidence_payload(case_id))
    client.post(
        f"/api/v1/cases/{case_id}/evidence",
        json={"evidence_id": "ev-001", "by": "a@x.com"},
    )
    response = client.delete(
        f"/api/v1/cases/{case_id}/evidence/ev-001?by=a@x.com"
    )
    assert response.status_code == 200
    assert "ev-001" not in response.json()["evidence_ids"]


def test_unlink_missing_is_noop():
    client = _client()
    case_id = _create_case(client)
    response = client.delete(
        f"/api/v1/cases/{case_id}/evidence/ev-999?by=a@x.com"
    )
    # idempotent - returns 200 with unchanged case
    assert response.status_code == 200
