"""Phase 9d - Investigation API endpoints tests (test-first)."""
from fastapi.testclient import TestClient

from app.main import create_app


def _client() -> TestClient:
    return TestClient(create_app())


def _create_case(client: TestClient) -> str:
    r = client.post(
        "/api/v1/cases",
        json={"title": "T", "priority": "medium", "created_by": "a@x.com"},
    )
    assert r.status_code == 201
    return r.json()["case_id"]


def _add_evidence(client: TestClient, case_id: str, eid: str) -> None:
    r = client.post(
        "/api/v1/evidence",
        json={
            "evidence_id": eid,
            "case_id": case_id,
            "source_module": "huntscope",
            "evidence_type": "hunt_finding",
            "raw_reference": f"raw:{eid}",
            "finding": "Encoded PowerShell detected",
            "timestamp": "2026-11-01T09:00:00Z",
            "confidence": 80,
            "provenance": {
                "rule_id": "process_powershell_encoded",
                "ioc_value": "203.0.113.10",
            },
        },
    )
    assert r.status_code == 201


# ---------- investigate ----------
def test_investigate_empty_evidence_ids():
    client = _client()
    response = client.post("/api/v1/investigate", json={"evidence_ids": []})
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["evidence_count"] == 0
    assert data["summary"]["risk_classification"] == "insufficient_data"


def test_investigate_with_evidence():
    client = _client()
    case_id = _create_case(client)
    _add_evidence(client, case_id, "ev-001")
    response = client.post(
        "/api/v1/investigate",
        json={"evidence_ids": ["ev-001"]},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["summary"]["evidence_count"] == 1
    assert data["summary"]["mitre_technique_count"] >= 1


def test_investigate_missing_evidence_returns_404():
    client = _client()
    response = client.post(
        "/api/v1/investigate",
        json={"evidence_ids": ["ev-999"]},
    )
    assert response.status_code == 404


def test_investigate_report_has_mitre():
    client = _client()
    case_id = _create_case(client)
    _add_evidence(client, case_id, "ev-001")
    response = client.post(
        "/api/v1/investigate",
        json={"evidence_ids": ["ev-001"]},
    )
    data = response.json()
    ids = {m["technique_id"] for m in data["mitre_mappings"]}
    assert "T1059.001" in ids


def test_investigate_report_has_timeline():
    client = _client()
    case_id = _create_case(client)
    _add_evidence(client, case_id, "ev-001")
    response = client.post(
        "/api/v1/investigate",
        json={"evidence_ids": ["ev-001"]},
    )
    data = response.json()
    assert data["timeline"]["event_count"] >= 1


# ---------- case report ----------
def test_case_report_missing_case_returns_404():
    client = _client()
    response = client.get("/api/v1/cases/CASE-2099-9999/report")
    assert response.status_code == 404


def test_case_report_returns_full_investigation():
    client = _client()
    case_id = _create_case(client)
    _add_evidence(client, case_id, "ev-001")
    response = client.get(f"/api/v1/cases/{case_id}/report")
    assert response.status_code == 200
    data = response.json()
    assert data["case"]["case_id"] == case_id
    assert data["investigation"]["summary"]["evidence_count"] == 1


def test_case_report_links_evidence():
    client = _client()
    case_id = _create_case(client)
    _add_evidence(client, case_id, "ev-001")
    response = client.get(f"/api/v1/cases/{case_id}/report")
    data = response.json()
    assert "ev-001" in data["case"]["evidence_ids"]


def test_case_report_transitions_status():
    client = _client()
    case_id = _create_case(client)
    _add_evidence(client, case_id, "ev-001")
    response = client.get(f"/api/v1/cases/{case_id}/report")
    data = response.json()
    assert data["case"]["status"] == "investigating"


def test_case_report_empty_case_stays_new():
    client = _client()
    case_id = _create_case(client)
    response = client.get(f"/api/v1/cases/{case_id}/report")
    assert response.status_code == 200
    data = response.json()
    assert data["case"]["status"] == "new"
    assert data["investigation"]["summary"]["evidence_count"] == 0
