"""Phase 9 integration - end-to-end API pipeline with auth.

Simulates: an authenticated client creates a case, adds evidence, opens
investigation, records a decision, closes the case, and verifies auth
is enforced.

No network. All HTTP is via TestClient.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import create_app

API_KEY = "test-secret-key"


@pytest.fixture
def client_with_auth() -> TestClient:
    """Return a TestClient whose app has API key auth enabled."""
    import app.main as main_module

    original = main_module.settings
    main_module.settings = original.model_copy(
        update={"vectraid_api_key": API_KEY}
    )
    try:
        app = create_app()
    finally:
        main_module.settings = original

    client = TestClient(app)
    client.headers.update({"X-API-Key": API_KEY})
    return client


@pytest.fixture
def client_no_auth() -> TestClient:
    """Client with no API key configured (dev mode)."""
    return TestClient(create_app())


# ---------- full lifecycle via HTTP ----------
def test_full_lifecycle_via_api(client_with_auth: TestClient):
    # 1. Create a case
    r = client_with_auth.post(
        "/api/v1/cases",
        json={
            "title": "Phishing + malware incident",
            "priority": "high",
            "created_by": "analyst@example.com",
        },
    )
    assert r.status_code == 201
    case_id = r.json()["case_id"]
    assert r.json()["status"] == "new"

    # 2. Add two evidence items
    for eid, module, etype, ts, conf in [
        ("ev-001", "phishtrace", "email_analysis", "2026-11-01T08:00:00Z", 85),
        ("ev-002", "huntscope", "hunt_finding", "2026-11-01T09:00:00Z", 80),
    ]:
        r = client_with_auth.post(
            "/api/v1/evidence",
            json={
                "evidence_id": eid,
                "case_id": case_id,
                "source_module": module,
                "evidence_type": etype,
                "raw_reference": f"raw:{eid}",
                "finding": f"{module} finding",
                "timestamp": ts,
                "confidence": conf,
                "provenance": {
                    "ioc_value": "203.0.113.10",
                    "rule_id": "process_powershell_encoded"
                    if module == "huntscope"
                    else None,
                },
            },
        )
        assert r.status_code == 201, r.text

    # 3. Open investigation via report endpoint
    r = client_with_auth.get(f"/api/v1/cases/{case_id}/report")
    assert r.status_code == 200
    report = r.json()
    assert report["case"]["status"] == "investigating"
    assert set(report["case"]["evidence_ids"]) == {"ev-001", "ev-002"}
    assert report["investigation"]["summary"]["evidence_count"] == 2
    assert report["investigation"]["summary"]["mitre_technique_count"] >= 1

    # 4. Record analyst decision
    r = client_with_auth.post(
        f"/api/v1/cases/{case_id}/decisions",
        json={
            "outcome": "escalate",
            "rationale": "Confirmed malicious indicators",
            "by": "analyst@example.com",
        },
    )
    assert r.status_code == 200
    assert len(r.json()["decisions"]) == 1

    # 5. Transition to resolved, then closed
    r = client_with_auth.post(
        f"/api/v1/cases/{case_id}/transition",
        json={"to": "resolved", "by": "analyst@example.com"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "resolved"

    r = client_with_auth.post(
        f"/api/v1/cases/{case_id}/transition",
        json={"to": "closed", "by": "lead@example.com"},
    )
    assert r.status_code == 200
    assert r.json()["status"] == "closed"

    # 6. Verify filter by status
    r = client_with_auth.get("/api/v1/cases?status=closed")
    assert r.status_code == 200
    closed = r.json()
    assert len(closed) == 1
    assert closed[0]["case_id"] == case_id


# ---------- auth enforcement ----------
def test_auth_enforced_on_all_v1_endpoints(client_with_auth: TestClient):
    # Remove the auth header to test rejection
    client_with_auth.headers.pop("X-API-Key", None)

    r = client_with_auth.get("/api/v1/cases")
    assert r.status_code == 401

    r = client_with_auth.post(
        "/api/v1/analyze/ioc",
        json={"indicator": "x", "ioc_type": "ipv4"},
    )
    assert r.status_code == 401


def test_health_open_without_auth(client_with_auth: TestClient):
    client_with_auth.headers.pop("X-API-Key", None)
    r = client_with_auth.get("/health")
    assert r.status_code == 200


# ---------- stateless investigate ----------
def test_stateless_investigate_via_api(client_with_auth: TestClient):
    case_id = client_with_auth.post(
        "/api/v1/cases",
        json={"title": "X", "priority": "medium", "created_by": "a@x.com"},
    ).json()["case_id"]

    client_with_auth.post(
        "/api/v1/evidence",
        json={
            "evidence_id": "ev-001",
            "case_id": case_id,
            "source_module": "huntscope",
            "evidence_type": "hunt_finding",
            "raw_reference": "raw:001",
            "finding": "powershell",
            "timestamp": "2026-11-01T09:00:00Z",
            "confidence": 80,
            "provenance": {
                "rule_id": "process_powershell_encoded",
                "ioc_value": "x.test",
            },
        },
    )

    r = client_with_auth.post(
        "/api/v1/investigate",
        json={"evidence_ids": ["ev-001"]},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["summary"]["evidence_count"] == 1
    ids = {m["technique_id"] for m in data["mitre_mappings"]}
    assert "T1059.001" in ids


# ---------- analyze ioc ----------
def test_analyze_ioc_via_api(client_with_auth: TestClient):
    r = client_with_auth.post(
        "/api/v1/analyze/ioc",
        json={"indicator": "203.0.113.10", "ioc_type": "ipv4"},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["indicator"] == "203.0.113.10"
    # Enrichment should include all three adapters
    providers = {e["provider"] for e in data["enrichment"]}
    assert providers == {"virustotal", "abuseipdb", "otx"}


# ---------- audit trail is preserved ----------
def test_audit_trail_preserved(client_with_auth: TestClient):
    case_id = client_with_auth.post(
        "/api/v1/cases",
        json={"title": "X", "priority": "medium", "created_by": "a@x.com"},
    ).json()["case_id"]

    client_with_auth.post(
        f"/api/v1/cases/{case_id}/transition",
        json={"to": "investigating", "by": "analyst@example.com"},
    )

    r = client_with_auth.get(f"/api/v1/cases/{case_id}")
    data = r.json()
    actions = [e["action"] for e in data["history"]]
    assert actions[0] == "created"
    assert "status_changed" in actions
