"""Phase 9e - Analysis API endpoints tests (test-first)."""
import base64
from pathlib import Path

from fastapi.testclient import TestClient

from app.main import create_app

_FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"


def _client() -> TestClient:
    return TestClient(create_app())


# ---------- analyze IOC ----------
def test_analyze_ioc_valid():
    client = _client()
    response = client.post(
        "/api/v1/analyze/ioc",
        json={"indicator": "203.0.113.10", "ioc_type": "ipv4"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["indicator"] == "203.0.113.10"
    assert data["ioc_type"] == "ipv4"
    assert "enrichment" in data


def test_analyze_ioc_invalid_type_returns_422():
    client = _client()
    response = client.post(
        "/api/v1/analyze/ioc",
        json={"indicator": "x", "ioc_type": "invalid"},
    )
    assert response.status_code == 422


def test_analyze_ioc_empty_indicator_returns_422():
    client = _client()
    response = client.post(
        "/api/v1/analyze/ioc",
        json={"indicator": "", "ioc_type": "ipv4"},
    )
    assert response.status_code == 422


# ---------- analyze email ----------
def test_analyze_email_valid():
    email_text = (_FIXTURES / "emails" / "phishing_simulation.eml").read_text()
    client = _client()
    response = client.post(
        "/api/v1/analyze/email",
        json={"email_text": email_text},
    )
    assert response.status_code == 200
    data = response.json()
    assert "parsed" in data
    assert "iocs" in data
    assert "auth" in data
    assert "findings" in data
    assert data["parsed"]["from_domain"] == "spoofed-sender.test"


def test_analyze_email_empty_returns_422():
    client = _client()
    response = client.post("/api/v1/analyze/email", json={"email_text": ""})
    assert response.status_code == 422


# ---------- analyze file ----------
def test_analyze_file_valid():
    # Use sample PDF (safe fixture)
    pdf_bytes = (_FIXTURES / "malware" / "sample.pdf").read_bytes()
    encoded = base64.b64encode(pdf_bytes).decode()
    client = _client()
    response = client.post(
        "/api/v1/analyze/file",
        json={"content_b64": encoded, "filename": "sample.pdf"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["identification"]["magic"] == "pdf"
    assert "metadata" in data
    assert "yara" in data
    assert "classification" in data


def test_analyze_file_invalid_base64_returns_422():
    client = _client()
    response = client.post(
        "/api/v1/analyze/file",
        json={"content_b64": "not-valid-b64!", "filename": "x.bin"},
    )
    assert response.status_code == 422


# ---------- hunt logs ----------
def test_hunt_logs_valid():
    logs_text = (_FIXTURES / "logs" / "sysmon_process.json").read_text()
    client = _client()
    response = client.post(
        "/api/v1/hunt/logs",
        json={"logs_text": logs_text, "iocs": []},
    )
    assert response.status_code == 200
    data = response.json()
    assert "report" in data
    assert data["report"]["summary"]["event_count"] == 3


def test_hunt_logs_with_iocs():
    logs_text = (_FIXTURES / "logs" / "sysmon_network.json").read_text()
    client = _client()
    response = client.post(
        "/api/v1/hunt/logs",
        json={"logs_text": logs_text, "iocs": ["203.0.113.10"]},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["report"]["summary"]["ioc_match_count"] >= 1


def test_hunt_logs_empty_returns_422():
    client = _client()
    response = client.post("/api/v1/hunt/logs", json={"logs_text": ""})
    assert response.status_code == 422
