"""Phase 9b - Case API endpoints tests (test-first)."""



# ---------- create ----------
def test_create_case(api_client):
    client = api_client
    response = client.post(
        "/api/v1/cases",
        json={
            "title": "Suspicious phishing",
            "priority": "high",
            "created_by": "analyst@example.com",
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["case_id"].startswith("CASE-")
    assert data["title"] == "Suspicious phishing"
    assert data["status"] == "new"
    assert data["priority"] == "high"


def test_create_case_missing_title_returns_422(api_client):
    client = api_client
    response = client.post(
        "/api/v1/cases",
        json={"priority": "high", "created_by": "analyst@example.com"},
    )
    assert response.status_code == 422


def test_create_case_invalid_priority_returns_422(api_client):
    client = api_client
    response = client.post(
        "/api/v1/cases",
        json={
            "title": "x",
            "priority": "invalid",
            "created_by": "analyst@example.com",
        },
    )
    assert response.status_code == 422


# ---------- list ----------
def test_list_cases_empty(api_client):
    client = api_client
    response = client.get("/api/v1/cases")
    assert response.status_code == 200
    assert response.json() == []


def test_list_cases_after_create(api_client):
    client = api_client
    client.post(
        "/api/v1/cases",
        json={"title": "One", "priority": "low", "created_by": "a@x.com"},
    )
    client.post(
        "/api/v1/cases",
        json={"title": "Two", "priority": "high", "created_by": "a@x.com"},
    )
    response = client.get("/api/v1/cases")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 2


def test_list_cases_filter_by_status(api_client):
    client = api_client
    r = client.post(
        "/api/v1/cases",
        json={"title": "One", "priority": "low", "created_by": "a@x.com"},
    )
    case_id = r.json()["case_id"]
    client.post(
        f"/api/v1/cases/{case_id}/transition",
        json={"to": "investigating", "by": "a@x.com"},
    )

    response = client.get("/api/v1/cases?status=new")
    assert response.status_code == 200
    assert len(response.json()) == 0

    response = client.get("/api/v1/cases?status=investigating")
    assert response.status_code == 200
    assert len(response.json()) == 1


# ---------- get ----------
def test_get_case_by_id(api_client):
    client = api_client
    r = client.post(
        "/api/v1/cases",
        json={"title": "One", "priority": "medium", "created_by": "a@x.com"},
    )
    case_id = r.json()["case_id"]
    response = client.get(f"/api/v1/cases/{case_id}")
    assert response.status_code == 200
    assert response.json()["case_id"] == case_id


def test_get_missing_case_returns_404(api_client):
    client = api_client
    response = client.get("/api/v1/cases/CASE-2099-9999")
    assert response.status_code == 404


# ---------- transition ----------
def test_transition_case(api_client):
    client = api_client
    r = client.post(
        "/api/v1/cases",
        json={"title": "One", "priority": "medium", "created_by": "a@x.com"},
    )
    case_id = r.json()["case_id"]
    response = client.post(
        f"/api/v1/cases/{case_id}/transition",
        json={"to": "investigating", "by": "analyst@example.com"},
    )
    assert response.status_code == 200
    assert response.json()["status"] == "investigating"


def test_transition_invalid_returns_400(api_client):
    client = api_client
    r = client.post(
        "/api/v1/cases",
        json={"title": "One", "priority": "medium", "created_by": "a@x.com"},
    )
    case_id = r.json()["case_id"]
    response = client.post(
        f"/api/v1/cases/{case_id}/transition",
        json={"to": "closed", "by": "a@x.com"},  # NEW -> CLOSED invalid
    )
    assert response.status_code == 400


def test_transition_missing_case_returns_404(api_client):
    client = api_client
    response = client.post(
        "/api/v1/cases/CASE-2099-9999/transition",
        json={"to": "investigating", "by": "a@x.com"},
    )
    assert response.status_code == 404


# ---------- assign ----------
def test_assign_analyst(api_client):
    client = api_client
    r = client.post(
        "/api/v1/cases",
        json={"title": "One", "priority": "medium", "created_by": "a@x.com"},
    )
    case_id = r.json()["case_id"]
    response = client.post(
        f"/api/v1/cases/{case_id}/assign",
        json={"assignee": "alice@example.com", "by": "lead@example.com"},
    )
    assert response.status_code == 200
    assert response.json()["assignee"] == "alice@example.com"


# ---------- notes ----------
def test_add_note(api_client):
    client = api_client
    r = client.post(
        "/api/v1/cases",
        json={"title": "One", "priority": "medium", "created_by": "a@x.com"},
    )
    case_id = r.json()["case_id"]
    response = client.post(
        f"/api/v1/cases/{case_id}/notes",
        json={"note": "Investigating", "by": "a@x.com"},
    )
    assert response.status_code == 200
    assert len(response.json()["notes"]) == 1
    assert response.json()["notes"][0]["text"] == "Investigating"


# ---------- decisions ----------
def test_add_decision(api_client):
    client = api_client
    r = client.post(
        "/api/v1/cases",
        json={"title": "One", "priority": "medium", "created_by": "a@x.com"},
    )
    case_id = r.json()["case_id"]
    response = client.post(
        f"/api/v1/cases/{case_id}/decisions",
        json={
            "outcome": "escalate",
            "rationale": "Confirmed malware",
            "by": "a@x.com",
        },
    )
    assert response.status_code == 200
    assert len(response.json()["decisions"]) == 1
    assert response.json()["decisions"][0]["outcome"] == "escalate"


def test_add_decision_missing_rationale_returns_422(api_client):
    client = api_client
    r = client.post(
        "/api/v1/cases",
        json={"title": "One", "priority": "medium", "created_by": "a@x.com"},
    )
    case_id = r.json()["case_id"]
    response = client.post(
        f"/api/v1/cases/{case_id}/decisions",
        json={"outcome": "escalate", "rationale": "", "by": "a@x.com"},
    )
    assert response.status_code == 422
