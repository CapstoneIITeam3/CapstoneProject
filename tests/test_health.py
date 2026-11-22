"""Unit and Integration Tests for ThreatWatch Health & API Documentation."""
import pytest


def test_health_endpoint_schema(client):
    """Verify /api/health returns a well-formed JSON response with all expected keys."""
    resp = client.get("/api/health")
    assert resp.status_code in (200, 503)
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "status" in data
    assert "detector" in data
    assert "database" in data
    assert "service" in data
    assert data["status"] in ("ok", "degraded")


def test_health_detector_structure(client):
    """Verify detector metadata structure reported by the health endpoint."""
    resp = client.get("/api/health")
    data = resp.get_json()
    detector_info = data["detector"]
    assert "mode" in detector_info
    assert detector_info["mode"] in ("team ML (RF + IF)", "heuristic fallback")
    assert "isolation_forest" in detector_info
    assert "preprocessor" in detector_info


def test_swagger_ui_endpoint(client):
    """Verify Flasgger Swagger UI /apidocs/ is accessible and renders HTTP 200."""
    resp = client.get("/apidocs/")
    assert resp.status_code == 200
    assert b"Swagger UI" in resp.data or b"flasgger" in resp.data or b"ThreatWatch" in resp.data


def test_swagger_spec_json(client):
    """Verify OpenAPI specification JSON endpoint returns valid metadata, all 11 paths, and securityDefinitions."""
    resp = client.get("/apispec_1.json")
    assert resp.status_code == 200
    spec = resp.get_json()
    assert isinstance(spec, dict)
    assert "swagger" in spec or "openapi" in spec
    assert "paths" in spec

    # Verify all 11 REST endpoints are documented
    expected_paths = [
        "/api/health",
        "/api/auth/firebase-login",
        "/api/classify",
        "/api/predict",
        "/api/stats",
        "/api/logs",
        "/api/logs/{log_id}",
        "/api/logs/export.csv",
        "/api/alerts",
        "/api/alerts/{alert_id}/{action}",
        "/api/alerts/acknowledge-all",
    ]
    for path in expected_paths:
        assert path in spec["paths"], f"Endpoint {path} missing from Swagger specification"

    # Verify securityDefinitions for multi-scheme authentication
    assert "securityDefinitions" in spec
    sec_defs = spec["securityDefinitions"]
    assert "ApiKeyAuth" in sec_defs
    assert "Bearer" in sec_defs
    assert "BasicAuth" in sec_defs
    assert "CsrfToken" in sec_defs


def test_api_key_header_authentication(client, monkeypatch):
    """Verify X-API-Key header authenticates access to protected API endpoints."""
    monkeypatch.setenv("INGEST_API_KEY", "test-secret-sensor-api-key")
    resp = client.get("/api/stats", headers={"X-API-Key": "test-secret-sensor-api-key"})
    assert resp.status_code == 200
    data = resp.get_json()
    assert isinstance(data, dict)
    assert "total" in data and "threats" in data


def test_basic_auth_header_authentication(client):
    """Verify Authorization: Basic header authenticates access to protected API endpoints."""
    import base64
    from models import create_user, users_col

    test_user = "basic_auth_tester"
    test_email = "basic_tester@threatwatch.local"
    test_pass = "TestBasicAuthPass123!"

    users_col.delete_many({"email": test_email})
    create_user(username=test_user, password=test_pass, email=test_email, role="admin")

    try:
        b64_creds = base64.b64encode(f"{test_email}:{test_pass}".encode()).decode()
        resp = client.get("/api/stats", headers={"Authorization": f"Basic {b64_creds}"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert isinstance(data, dict)
        assert "total" in data and "threats" in data
    finally:
        users_col.delete_many({"email": test_email})
