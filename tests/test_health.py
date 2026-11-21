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
    """Verify OpenAPI specification JSON endpoint returns valid metadata."""
    resp = client.get("/apispec_1.json")
    assert resp.status_code == 200
    spec = resp.get_json()
    assert isinstance(spec, dict)
    assert "swagger" in spec or "openapi" in spec
    assert "paths" in spec
    assert "/api/classify" in spec["paths"]
    assert "/api/predict" in spec["paths"]
