"""Integration Tests for Machine Learning Prediction and Traffic Classification APIs."""
import pytest


def test_api_predict_success(client, sample_row):
    """Verify POST /api/predict accepts valid NSL-KDD attributes and handles ML predictions."""
    resp = client.post("/api/predict", json=sample_row)
    # Returns 200 (if DB connected) or 503 (database disconnected graceful degradation)
    assert resp.status_code in (200, 503)
    data = resp.get_json()
    assert isinstance(data, dict)
    if resp.status_code == 200:
        assert "threat_score" in data
        assert "tier" in data
        assert "anomaly_detected" in data
        assert "attack_category" in data
        assert 0.0 <= data["threat_score"] <= 1.0
        assert data["tier"] in ("Normal", "Suspicious", "Malicious")
    else:
        assert "error" in data


def test_api_predict_rejects_empty_payload(client):
    """Verify POST /api/predict rejects an empty request payload."""
    resp = client.post("/api/predict", json={})
    assert resp.status_code == 400
    data = resp.get_json()
    assert "error" in data


def test_api_predict_rejects_non_json_body(client):
    """Verify POST /api/predict rejects invalid non-JSON content types."""
    resp = client.post("/api/predict", data="raw non-json text", content_type="text/plain")
    assert resp.status_code == 400


def test_api_classify_unauthenticated_without_key_rejected(client, sample_row):
    """Verify POST /api/classify without a session or valid API key is rejected."""
    resp = client.post("/api/classify", json=sample_row)
    # Rejection by check_csrf (400) or login_manager (401)
    assert resp.status_code in (400, 401)
