"""Unit Tests for Threat Detection Engine & Input Validation."""
import pytest
from detector import ValidationError, detector, tier_for, validate


def test_detector_initialization():
    """Verify that detector loads and reports its active detection mode."""
    state = detector.load()
    assert isinstance(state, dict)
    assert "mode" in state
    assert state["mode"] in ("team ML (RF + IF)", "heuristic fallback")


def test_detector_validate_clean_sample(sample_row):
    """Verify input validation accepts clean, well-formed NSL-KDD traffic attributes."""
    cleaned = validate(sample_row)
    assert isinstance(cleaned, dict)
    assert cleaned["protocol_type"] == "tcp"
    assert cleaned["service"] == "http"
    assert cleaned["flag"] == "SF"
    assert cleaned["src_bytes"] == 181
    assert cleaned["dst_bytes"] == 5450


def test_detector_validate_rejects_nan(sample_row):
    """Verify input validation rejects NaN values to prevent model poisoning."""
    bad_sample = dict(sample_row)
    bad_sample["duration"] = float("nan")
    with pytest.raises(ValidationError, match="cannot be NaN or Infinite"):
        validate(bad_sample)


def test_detector_validate_rejects_infinity(sample_row):
    """Verify input validation rejects infinite values."""
    bad_sample = dict(sample_row)
    bad_sample["duration"] = float("inf")
    with pytest.raises(ValidationError, match="cannot be NaN or Infinite"):
        validate(bad_sample)


def test_detector_validate_rejects_oversized_string(sample_row):
    """Verify input validation rejects excessively long strings (buffer overflow mitigation)."""
    bad_sample = dict(sample_row)
    bad_sample["service"] = "A" * 100
    with pytest.raises(ValidationError, match="exceeds maximum permitted length"):
        validate(bad_sample)


def test_detector_validate_rejects_null_byte(sample_row):
    """Verify input validation sanitizes or strips null bytes in string fields."""
    bad_sample = dict(sample_row)
    bad_sample["service"] = "http\x00extra"
    cleaned = validate(bad_sample)
    assert "\x00" not in cleaned["service"]


def test_tier_for_threshold_classification():
    """Verify threat tier classification mapping based on configurable thresholds."""
    sus_t = 0.20
    mal_t = 0.50
    assert tier_for(0.0, sus_t, mal_t) == "Normal"
    assert tier_for(0.15, sus_t, mal_t) == "Normal"
    assert tier_for(0.20, sus_t, mal_t) == "Suspicious"
    assert tier_for(0.35, sus_t, mal_t) == "Suspicious"
    assert tier_for(0.50, sus_t, mal_t) == "Malicious"
    assert tier_for(0.95, sus_t, mal_t) == "Malicious"
    assert tier_for(1.0, sus_t, mal_t) == "Malicious"
    # Anomaly flag triggers Suspicious even when score is below suspicious_t
    assert tier_for(0.05, sus_t, mal_t, anomaly_flag=True) == "Suspicious"


def test_detector_score_output_schema(sample_row):
    """Verify detector.score() output schema and property constraints."""
    result = detector.score(sample_row)
    assert isinstance(result, dict)
    assert "threat_score" in result
    assert "rf_probability" in result
    assert "anomaly_score" in result
    assert "anomaly_flag" in result
    assert "explanation" in result
    assert "model_version" in result

    assert 0.0 <= result["threat_score"] <= 1.0
    assert isinstance(result["anomaly_flag"], bool)
    assert isinstance(result["explanation"], list)
