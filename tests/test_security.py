"""Integration Tests for Security Controls, Defense-in-Depth Headers, and Limiting."""
import pytest


def test_defense_in_depth_security_headers(client):
    """Verify presence of OWASP-recommended HTTP security headers on responses."""
    resp = client.get("/login")
    headers = resp.headers

    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-XSS-Protection") == "1; mode=block"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

    # Verify Content Security Policy (CSP)
    csp = headers.get("Content-Security-Policy", "")
    assert "default-src 'self'" in csp
    assert "https://www.gstatic.com" in csp
    assert "https://apis.google.com" in csp
    assert "https://accounts.google.com" in csp


def test_permissions_policy_header(client):
    """Verify modern Permissions-Policy header disables sensitive hardware features."""
    resp = client.get("/login")
    perm = resp.headers.get("Permissions-Policy", "")
    assert "camera=()" in perm
    assert "microphone=()" in perm
    assert "geolocation=()" in perm


def test_session_cookie_security_flags(client):
    """Verify that session cookies are configured with HttpOnly and SameSite flags."""
    resp = client.get("/login")
    cookies = resp.headers.getlist("Set-Cookie")
    for cookie in cookies:
        if "session=" in cookie:
            assert "HttpOnly" in cookie
            assert "SameSite=Lax" in cookie or "SameSite=Strict" in cookie


# ---------------------------------------------------------------- SQL & NoSQL Injection Protection Tests
def test_sql_injection_detection_unit():
    """Unit tests for the security module's SQLi pattern matcher and search sanitizer."""
    from security import is_sql_injection, sanitize_search_query

    malicious_inputs = [
        "' OR '1'='1",
        "' or 1=1--",
        "admin'--",
        "' UNION SELECT 1, 2, 3--",
        "1; DROP TABLE users;--",
        "; DELETE FROM log_records WHERE 1=1;",
        "sleep(5)",
        "waitfor delay '0:0:5'",
        "' AND 1=1",
        "' or true",
        "' /* comment */",
    ]

    for attack in malicious_inputs:
        is_sqli, matched = is_sql_injection(attack)
        assert is_sqli is True, f"Failed to detect SQL injection payload: {attack}"
        assert matched is not None

    benign_inputs = [
        "192.168.1.100",
        "testadmin@threatwatch.local",
        "TestPassword123!",
        "http",
        "tcp",
        "Normal Web Traffic",
        "SYN Flood",
        "suspicious",
        "page 1 of 5",
        "sort by timestamp",
    ]

    for safe in benign_inputs:
        is_sqli, _ = is_sql_injection(safe)
        assert is_sqli is False, f"False positive on safe input: {safe}"

    # Verify search sanitization escapes regex metacharacters
    raw_query = "192.168.*.[0-9]+"
    sanitized = sanitize_search_query(raw_query)
    assert r"\*" in sanitized
    assert r"\[" in sanitized


def test_sql_injection_query_parameter_blocked(client):
    """Verify GET requests with SQL injection in query parameters are blocked with HTTP 400."""
    # API query parameter with SQLi
    res_api = client.get("/api/logs?q=' OR 1=1--")
    assert res_api.status_code == 400
    data_api = res_api.get_json()
    assert "Potential SQL injection detected" in data_api.get("error", "")

    # Web route query parameter with SQLi
    res_web = client.get("/logs?q=UNION SELECT 1,2,3--")
    assert res_web.status_code == 400
    assert b"Potential SQL injection detected" in res_web.data

    # Alert severity query parameter with stacked query SQLi
    res_alert = client.get("/api/alerts?status='; DROP TABLE logs;--")
    assert res_alert.status_code == 400
    assert "Potential SQL injection detected" in res_alert.get_json().get("error", "")


def test_sql_injection_form_payload_blocked(client):
    """Verify POST form submissions containing SQL injection are intercepted and blocked."""
    # Attempt auth bypass SQLi in username / email form field
    login_page = client.get("/login")
    from tests.test_auth import _extract_csrf
    csrf = _extract_csrf(login_page.get_data(as_text=True))

    res = client.post(
        "/login",
        data={
            "username": "admin' OR '1'='1",
            "password": "RandomPassword!123",
            "_csrf": csrf,
        },
    )
    assert res.status_code == 400
    assert b"Potential SQL injection detected" in res.data


def test_sql_injection_json_payload_blocked(client):
    """Verify JSON payloads with SQL injection or NoSQL operator injection are blocked."""
    # Attempt SQLi inside JSON body
    res_sqli = client.post(
        "/api/predict",
        json={"service": "' UNION SELECT * FROM users--", "protocol_type": "tcp"},
    )
    assert res_sqli.status_code == 400
    assert "Potential SQL injection detected" in res_sqli.get_json().get("error", "")

    # Attempt NoSQL operator injection in JSON body
    res_nosql = client.post(
        "/api/predict",
        json={"$gt": "", "protocol_type": "tcp"},
    )
    assert res_nosql.status_code == 400
    assert "Potential SQL injection detected" in res_nosql.get_json().get("error", "")


def test_benign_search_and_auth_allowed(client):
    """Verify legitimate search terms and form inputs are not falsely blocked."""
    # Clean API search query
    res = client.get("/api/logs?q=192.168.1.1")
    # Returns 401 unauthenticated or 200/302, but MUST NOT be 400 (not flagged as SQLi)
    assert res.status_code in (200, 302, 401)
    assert res.status_code != 400

    # Clean web search
    res_web = client.get("/logs?q=http")
    assert res_web.status_code in (200, 302)
    assert res_web.status_code != 400
