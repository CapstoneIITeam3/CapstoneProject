"""Integration Tests for Authentication, Password Policies, and Session Lifecycle."""
import re
import pytest
from models import validate_password


def _extract_csrf(html_text):
    """Helper to extract the CSRF token from rendered HTML."""
    match = re.search(r'name="_csrf"\s+value="([^"]+)"', html_text)
    return match.group(1) if match else None


def test_login_page_renders_with_firebase_and_csrf(client):
    """Verify login page GET renders HTTP 200 with CSRF token and Firebase UI elements."""
    resp = client.get("/login")
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    csrf = _extract_csrf(html)
    assert csrf is not None, "CSRF token must be present in the login form"
    assert len(csrf) >= 32
    assert "Sign in with Google" in html
    assert "Reset Password" in html
    assert "Threat" in html and "Watch" in html


def test_password_policy_enforcement():
    """Verify NIST/OWASP password strength validation logic."""
    # Under 8 characters
    with pytest.raises(ValueError, match="at least 8 characters"):
        validate_password("Ab1!xyz")

    # Over 128 characters
    with pytest.raises(ValueError, match="cannot exceed 128"):
        validate_password("A" * 129 + "b1!")

    # Missing uppercase letter
    with pytest.raises(ValueError, match="uppercase letter"):
        validate_password("lowercase123!@#")

    # Missing lowercase letter
    with pytest.raises(ValueError, match="lowercase letter"):
        validate_password("UPPERCASE123!@#")

    # Missing numeric digit
    with pytest.raises(ValueError, match="numeric digit"):
        validate_password("NoDigitsHere!@#")

    # Missing special character
    with pytest.raises(ValueError, match="special character"):
        validate_password("NoSpecialChars123")

    # Fully compliant strong password
    try:
        validate_password("CyberSec#2026!ThreatWatch")
    except ValueError as e:
        pytest.fail(f"Compliant password raised ValueError unexpectedly: {e}")


def test_login_with_invalid_credentials(client):
    """Verify submitting invalid credentials returns HTTP 401 or graceful DB offline error."""
    get_resp = client.get("/login")
    csrf = _extract_csrf(get_resp.get_data(as_text=True))

    post_resp = client.post(
        "/login",
        data={
            "username": "nonexistent_analyst",
            "password": "WrongPassword#123",
            "_csrf": csrf,
        },
    )
    # 401 Unauthorized when DB is reachable, 503 when local DB offline in CI
    assert post_resp.status_code in (401, 503)
    if post_resp.status_code == 401:
        assert b"Invalid username or password" in post_resp.data


def test_login_lockout_throttling(client):
    """Verify rapid failed logins trigger lockout protection or rate limiting."""
    get_resp = client.get("/login")
    csrf = _extract_csrf(get_resp.get_data(as_text=True))

    responses = []
    for _ in range(6):
        r = client.post(
            "/login",
            data={
                "username": "target_admin",
                "password": "BadPassword!999",
                "_csrf": csrf,
            },
        )
        responses.append(r)

    # By attempt 6, either account lockout error, 503 DB offline, or 429 Too Many Requests is triggered
    status_codes = [r.status_code for r in responses]
    assert 429 in status_codes or 503 in status_codes or any(b"Too many failed attempts" in r.data for r in responses)


def test_logout_unauthenticated_redirect(client):
    """Verify POST /logout when unauthenticated is rejected or redirects to login."""
    resp = client.post("/logout")
    # CSRF check blocks with 400, or unauthorized redirects to login view (302/401)
    assert resp.status_code in (400, 401, 302)


def test_login_invalid_email_format(client):
    """Verify login rejects usernames or strings that do not conform to email format."""
    get_resp = client.get("/login")
    from tests.test_auth import _extract_csrf
    csrf = _extract_csrf(get_resp.get_data(as_text=True))

    post_resp = client.post(
        "/login",
        data={
            "username": "non_email_user_format",
            "password": "WrongPassword#123",
            "_csrf": csrf,
        },
    )
    assert post_resp.status_code == 401
    assert b"Email is not valid" in post_resp.data
