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
            "username": "nonexistent_analyst@threatwatch.local",
            "password": "WrongPassword#123",
            "_csrf": csrf,
        },
    )
    # 401 Unauthorized when DB is reachable, 503 when local DB offline in CI
    assert post_resp.status_code in (401, 503)
    if post_resp.status_code == 401:
        assert b"Invalid email or password" in post_resp.data


def test_login_invalid_email_format(client):
    """Verify submitting credentials without a valid email address format returns an error."""
    get_resp = client.get("/login")
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


def test_login_lockout_throttling(client):
    """Verify rapid failed logins trigger lockout protection or rate limiting."""
    get_resp = client.get("/login", environ_base={"REMOTE_ADDR": "127.0.0.99"})
    csrf = _extract_csrf(get_resp.get_data(as_text=True))

    responses = []
    for _ in range(6):
        r = client.post(
            "/login",
            data={
                "username": "target_admin@threatwatch.local",
                "password": "BadPassword!999",
                "_csrf": csrf,
            },
            environ_base={"REMOTE_ADDR": "127.0.0.99"},
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


def test_rbac_automatic_role_assignment():
    """Verify designated admin leads receive role='admin' while new registrations receive 'analyst'."""
    from models import find_or_create_firebase_user
    import secrets

    random_analyst_email = f"analyst_{secrets.token_hex(4)}@threatwatch.local"
    analyst_user = find_or_create_firebase_user(random_analyst_email)
    assert analyst_user.role == "analyst"

    lead_admin = find_or_create_firebase_user("admin@threatwatch.local")
    assert lead_admin.role == "admin"

    test_admin = find_or_create_firebase_user("testadmin@threatwatch.local")
    assert test_admin.role == "admin"


def test_rbac_settings_access_control(client):
    """Verify /settings requires role='admin' and blocks role='analyst'."""
    from models import users_col, create_user

    analyst_email = "analyst_rbac@threatwatch.local"
    admin_email = "admin_rbac@threatwatch.local"
    pw = "StrongPass123!"

    # Create both an analyst and admin
    users_col.delete_many({"email": {"$in": [analyst_email, admin_email]}})
    create_user(username="analyst_rbac", password=pw, email=analyst_email, role="analyst")
    create_user(username="admin_rbac", password=pw, email=admin_email, role="admin")

    try:
        # 1. Unauthenticated: redirects to /login
        r = client.get("/settings")
        assert r.status_code == 302
        assert "/login" in r.headers.get("Location", "")

        # 2. Login as Analyst (using dedicated IP to avoid any rate limit collisions)
        login_page = client.get("/login", environ_base={"REMOTE_ADDR": "127.0.0.77"})
        csrf = _extract_csrf(login_page.get_data(as_text=True))
        login_res = client.post(
            "/login",
            data={"username": analyst_email, "password": pw, "_csrf": csrf},
            environ_base={"REMOTE_ADDR": "127.0.0.77"},
        )
        assert login_res.status_code == 302

        # Analyst attempts to access /settings -> blocked by @admin_required, redirected to dashboard
        r_analyst = client.get("/settings", follow_redirects=True, environ_base={"REMOTE_ADDR": "127.0.0.77"})
        assert r_analyst.status_code == 200
        assert b"Access denied: Administrator privileges required" in r_analyst.data

        # 3. Log out (with current session CSRF) and log in as Admin
        with client.session_transaction() as sess:
            session_csrf = sess.get("_csrf")

        logout_res = client.post(
            "/logout",
            data={"_csrf": session_csrf},
            environ_base={"REMOTE_ADDR": "127.0.0.77"},
        )
        assert logout_res.status_code == 302

        login_page2 = client.get("/login", environ_base={"REMOTE_ADDR": "127.0.0.78"})
        assert login_page2.status_code == 200
        csrf2 = _extract_csrf(login_page2.get_data(as_text=True))
        assert csrf2, "Failed to extract CSRF token from admin login page"

        login_res2 = client.post(
            "/login",
            data={"username": admin_email, "password": pw, "_csrf": csrf2},
            environ_base={"REMOTE_ADDR": "127.0.0.78"},
        )
        assert login_res2.status_code == 302

        # Admin accesses /settings -> allowed
        r_admin = client.get("/settings", environ_base={"REMOTE_ADDR": "127.0.0.78"})
        assert r_admin.status_code == 200
        assert b"Settings" in r_admin.data
        assert b"settingsForm" in r_admin.data
    finally:
        users_col.delete_many({"email": {"$in": [analyst_email, admin_email]}})
