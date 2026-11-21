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
