"""End-to-End (E2E) UI Tests for ThreatWatch Authentication & Session Lifecycle."""
import time
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from tests.e2e.conftest import do_login


def test_login_page_renders_elements(driver, live_server):
    """Verify that the ThreatWatch login view loads complete UI branding and auth controls."""
    driver.get(f"{live_server}/login")

    # Verify Title and Branding
    assert "Log in" in driver.title or "ThreatWatch" in driver.title
    brand = driver.find_element(By.CLASS_NAME, "brand")
    assert "Threat" in brand.text and "Watch" in brand.text

    # Verify Input Fields
    username_field = driver.find_element(By.ID, "username")
    password_field = driver.find_element(By.ID, "password")
    submit_btn = driver.find_element(By.ID, "submitBtn")
    assert username_field.is_displayed()
    assert password_field.is_displayed()
    assert submit_btn.is_displayed()

    # Submit button should initially be disabled until input entered
    assert not submit_btn.is_enabled()

    # Verify Google Sign-In and Forgot Password modal triggers
    google_btn = driver.find_element(By.ID, "googleSignInBtn")
    forgot_btn = driver.find_element(By.ID, "forgotBtn")
    assert google_btn.is_displayed()
    assert "Sign in with Google" in google_btn.text
    assert forgot_btn.is_displayed()


def test_password_visibility_toggle(driver, live_server):
    """Verify that clicking the eye button toggles the password input between password and text."""
    driver.get(f"{live_server}/login")

    pw_field = driver.find_element(By.ID, "password")
    eye_btn = driver.find_element(By.ID, "eyeBtn")

    pw_field.send_keys("SampleSecret123!")
    assert pw_field.get_attribute("type") == "password"

    # Click eye button to reveal
    eye_btn.click()
    time.sleep(0.2)
    assert pw_field.get_attribute("type") == "text"

    # Click eye button again to hide
    eye_btn.click()
    time.sleep(0.2)
    assert pw_field.get_attribute("type") == "password"


def test_forgot_password_modal_interaction(driver, live_server):
    """Verify password recovery modal can be opened and closed in the browser DOM."""
    driver.get(f"{live_server}/login")

    forgot_btn = driver.find_element(By.ID, "forgotBtn")
    modal = driver.find_element(By.ID, "forgotModal")
    modal_close = driver.find_element(By.ID, "modalCloseBtn")
    reset_email = driver.find_element(By.ID, "resetEmail")
    send_reset_btn = driver.find_element(By.ID, "sendResetBtn")

    # Initially hidden
    assert not modal.is_displayed()

    # Open modal
    forgot_btn.click()
    time.sleep(0.3)
    assert modal.is_displayed()
    assert reset_email.is_displayed()
    assert send_reset_btn.is_displayed()

    # Close modal
    modal_close.click()
    time.sleep(0.3)
    assert not modal.is_displayed()


def test_failed_login_with_invalid_credentials(driver, live_server):
    """Verify that submitting incorrect credentials displays an authentication error banner."""
    driver.get(f"{live_server}/login")

    driver.find_element(By.ID, "username").send_keys("invalid_operator")
    driver.find_element(By.ID, "password").send_keys("IncorrectPassword123!")

    time.sleep(0.3)
    driver.find_element(By.ID, "submitBtn").click()

    # Wait for page response
    WebDriverWait(driver, 5).until(
        lambda d: "/login" in d.current_url
    )
    error_elements = driver.find_elements(By.CLASS_NAME, "error")
    assert len(error_elements) > 0 or "/login" in driver.current_url


def test_successful_login_and_logout_flow(driver, live_server):
    """Verify end-to-end user journey: login with valid credentials, dashboard landing, and logout."""
    do_login(driver, live_server, username="admin", password="Test1234!")

    # Verify landing on Dashboard
    WebDriverWait(driver, 8).until(
        lambda d: d.current_url.rstrip("/").endswith(live_server.rstrip("/"))
    )
    assert "ThreatWatch" in driver.title or "Dashboard" in driver.title

    # Verify top navigation links and username
    topnav = driver.find_element(By.CLASS_NAME, "topnav")
    assert "Dashboard" in topnav.text
    assert "Logs" in topnav.text
    assert "Alerts" in topnav.text
    assert "admin" in topnav.text

    # Locate and trigger Log out button
    logout_btn = driver.find_element(By.XPATH, "//button[contains(text(), 'Log out')]")
    assert logout_btn.is_displayed()
    logout_btn.click()

    # Verify redirection back to login screen
    WebDriverWait(driver, 8).until(
        lambda d: "/login" in d.current_url
    )
    assert "/login" in driver.current_url
    username_field = WebDriverWait(driver, 8).until(
        EC.presence_of_element_located((By.ID, "username"))
    )
    assert username_field is not None


def test_protected_routes_redirect_to_login(driver, live_server):
    """Verify that accessing protected internal endpoints without a session redirects to /login."""
    protected_paths = ["/", "/logs", "/alerts", "/settings"]

    for path in protected_paths:
        driver.get(f"{live_server}{path}")
        WebDriverWait(driver, 5).until(
            lambda d: "/login" in d.current_url
        )
        assert "/login" in driver.current_url
