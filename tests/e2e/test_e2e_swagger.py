"""End-to-End Browser Tests for Swagger UI / OpenAPI Documentation."""
import time
import pytest
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


def test_swagger_ui_browser_rendering_and_modal(driver, live_server):
    """Verify in a real browser (Google Chrome) that Swagger UI renders, loads assets, and displays the Authorize modal."""
    driver.get(f"{live_server}/apidocs/")

    # 1. Wait for Swagger UI container to load
    wait = WebDriverWait(driver, 15)
    swagger_ui = wait.until(EC.presence_of_element_located((By.CLASS_NAME, "swagger-ui")))
    assert swagger_ui is not None

    # Verify Title and Header content
    title_elem = wait.until(EC.presence_of_element_located((By.CLASS_NAME, "title")))
    assert "ThreatWatch" in title_elem.text or "Swagger" in driver.title

    # 2. Check for the 'Authorize' button (lock icon)
    auth_btn = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "button.btn.authorize")))
    assert auth_btn is not None
    auth_btn.click()
    time.sleep(0.5)

    # 3. Verify 'Available authorizations' modal dialog appeared
    modal = wait.until(EC.visibility_of_element_located((By.CLASS_NAME, "modal-ux")))
    assert modal is not None
    modal_text = modal.text
    assert "Available authorizations" in modal_text
    assert "ApiKeyAuth" in modal_text
    assert "Basic authorization" in modal_text or "BasicAuth" in modal_text
    assert "Bearer" in modal_text
    assert "CsrfToken" in modal_text

    # Close the modal
    close_btn = modal.find_element(By.CSS_SELECTOR, "button.btn-done, button.close-modal")
    close_btn.click()
    time.sleep(0.5)

    # 4. Check browser console logs for fatal JavaScript exceptions
    browser_logs = driver.get_log("browser")
    severe_errors = [
        log for log in browser_logs
        if log["level"] == "SEVERE" and "favicon.ico" not in log["message"]
    ]
    assert len(severe_errors) == 0, f"Encountered unexpected browser console errors: {severe_errors}"


def test_swagger_ui_execute_health_endpoint(driver, live_server):
    """Verify executing an interactive endpoint call (GET /api/health) directly from the Swagger UI."""
    driver.get(f"{live_server}/apidocs/")
    wait = WebDriverWait(driver, 15)

    # Wait for operations to be rendered
    wait.until(EC.presence_of_element_located((By.CLASS_NAME, "opblock")))

    # Find and expand the GET /api/health block
    health_block = None
    for block in driver.find_elements(By.CLASS_NAME, "opblock-summary"):
        if "/api/health" in block.text:
            health_block = block
            break

    assert health_block is not None, "GET /api/health operation block not found in Swagger UI"
    driver.execute_script("arguments[0].scrollIntoView(true);", health_block)
    health_block.click()
    time.sleep(0.5)

    # Click 'Try it out' button
    try_out_btn = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, ".try-out__btn")))
    try_out_btn.click()
    time.sleep(0.3)

    # Click 'Execute' button
    execute_btn = wait.until(EC.element_to_be_clickable((By.CSS_SELECTOR, "button.execute")))
    execute_btn.click()

    # Wait for the response block
    live_response = wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, ".live-responses-table, .responses-inner")))
    time.sleep(1.0)
    response_text = live_response.text

    # Verify response code (200 or 503) and JSON payload attributes
    assert ("200" in response_text or "503" in response_text), f"Unexpected response in UI: {response_text}"
    assert "ThreatWatch" in response_text or "status" in response_text

    # Confirm no browser crashes occurred
    assert driver.title is not None
