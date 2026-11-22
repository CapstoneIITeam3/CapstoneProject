"""End-to-End (E2E) UI Tests for ThreatWatch Dashboard, Logs, Alerts, and Settings."""
import time
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from tests.e2e.conftest import do_login


def test_dashboard_overview_and_visualizations(driver, live_server):
    """Verify that the primary ThreatWatch dashboard loads stat metric cards and chart canvases."""
    do_login(driver, live_server, username="testadmin@threatwatch.local", password="TestPassword123!")

    # Verify landing on Dashboard view
    WebDriverWait(driver, 8).until(
        lambda d: d.current_url.rstrip("/").endswith(live_server.rstrip("/"))
    )

    # Verify stat cards exist in the DOM
    assert driver.find_element(By.ID, "sTotal") is not None
    assert driver.find_element(By.ID, "sThreats") is not None
    assert driver.find_element(By.ID, "sRisk") is not None
    assert driver.find_element(By.ID, "sOpen") is not None

    # Verify chart canvases
    assert driver.find_element(By.ID, "activityChart") is not None
    assert driver.find_element(By.ID, "histChart") is not None
    assert driver.find_element(By.ID, "catChart") is not None
    assert driver.find_element(By.ID, "tierChart") is not None

    # Verify analyze action button
    analyze_btn = driver.find_element(By.ID, "analyzeBtn")
    assert analyze_btn.is_displayed()


def test_analyze_modal_open_preset_close(driver, live_server):
    """Verify that the traffic analysis modal opens, populates via presets, and closes properly."""
    do_login(driver, live_server, username="testadmin@threatwatch.local", password="TestPassword123!")

    analyze_btn = driver.find_element(By.ID, "analyzeBtn")
    analyze_btn.click()

    # Modal should become visible
    modal = WebDriverWait(driver, 5).until(
        EC.visibility_of_element_located((By.ID, "analyzeModal"))
    )
    assert modal.is_displayed()

    # Verify preset buttons inside modal
    preset_btn = driver.find_element(By.XPATH, "//button[@data-preset='normal']")
    assert preset_btn.is_displayed()
    preset_btn.click()

    # Close modal
    close_btn = driver.find_element(By.XPATH, "//div[@id='analyzeModal']//button[@data-close]")
    close_btn.click()
    time.sleep(0.5)

    # Modal should now be hidden
    assert not modal.is_displayed()


def test_logs_page_navigation_and_table_controls(driver, live_server):
    """Verify navigation to the Logs view, search filter controls, and tabular log structure."""
    do_login(driver, live_server, username="testadmin@threatwatch.local", password="TestPassword123!")

    # Click Logs navigation link
    logs_nav = driver.find_element(By.XPATH, "//a[contains(text(), 'Logs')]")
    logs_nav.click()

    WebDriverWait(driver, 8).until(
        lambda d: "/logs" in d.current_url
    )
    assert "/logs" in driver.current_url

    # Verify filter form and inputs
    filters_form = driver.find_element(By.ID, "filters")
    assert filters_form.is_displayed()
    assert driver.find_element(By.NAME, "q") is not None
    assert driver.find_element(By.ID, "exportBtn") is not None

    # Verify data table
    table = driver.find_element(By.CLASS_NAME, "data")
    assert table is not None


def test_alerts_page_navigation_and_status_tabs(driver, live_server):
    """Verify navigation to Alerts page and tabbed filtering by alert triage status."""
    do_login(driver, live_server, username="testadmin@threatwatch.local", password="TestPassword123!")

    # Click Alerts navigation link
    alerts_nav = driver.find_element(By.XPATH, "//a[contains(text(), 'Alerts')]")
    alerts_nav.click()

    WebDriverWait(driver, 8).until(
        lambda d: "/alerts" in d.current_url
    )
    assert "/alerts" in driver.current_url

    # Verify status tabs
    open_tab = driver.find_element(By.CSS_SELECTOR, "button[data-status='open']")
    ack_tab = driver.find_element(By.CSS_SELECTOR, "button[data-status='acknowledged']")
    dis_tab = driver.find_element(By.CSS_SELECTOR, "button[data-status='dismissed']")

    assert open_tab.is_displayed()
    assert ack_tab.is_displayed()
    assert dis_tab.is_displayed()

    # Click acknowledged tab and verify tab state transition
    ack_tab.click()
    time.sleep(0.3)
    assert "on" in ack_tab.get_attribute("class")


def test_settings_page_threshold_controls(driver, live_server):
    """Verify navigation to Settings view and threshold parameter input fields."""
    do_login(driver, live_server, username="testadmin@threatwatch.local", password="TestPassword123!")

    # Click Settings navigation link
    settings_nav = driver.find_element(By.XPATH, "//a[contains(text(), 'Settings')]")
    settings_nav.click()

    WebDriverWait(driver, 8).until(
        lambda d: "/settings" in d.current_url
    )
    assert "/settings" in driver.current_url

    # Verify threshold form and inputs
    settings_form = driver.find_element(By.ID, "settingsForm")
    assert settings_form.is_displayed()

    sus_input = driver.find_element(By.ID, "tS")
    mal_input = driver.find_element(By.ID, "tM")
    assert sus_input.is_displayed()
    assert mal_input.is_displayed()
    assert float(sus_input.get_attribute("value")) > 0.0
    assert float(mal_input.get_attribute("value")) > 0.0
