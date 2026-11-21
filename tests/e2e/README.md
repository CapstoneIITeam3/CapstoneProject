# ThreatWatch Selenium E2E UI Test Suite

Automated End-to-End (E2E) browser testing suite for ThreatWatch AI-IDS using Selenium WebDriver, Python Pytest, and headless Google Chrome.

---

## Architecture Overview

- **W3C WebDriver Client:** `selenium>=4.18.0` with W3C bidirectional protocol support.
- **Automated Driver Management:** `webdriver-manager>=4.0.0` automatically fetches and configures the matching ChromeDriver binary.
- **Background Application Server:** Dedicated thread running `werkzeug.serving.make_server` on an ephemeral TCP port discovered dynamically via `find_free_port()`.
- **Offline CI/CD Resilience:** Built-in in-memory fallback for MongoDB user lookups and collection queries, guaranteeing reliable, timeout-free test runs even when a local MongoDB daemon is not running.
- **Browser Configuration:** Headless Chrome (`--headless=new`, `--no-sandbox`, `--disable-dev-shm-usage`, `--disable-gpu`, `--window-size=1920,1080`).

---

## Test Directory Structure

```text
tests/e2e/
├── __init__.py               # E2E test package marker
├── conftest.py               # Live server fixture, WebDriver setup, and login helper
├── test_e2e_auth.py          # Authentication, password toggle, modal, and session tests
├── test_e2e_dashboard.py     # Dashboard metrics, analyze modal, logs, alerts, settings
└── README.md                 # Test suite documentation and runner instructions
```

---

## Test Suites & Coverage

### 1. Authentication & Security Lifecycle (`test_e2e_auth.py`)
- `test_login_page_renders_elements`: Validates full UI branding, form inputs, disabled submit button state, and Firebase OAuth/modal triggers.
- `test_password_visibility_toggle`: Tests password masking and unmasking via the `#eyeBtn` control.
- `test_forgot_password_modal_interaction`: Tests opening and closing the automated password reset modal in the browser DOM.
- `test_failed_login_with_invalid_credentials`: Validates rejected login attempts and error alerts.
- `test_successful_login_and_logout_flow`: Full journey from valid credentials submission to Dashboard landing and session termination.
- `test_protected_routes_redirect_to_login`: Asserts route protection for `/`, `/logs`, `/alerts`, and `/settings`.

### 2. Dashboard Monitoring & Navigation (`test_e2e_dashboard.py`)
- `test_dashboard_overview_and_visualizations`: Validates stat cards (`#sTotal`, `#sThreats`, `#sRisk`, `#sOpen`) and Chart.js canvases (`#activityChart`, `#histChart`, `#catChart`, `#tierChart`).
- `test_analyze_modal_open_preset_close`: Tests opening the connection analyze modal, populating traffic presets, and modal dismissal.
- `test_logs_page_navigation_and_table_controls`: Tests navigation to `/logs`, filter form inputs, search field, and export trigger.
- `test_alerts_page_navigation_and_status_tabs`: Tests navigation to `/alerts` and status tab filtering (Open, Acknowledged, Dismissed).
- `test_settings_page_threshold_controls`: Tests navigation to `/settings` and threshold inputs (`#tS`, `#tM`).

---

## How to Run the Tests

### Prerequisites
1. Google Chrome installed on the host system.
2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running All E2E Tests
```bash
pytest tests/e2e -v
```

### Running Specific Test Modules
```bash
# Authentication tests
pytest tests/e2e/test_e2e_auth.py -v

# Dashboard, logs, alerts, and settings tests
pytest tests/e2e/test_e2e_dashboard.py -v
```

### Generating JUnit XML Reports (for Jenkins CI/CD)
```bash
pytest tests/e2e -v --junitxml=reports/e2e-results.xml
```
