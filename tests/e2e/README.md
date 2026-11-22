# ThreatWatch Selenium E2E UI Test Suite

Automated End-to-End (E2E) browser testing suite for ThreatWatch AI-IDS using Selenium WebDriver, Python Pytest, and headless Google Chrome.

---

## Architecture Overview

- **W3C WebDriver Client:** `selenium>=4.18.0` with W3C bidirectional protocol support.
- **Automated Driver Management:** `webdriver-manager>=4.0.0` automatically fetches and configures the matching ChromeDriver binary.
- **Automated Video Recording:** In-process screen recorder (`video_recorder.py`) using `opencv-python` and `numpy`. Operates seamlessly across both Headless (`--headless=new`) and Headful Chrome, generating timestamped `.mp4` video artifacts with heads-up diagnostic HUD overlays.
- **Background Application Server:** Dedicated thread running `werkzeug.serving.make_server` on an ephemeral TCP port discovered dynamically via `find_free_port()`.
- **Offline CI/CD Resilience:** Built-in in-memory fallback for MongoDB user lookups and collection queries, guaranteeing reliable, timeout-free test runs even when a local MongoDB daemon is not running.
- **Browser Configuration:** Headless Chrome (`--headless=new`, `--no-sandbox`, `--disable-dev-shm-usage`, `--disable-gpu`, `--window-size=1920,1080`).

---

## Test Directory Structure

```text
tests/e2e/
├── __init__.py               # E2E test package marker
├── conftest.py               # Live server fixture, WebDriver setup, video recorder fixture, and login helper
├── video_recorder.py         # Thread-safe OpenCV MP4 screen recorder with diagnostic HUD overlay
├── test_e2e_auth.py          # Authentication, password toggle, modal, and session tests
├── test_e2e_dashboard.py     # Dashboard metrics, analyze modal, logs, alerts, settings
├── test_e2e_swagger.py       # Swagger UI documentation interactive validation
└── README.md                 # Test suite documentation, video recording instructions, and runner guide
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

---

## Automated Video Recording Configuration

The E2E test suite automatically records video of every browser test session in standard H.264/MPEG-4 (`.mp4`) format, complete with a diagnostic HUD (test title, elapsed time, and framerate).

### Retention Modes (via Environment Variables)

| Variable | Values | Description |
| :--- | :--- | :--- |
| `RECORD_VIDEO` | `1` or `all` (default) | Records and keeps MP4 videos for all executed tests in `reports/videos/`. |
| | `failed_only` | Records tests in the background, but immediately deletes videos of passing tests. Only failed test videos are preserved (ideal for CI disk conservation). |
| | `0` or `off` | Completely disables video recording for rapid local debugging. |
| `VIDEO_DIR` | e.g. `reports/videos` | Target directory where `.mp4` video artifacts are stored. |
| `VIDEO_FPS` | `10` (default) | Video frame rate (frames per second). |
| `VIDEO_SPEED` | `1.0` (default) | Playback pacing multiplier. `1.0` = true 1:1 real-time wall-clock speed; `0.5` = 2x slow-motion demo mode (ideal for presentations & human review). |
| `VIDEO_END_HOLD` | `1.5` (default) | Dwell duration in seconds to freeze the final frame with `[PASSED]` / `[FAILED]` status badge before closing the video. |

### Running with Custom Video Flags

```bash
# Record all tests (default behavior)
pytest tests/e2e -v

# Keep video recordings ONLY for failed tests
RECORD_VIDEO=failed_only pytest tests/e2e -v

# Disable video recording
RECORD_VIDEO=0 pytest tests/e2e -v
```

In Windows PowerShell:
```powershell
# Only record failures
$env:RECORD_VIDEO="failed_only"; pytest tests/e2e -v

# Disable recording
$env:RECORD_VIDEO="0"; pytest tests/e2e -v
```

### Viewing Recorded Videos
Saved video files can be played with any standard media player (VLC, Windows Media Player, QuickTime) or embedded directly in browser reports and CI artifacts.

Each test execution session creates a dedicated timestamped subdirectory to preserve run history:
```text
reports/videos/run_<YYYYMMDD_HHMMSS>/<test_function_name>.mp4
```

For example:
```text
reports/videos/run_20261122_225200/
├── test_login_page_renders_elements.mp4
├── test_password_visibility_toggle.mp4
└── ...
```
