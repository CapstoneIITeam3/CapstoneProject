"""Shared Fixtures and WebDriver Configurations for E2E Testing."""
import os
import socket
import threading
import time
import pytest
from bson import ObjectId
import bcrypt
from werkzeug.serving import make_server
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

import app as flask_app_module
from app import app as flask_app
import models
from models import MongoUser, create_user, users_col


def find_free_port():
    """Find and return an available local TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="session")
def live_server():
    """Start the ThreatWatch Flask server in a background thread for browser testing."""
    os.environ["SEED_DEMO"] = "0"
    os.environ["REPLAY"] = "0"
    os.environ["SECRET_KEY"] = "e2e-secret-key-threatwatch"

    port = find_free_port()
    base_url = f"http://127.0.0.1:{port}"

    # Determine database reachability and ensure standard test credentials exist
    test_user_id = str(ObjectId())
    test_pw_hash = bcrypt.hashpw(b"TestPassword123!", bcrypt.gensalt()).decode("utf-8")
    test_doc = {
        "_id": ObjectId(test_user_id),
        "username": "testadmin",
        "email": "testadmin@threatwatch.local",
        "password_hash": test_pw_hash,
        "role": "admin",
    }

    try:
        users_col.find_one({}, maxTimeMS=500)
        # MongoDB is active: seed or update testadmin user
        existing = users_col.find_one({"email": "testadmin@threatwatch.local"})
        if not existing:
            create_user(username="testadmin", password="TestPassword123!", email="testadmin@threatwatch.local", role="admin")
        else:
            users_col.update_one({"email": "testadmin@threatwatch.local"}, {"$set": {"password_hash": test_pw_hash}})
    except Exception:
        # Fallback in-memory user mock when MongoDB daemon is not running in offline CI/CD
        class MockCursor:
            def __init__(self, items=None):
                self.items = items or []
                self._iter = None
            def sort(self, *a, **k):
                return self
            def limit(self, *a, **k):
                return self
            def skip(self, *a, **k):
                return self
            def __iter__(self):
                return iter(self.items)
            def __next__(self):
                if self._iter is None:
                    self._iter = iter(self.items)
                return next(self._iter)
            def __list__(self):
                return list(self.items)

        def mock_find_user(username):
            try:
                doc = models.users_col.find_one({"username": username})
                if doc:
                    return MongoUser(doc)
            except Exception:
                pass
            if username in ("admin", "testadmin", "testadmin@threatwatch.local"):
                return MongoUser(test_doc)
            return None

        def mock_find_user_by_email(email):
            try:
                doc = models.users_col.find_one({"email": email})
                if doc:
                    return MongoUser(doc)
            except Exception:
                pass
            if email in ("admin@threatwatch.local", "testadmin@threatwatch.local"):
                return MongoUser(test_doc)
            return None

        def mock_find_user_by_id(uid):
            try:
                from bson import ObjectId
                query_id = ObjectId(str(uid)) if ObjectId.is_valid(str(uid)) else uid
                doc = models.users_col.find_one({"_id": query_id})
                if doc:
                    return MongoUser(doc)
            except Exception:
                pass
            if str(uid) == test_user_id or uid == test_doc["_id"]:
                return MongoUser(test_doc)
            return None

        def mock_check_password(user, raw):
            if not user or not raw:
                return False
            try:
                return bcrypt.checkpw(raw.encode("utf-8"), user._doc["password_hash"].encode("utf-8"))
            except Exception:
                return raw in ("Test1234!", "TestPassword123!")

        def mock_audit(*args, **kwargs):
            pass

        flask_app_module.find_user = mock_find_user
        flask_app_module.find_user_by_email = mock_find_user_by_email
        flask_app_module.find_user_by_id = mock_find_user_by_id
        flask_app_module.check_password = mock_check_password
        flask_app_module.audit = mock_audit

        models.find_user = mock_find_user
        models.find_user_by_email = mock_find_user_by_email
        models.find_user_by_id = mock_find_user_by_id
        models.check_password = mock_check_password
        models.audit = mock_audit

        # Speed up offline responses by preventing 5s connection timeouts
        models.settings_col.find_one = lambda *a, **k: None
        models.log_records_col.find = lambda *a, **k: MockCursor([])
        models.log_records_col.find_one = lambda *a, **k: None
        models.log_records_col.count_documents = lambda *a, **k: 0
        models.alerts_col.find = lambda *a, **k: MockCursor([])
        models.alerts_col.find_one = lambda *a, **k: None
        models.alerts_col.count_documents = lambda *a, **k: 0
        models.audit_logs_col.find = lambda *a, **k: MockCursor([])
        models.audit_logs_col.find_one = lambda *a, **k: None

    flask_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SERVER_NAME": None,
        "SECRET_KEY": "e2e-secret-key-threatwatch",
    })

    server = make_server("127.0.0.1", port, flask_app)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(1.0)

    yield base_url

    server.shutdown()


@pytest.fixture(scope="function")
def driver():
    """Initialize a clean headless Google Chrome WebDriver instance."""
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--disable-extensions")
    options.add_argument("--log-level=3")

    service = Service(ChromeDriverManager().install())
    chrome_driver = webdriver.Chrome(service=service, options=options)
    chrome_driver.implicitly_wait(8)

    yield chrome_driver

    try:
        chrome_driver.quit()
    except Exception:
        pass


@pytest.hookimpl(tryfirst=True, hookwrapper=True)
def pytest_runtest_makereport(item, call):
    """Capture test outcome to support failure-only video retention mode."""
    outcome = yield
    report = outcome.get_result()
    if report.when == "call":
        item.test_failed = report.failed


@pytest.fixture(scope="session")
def session_video_dir():
    """Create and yield a timestamped directory (e.g. reports/videos/run_YYYYMMDD_HHMMSS) for the test run."""
    record_mode = os.environ.get("RECORD_VIDEO", "1").lower().strip()
    if record_mode in ("0", "false", "off", "no"):
        yield None
        return

    base_video_dir = os.environ.get(
        "VIDEO_DIR",
        os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "reports", "videos")),
    )
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    session_dir = os.path.join(base_video_dir, f"run_{timestamp}")
    os.makedirs(session_dir, exist_ok=True)

    yield session_dir

    # Clean up empty directory if no videos were kept (e.g. failed_only mode with all passing tests)
    try:
        if os.path.exists(session_dir) and not os.listdir(session_dir):
            os.rmdir(session_dir)
    except OSError:
        pass


@pytest.fixture(scope="function", autouse=True)
def record_test_video(request, driver, session_video_dir):
    """Automatically record browser interactions to an MP4 video file inside the session folder.
    
    Controlled via environment variables:
      - RECORD_VIDEO: "1" / "all" (record all tests, default), "failed_only" (keep only on failure), or "0" (disabled)
      - VIDEO_DIR: Target root directory (default: 'reports/videos' in repo root)
      - VIDEO_SPEED: Playback speed multiplier (default: 1.0 for true real-time, 0.5 for 2x slow-mo)
      - VIDEO_END_HOLD: Seconds to hold the final state with [PASSED]/[FAILED] badge (default: 1.5s)
      - VIDEO_FPS: Target frame rate (default: 10 FPS)
    """
    record_mode = os.environ.get("RECORD_VIDEO", "1").lower().strip()
    if record_mode in ("0", "false", "off", "no") or not session_video_dir:
        yield None
        return

    fps = int(os.environ.get("VIDEO_FPS", "10"))
    speed = float(os.environ.get("VIDEO_SPEED", "1.0"))
    end_hold_sec = float(os.environ.get("VIDEO_END_HOLD", "1.5"))
    test_name = request.node.name
    clean_test_name = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in test_name)
    video_path = os.path.join(session_video_dir, f"{clean_test_name}.mp4")

    from tests.e2e.video_recorder import SeleniumVideoRecorder
    recorder = SeleniumVideoRecorder(
        driver,
        video_path,
        fps=fps,
        speed=speed,
        end_hold_sec=end_hold_sec,
        overlay=True,
        test_name=test_name,
    )
    recorder.start()

    yield recorder

    test_failed = getattr(request.node, "test_failed", False)
    recorder.set_status(passed=not test_failed)
    recorder.stop()

    # If configured for failures only, prune passing test video
    if record_mode in ("failed_only", "failures_only", "failures") and not test_failed:
        recorder.discard()


def do_login(driver, base_url, username="testadmin@threatwatch.local", password="TestPassword123!"):
    """Helper utility to perform UI login via browser automation."""
    driver.get(f"{base_url}/login")
    u_field = driver.find_element("id", "username")
    p_field = driver.find_element("id", "password")
    submit_btn = driver.find_element("id", "submitBtn")

    u_field.clear()
    u_field.send_keys(username)
    p_field.clear()
    p_field.send_keys(password)

    # Allow JavaScript input listener to enable submit button
    time.sleep(0.3)
    submit_btn.click()
    time.sleep(1.0)
