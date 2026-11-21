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
    test_pw_hash = bcrypt.hashpw(b"Test1234!", bcrypt.gensalt()).decode("utf-8")
    test_doc = {
        "_id": ObjectId(test_user_id),
        "username": "admin",
        "email": "admin@threatwatch.local",
        "password_hash": test_pw_hash,
        "role": "admin",
    }

    try:
        users_col.find_one({}, maxTimeMS=500)
        # MongoDB is active: seed or update admin user
        existing = users_col.find_one({"username": "admin"})
        if not existing:
            create_user(username="admin", password="Test1234!", email="admin@threatwatch.local", role="admin")
        else:
            users_col.update_one({"username": "admin"}, {"$set": {"password_hash": test_pw_hash}})
    except Exception:
        # Fallback in-memory user mock when MongoDB daemon is not running in offline CI/CD
        class MockCursor:
            def __init__(self, items=None):
                self.items = items or []
            def sort(self, *a, **k):
                return self
            def limit(self, *a, **k):
                return self
            def skip(self, *a, **k):
                return self
            def __iter__(self):
                return iter(self.items)
            def __list__(self):
                return list(self.items)

        def mock_find_user(username):
            if username == "admin":
                return MongoUser(test_doc)
            return None

        def mock_find_user_by_id(uid):
            if str(uid) == test_user_id or uid == test_doc["_id"]:
                return MongoUser(test_doc)
            return None

        def mock_check_password(user, raw):
            if not user or not raw:
                return False
            try:
                return bcrypt.checkpw(raw.encode("utf-8"), user._doc["password_hash"].encode("utf-8"))
            except Exception:
                return raw == "Test1234!"

        def mock_audit(*args, **kwargs):
            pass

        flask_app_module.find_user = mock_find_user
        flask_app_module.find_user_by_id = mock_find_user_by_id
        flask_app_module.check_password = mock_check_password
        flask_app_module.audit = mock_audit

        models.find_user = mock_find_user
        models.find_user_by_id = mock_find_user_by_id
        models.check_password = mock_check_password
        models.audit = mock_audit

        # Speed up offline responses by preventing 5s connection timeouts
        models.settings_col.find_one = lambda *a, **k: None
        models.log_records_col.find = lambda *a, **k: MockCursor([])
        models.log_records_col.count_documents = lambda *a, **k: 0
        models.alerts_col.find = lambda *a, **k: MockCursor([])
        models.alerts_col.count_documents = lambda *a, **k: 0
        models.audit_logs_col.find = lambda *a, **k: MockCursor([])

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


def do_login(driver, base_url, username="admin", password="Test1234!"):
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
