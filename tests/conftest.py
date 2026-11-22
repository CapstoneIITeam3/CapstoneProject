"""Shared Pytest Fixtures for ThreatWatch AI-IDS Test Suite."""
import os
import pytest
import pandas as pd

# Test environment settings
os.environ["SECRET_KEY"] = "test-secret-key-for-pytest"
os.environ["MONGO_URI"] = "mongodb://localhost:27017/ai_ids_test_db"
os.environ["MONGO_DB_NAME"] = "ai_ids_test_db"
os.environ["SEED_DEMO"] = "0"
os.environ["REPLAY"] = "0"

import app as flask_app_module
from app import app as flask_app
from detector import detector, tier_for, validate


@pytest.fixture(scope="session")
def app():
    """Provide the configured Flask application instance for testing."""
    flask_app.config.update({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SERVER_NAME": "localhost:5000",
    })
    yield flask_app


@pytest.fixture
def client(app):
    """Provide an unauthenticated Flask test client."""
    return app.test_client()


@pytest.fixture
def sample_row():
    """Provide a standard dictionary of valid NSL-KDD network traffic attributes."""
    return {
        "duration": 0,
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": 181,
        "dst_bytes": 5450,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 1,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "num_access_files": 0,
        "num_outbound_cmds": 0,
        "is_host_login": 0,
        "is_guest_login": 0,
        "count": 8,
        "srv_count": 8,
        "serror_rate": 0.0,
        "srv_serror_rate": 0.0,
        "rerror_rate": 0.0,
        "srv_rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0,
        "dst_host_count": 9,
        "dst_host_srv_count": 9,
        "dst_host_same_srv_rate": 1.0,
        "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 0.11,
        "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0,
        "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0,
        "dst_host_srv_rerror_rate": 0.0,
    }
