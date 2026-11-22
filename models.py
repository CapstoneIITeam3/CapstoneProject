"""MongoDB Data Models and Helper Functions for ThreatWatch AI-IDS.

Replaces SQLAlchemy/SQLite with pure MongoDB via PyMongo.
Collections:
  - users: User credentials and roles (bcrypt hashed)
  - log_records: Ingested network traffic logs with ML classification results
  - alerts: Security alerts generated from suspicious / malicious traffic
  - settings: System configuration parameters (thresholds, replay, email)
  - audit_logs: Administrative action history
  - password_resets: Password reset tokens with automatic TTL expiration
  - counters: Atomic sequence counters for integer log_id and alert_id
"""
import os
import json
import secrets
from datetime import datetime, timezone
import bcrypt
from bson import ObjectId
from flask_login import UserMixin
from pymongo import ReturnDocument

from db import (
    db,
    users_col,
    log_records_col,
    alerts_col,
    settings_col,
    audit_logs_col,
    password_resets_col,
)


def utcnow():
    """Return current UTC datetime."""
    return datetime.now(timezone.utc)


def iso(dt):
    """Format datetime into standard ISO 8601 UTC string."""
    if not dt:
        return None
    if isinstance(dt, str):
        return dt
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat(timespec="seconds").replace("+00:00", "Z")


def parse_dt(s):
    """Parse ISO datetime string into UTC datetime."""
    if not s:
        return None
    try:
        clean = s.replace("Z", "+00:00")
        return datetime.fromisoformat(clean)
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid date format '{s}': {e}")


# ---------------------------------------------------------------- Auto-increment IDs
def get_next_sequence(name):
    """Atomically increment and return integer sequence ID for compatibility."""
    doc = db["counters"].find_one_and_update(
        {"_id": name},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=ReturnDocument.AFTER,
    )
    return doc["seq"]


# ---------------------------------------------------------------- Flask-Login User
class MongoUser(UserMixin):
    """Wrapper around MongoDB user document for Flask-Login integration."""

    def __init__(self, doc):
        self._doc = doc
        self._id = str(doc["_id"])
        self.username = doc.get("username", "")
        self.email = doc.get("email")
        self.role = doc.get("role", "admin")
        self.firebase_uid = doc.get("firebase_uid")
        self.auth_provider = doc.get("auth_provider", "local")

    @property
    def id(self):
        return self._id

    def get_id(self):
        return self._id

    def to_dict(self):
        return {
            "id": self._id,
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "firebase_uid": self.firebase_uid,
            "auth_provider": self.auth_provider,
        }


def validate_password(password):
    """Enforce NIST/OWASP password strength standards.

    Requirements:
      - Minimum 8 characters, maximum 128 characters
      - At least one uppercase letter (A-Z)
      - At least one lowercase letter (a-z)
      - At least one numeric digit (0-9)
      - At least one special character (!@#$%^&*(),.?":{}|<>_-+=~)
    """
    if not password or not isinstance(password, str):
        raise ValueError("Password must be a non-empty string.")
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if len(password) > 128:
        raise ValueError("Password cannot exceed 128 characters.")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter (A-Z).")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter (a-z).")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one numeric digit (0-9).")
    special_chars = set("!@#$%^&*(),.?\":{}|<>_-+=~`[]/\\';")
    if not any(c in special_chars for c in password):
        raise ValueError("Password must contain at least one special character (!@#$%^&*).")


def create_user(username, password, email=None, role="admin", enforce_policy=False):
    """Create a new user document in MongoDB with bcrypt hashed password."""
    if enforce_policy:
        validate_password(password)
    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    doc = {
        "username": username.strip(),
        "password_hash": pw_hash,
        "email": email.strip() if email else None,
        "role": role,
        "created_at": utcnow(),
    }
    result = users_col.insert_one(doc)
    doc["_id"] = result.inserted_id
    return MongoUser(doc)


def find_user(username):
    """Find a user by username."""
    if not username:
        return None
    doc = users_col.find_one({"username": username.strip()})
    return MongoUser(doc) if doc else None


def find_user_by_id(user_id):
    """Find a user by MongoDB ObjectId or string representation."""
    if not user_id:
        return None
    try:
        oid = ObjectId(user_id) if not isinstance(user_id, ObjectId) else user_id
        doc = users_col.find_one({"_id": oid})
        return MongoUser(doc) if doc else None
    except Exception:
        return None


def find_user_by_email(email):
    """Find a user by email address."""
    if not email:
        return None
    doc = users_col.find_one({"email": email.strip().lower()})
    return MongoUser(doc) if doc else None


def check_password(user, raw_password):
    """Verify password against bcrypt hash."""
    if not user or not raw_password:
        return False
    pw_hash = user._doc.get("password_hash", "")
    try:
        return bcrypt.checkpw(raw_password.encode("utf-8"), pw_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def set_password(user_id, new_password, enforce_policy=True):
    """Update user's password hash in MongoDB with policy enforcement."""
    if enforce_policy:
        validate_password(new_password)
    pw_hash = bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    oid = ObjectId(user_id) if not isinstance(user_id, ObjectId) else user_id
    users_col.update_one({"_id": oid}, {"$set": {"password_hash": pw_hash}})


def find_or_create_firebase_user(email, uid=None, display_name=None, role="admin"):
    """Find an existing user by email or create a new user provisioned via Firebase.

    Links Firebase UID, updates last login timestamp, and securely provisions new
    analyst/admin accounts in the MongoDB users collection.
    """
    if not email:
        raise ValueError("A valid email is required to provision a Firebase user.")

    clean_email = email.strip().lower()
    existing = users_col.find_one({"email": clean_email})
    if existing:
        updates = {"last_login": utcnow()}
        if uid and not existing.get("firebase_uid"):
            updates["firebase_uid"] = uid
        if not existing.get("auth_provider"):
            updates["auth_provider"] = "firebase"
        users_col.update_one({"_id": existing["_id"]}, {"$set": updates})
        existing.update(updates)
        return MongoUser(existing)

    # Derive unique username
    base_username = (
        display_name.strip().replace(" ", "_").lower()
        if display_name and display_name.strip()
        else clean_email.split("@")[0]
    )
    sanitized_username = "".join(c for c in base_username if c.isalnum() or c in ("_", "-"))[:30] or "user"
    candidate = sanitized_username
    counter = 1
    while users_col.find_one({"username": candidate}):
        candidate = f"{sanitized_username}_{counter}"
        counter += 1

    # High-entropy random password so account cannot be accessed via basic password unless explicitly set
    random_pw = secrets.token_urlsafe(32)
    pw_hash = bcrypt.hashpw(random_pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    doc = {
        "username": candidate,
        "password_hash": pw_hash,
        "email": clean_email,
        "role": role,
        "firebase_uid": uid,
        "auth_provider": "firebase",
        "created_at": utcnow(),
        "last_login": utcnow(),
    }
    result = users_col.insert_one(doc)
    doc["_id"] = result.inserted_id
    return MongoUser(doc)




def find_or_create_firebase_user(email, uid=None, display_name=None, role="admin"):
    """Find an existing user by email or create a new user provisioned via Firebase."""
    if not email:
        raise ValueError("A valid email is required to provision a Firebase user.")
    clean_email = email.strip().lower()
    existing = users_col.find_one({"email": clean_email})
    if existing:
        updates = {"last_login": utcnow()}
        if uid and not existing.get("firebase_uid"):
            updates["firebase_uid"] = uid
            updates["auth_provider"] = "firebase"
        users_col.update_one({"_id": existing["_id"]}, {"$set": updates})
        existing.update(updates)
        return MongoUser(existing)

    base_username = (
        display_name.strip().replace(" ", "_").lower()
        if display_name and display_name.strip()
        else clean_email.split("@")[0]
    )
    sanitized_username = "".join(c for c in base_username if c.isalnum() or c in ("_", "-"))[:30] or "user"
    candidate = sanitized_username
    counter = 1
    while users_col.find_one({"username": candidate}):
        candidate = f"{sanitized_username}_{counter}"
        counter += 1

    random_pw = secrets.token_urlsafe(32)
    pw_hash = bcrypt.hashpw(random_pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

    doc = {
        "username": candidate,
        "password_hash": pw_hash,
        "email": clean_email,
        "role": role,
        "firebase_uid": uid,
        "auth_provider": "firebase",
        "created_at": utcnow(),
        "last_login": utcnow(),
    }
    result = users_col.insert_one(doc)
    doc["_id"] = result.inserted_id
    return MongoUser(doc)

# ---------------------------------------------------------------- System Settings
DEFAULT_SETTINGS = {
    "malicious_threshold": "0.50",
    "suspicious_threshold": "0.20",
    "use_anomaly_flag": "1",
    "alert_on_suspicious": "1",
    "email_alerts": "0",
    "replay_enabled": "1",
    "replay_interval": "2",
}


def get_setting(key, cast=str):
    """Retrieve setting value from MongoDB with default fallback."""
    doc = settings_col.find_one({"key": key})
    raw = doc["value"] if doc and "value" in doc else DEFAULT_SETTINGS.get(key, "")
    if cast is bool:
        return str(raw).lower() in ("1", "true", "yes")
    return cast(raw)


def set_setting(key, value):
    """Persist setting value to MongoDB."""
    val_str = "1" if value is True else ("0" if value is False else str(value))
    settings_col.update_one(
        {"key": key},
        {"$set": {"key": key, "value": val_str, "updated_at": utcnow()}},
        upsert=True,
    )


# ---------------------------------------------------------------- Audit Logging
def audit(action, details="", user_id=None):
    """Record an audit trail event in MongoDB."""
    doc = {
        "timestamp": utcnow(),
        "user_id": str(user_id) if user_id else None,
        "action": action,
        "details": str(details)[:500],
    }
    audit_logs_col.insert_one(doc)


# ---------------------------------------------------------------- Serialization Helpers
def log_to_dict(lr, full=False):
    """Format MongoDB log_record document into JSON dictionary for UI / API."""
    if not lr:
        return {}
    res = lr.get("result", {})
    item_id = lr.get("id") or str(lr.get("_id"))
    d = {
        "id": item_id,
        "timestamp": iso(lr.get("timestamp")),
        "src_ip": lr.get("src_ip"),
        "dst_ip": lr.get("dst_ip"),
        "protocol": lr.get("protocol_type"),
        "service": lr.get("service"),
        "flag": lr.get("flag"),
        "src_bytes": lr.get("src_bytes"),
        "dst_bytes": lr.get("dst_bytes"),
        "source": lr.get("source", "replay"),
        "threat_score": round(res.get("threat_score", 0.0), 4) if "threat_score" in res else None,
        "tier": res.get("tier"),
        "attack_category": res.get("attack_category"),
        "alert_id": lr.get("alert_id"),
        "alert_status": lr.get("alert_status"),
    }
    if full:
        d.update(
            features=lr.get("features", {}),
            true_label=lr.get("true_label"),
            anomaly_score=res.get("anomaly_score"),
            rf_probability=res.get("rf_probability"),
            threshold_applied=res.get("threshold_applied"),
            suspicious_threshold_applied=res.get("suspicious_threshold_applied"),
            model_version=res.get("model_version"),
            classified_at=iso(res.get("classified_at")),
            explanation=res.get("explanation", []),
        )
    return d


def alert_to_dict(a):
    """Format MongoDB alert document into JSON dictionary for UI / API."""
    if not a:
        return {}
    item_id = a.get("id") or str(a.get("_id"))
    return {
        "id": item_id,
        "severity": a.get("severity"),
        "status": a.get("status", "open"),
        "created_at": iso(a.get("created_at")),
        "log_id": a.get("log_id"),
        "src_ip": a.get("src_ip"),
        "dst_ip": a.get("dst_ip"),
        "protocol": a.get("protocol"),
        "service": a.get("service"),
        "threat_score": round(a.get("threat_score", 0.0), 4) if "threat_score" in a else None,
        "attack_category": a.get("attack_category"),
        "reviewed_by": a.get("reviewed_by"),
        "reviewed_at": iso(a.get("reviewed_at")),
        "note": a.get("note"),
        "email_status": a.get("email_status", "disabled"),
    }


def find_log_by_id(log_id):
    """Look up a log document by integer id or ObjectId."""
    if log_id is None:
        return None
    query = []
    try:
        query.append({"id": int(log_id)})
    except (ValueError, TypeError):
        pass
    if ObjectId.is_valid(str(log_id)):
        query.append({"_id": ObjectId(str(log_id))})
    if not query:
        return None
    return log_records_col.find_one({"$or": query})


def find_alert_by_id(alert_id):
    """Look up an alert document by integer id or ObjectId."""
    if alert_id is None:
        return None
    query = []
    try:
        query.append({"id": int(alert_id)})
    except (ValueError, TypeError):
        pass
    if ObjectId.is_valid(str(alert_id)):
        query.append({"_id": ObjectId(str(alert_id))})
    if not query:
        return None
    return alerts_col.find_one({"$or": query})
