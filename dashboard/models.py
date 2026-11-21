"""Database models — matches the ERD in SRS §6.5.

User 1──* Alert (acknowledges)
LogRecord 1──1 ClassificationResult 1──0..1 Alert
Plus Setting (key/value config) and AuditLog (SRS §3.2.7 admin actions).
"""
import json
from datetime import datetime, timezone

import bcrypt
from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(32), default="admin", nullable=False)

    def set_password(self, raw: str):
        self.password_hash = bcrypt.hashpw(raw.encode(), bcrypt.gensalt()).decode()

    def check_password(self, raw: str) -> bool:
        try:
            return bcrypt.checkpw(raw.encode(), self.password_hash.encode())
        except ValueError:
            return False


class LogRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utcnow, index=True, nullable=False)
    src_ip = db.Column(db.String(45))
    dst_ip = db.Column(db.String(45))
    protocol_type = db.Column(db.String(16))
    service = db.Column(db.String(32))
    flag = db.Column(db.String(16))
    duration = db.Column(db.Float)
    src_bytes = db.Column(db.Float)
    dst_bytes = db.Column(db.Float)
    features_json = db.Column(db.Text, nullable=False)  # every feature fed to the model
    true_label = db.Column(db.String(32))  # ground-truth label when replaying a labelled dataset
    source = db.Column(db.String(16), default="replay")  # replay | api | manual

    result = db.relationship("ClassificationResult", back_populates="log", uselist=False,
                             cascade="all, delete-orphan")

    @property
    def features(self):
        return json.loads(self.features_json)


class ClassificationResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    log_id = db.Column(db.Integer, db.ForeignKey("log_record.id"), unique=True, nullable=False)
    anomaly_score = db.Column(db.Float)        # Isolation Forest, normalised 0-1
    rf_probability = db.Column(db.Float)       # Random Forest P(attack), 0-1 (nullable)
    threat_score = db.Column(db.Float, index=True, nullable=False)  # combined score used for tiering
    tier = db.Column(db.String(16), index=True, nullable=False)    # Normal | Suspicious | Malicious
    attack_category = db.Column(db.String(16))  # DoS | Probe | R2L | U2R | None
    threshold_applied = db.Column(db.Float, nullable=False)
    suspicious_threshold_applied = db.Column(db.Float, nullable=False)
    model_version = db.Column(db.String(64))
    explanation_json = db.Column(db.Text)       # list of {feature, value, note}
    classified_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    log = db.relationship("LogRecord", back_populates="result")
    alert = db.relationship("Alert", back_populates="result", uselist=False,
                            cascade="all, delete-orphan")


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    result_id = db.Column(db.Integer, db.ForeignKey("classification_result.id"), unique=True, nullable=False)
    severity = db.Column(db.String(16), index=True, nullable=False)  # Suspicious | Malicious
    status = db.Column(db.String(16), default="open", index=True, nullable=False)  # open | acknowledged | dismissed
    created_at = db.Column(db.DateTime, default=utcnow, index=True, nullable=False)
    reviewed_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    reviewed_at = db.Column(db.DateTime)
    note = db.Column(db.String(500))
    email_status = db.Column(db.String(16), default="disabled")  # disabled | sent | failed

    result = db.relationship("ClassificationResult", back_populates="alert")
    reviewed_by = db.relationship("User")


class Setting(db.Model):
    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.String(256), nullable=False)


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=utcnow, index=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    action = db.Column(db.String(64), nullable=False)
    details = db.Column(db.String(500))

    user = db.relationship("User")


DEFAULT_SETTINGS = {
    "malicious_threshold": "0.50",   # = ml.predict._label() defaults
    "suspicious_threshold": "0.20",
    "use_anomaly_flag": "1",
    "alert_on_suspicious": "1",
    "email_alerts": "0",
    "replay_enabled": "1",
    "replay_interval": "2",
}


def get_setting(key, cast=str):
    row = db.session.get(Setting, key)
    raw = row.value if row else DEFAULT_SETTINGS[key]
    if cast is bool:
        return raw in ("1", "true", "True")
    return cast(raw)


def set_setting(key, value):
    row = db.session.get(Setting, key)
    if isinstance(value, bool):
        value = "1" if value else "0"
    if row:
        row.value = str(value)
    else:
        db.session.add(Setting(key=key, value=str(value)))
