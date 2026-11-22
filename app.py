"""AI-Based Cyber Threat Detection & Alerting System (ThreatWatch).

Unified application server combining the Flask dashboard UI, REST API,
MongoDB persistence, and ML threat detection engine.
"""
import csv
import io
import json
import logging
import os
import random
import secrets
import smtplib
import threading
import time
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps

from flask import (
    Flask,
    Response,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    stream_with_context,
    url_for,
)
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from flasgger import Swagger
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from google.oauth2 import id_token as google_id_token
from google.auth.transport import requests as google_requests
from pymongo.errors import PyMongoError, ServerSelectionTimeoutError

import simulator
from detector import ValidationError, detector, tier_for, validate
from db import (
    db,
    init_db_indexes,
    check_database_connection,
    users_col,
    log_records_col,
    alerts_col,
    settings_col,
    audit_logs_col,
)
from models import (
    DEFAULT_SETTINGS,
    MongoUser,
    alert_to_dict,
    audit,
    check_password,
    create_user,
    find_alert_by_id,
    find_log_by_id,
    find_or_create_firebase_user,
    find_user,
    find_user_by_email,
    find_user_by_id,
    get_next_sequence,
    get_setting,
    iso,
    log_to_dict,
    parse_dt,
    set_setting,
    utcnow,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("threatwatch")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.environ.get("SESSION_MINUTES", "30"))),
    SWAGGER={
        "title": "ThreatWatch - AI Cyber Threat Detection API",
        "uiversion": 3,
    },
)

swagger = Swagger(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"

limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per minute"],
    storage_uri="memory://",
    strategy="fixed-window",
)

# ---------------------------------------------------------------- Firebase Authentication (OAuth & Password Recovery)
FIREBASE_PROJECT_ID = os.environ.get("FIREBASE_PROJECT_ID", "threatwatch-a41a0").strip()
FIREBASE_API_KEY = os.environ.get("FIREBASE_API_KEY", "").strip()
FIREBASE_AUTH_DOMAIN = os.environ.get("FIREBASE_AUTH_DOMAIN", f"{FIREBASE_PROJECT_ID}.firebaseapp.com").strip()
FIREBASE_STORAGE_BUCKET = os.environ.get("FIREBASE_STORAGE_BUCKET", f"{FIREBASE_PROJECT_ID}.firebasestorage.app").strip()
FIREBASE_MESSAGING_SENDER_ID = os.environ.get("FIREBASE_MESSAGING_SENDER_ID", "").strip()
FIREBASE_APP_ID = os.environ.get("FIREBASE_APP_ID", "").strip()
FIREBASE_MEASUREMENT_ID = os.environ.get("FIREBASE_MEASUREMENT_ID", "").strip()
ALLOWED_DOMAINS = [
    d.strip().lower()
    for d in os.environ.get("ALLOWED_DOMAINS", "").split(",")
    if d.strip()
]


def is_firebase_configured():
    """Return True if Firebase project ID and API key are configured in the environment."""
    return bool(FIREBASE_PROJECT_ID and FIREBASE_API_KEY)


@app.context_processor
def inject_firebase_context():
    """Inject Firebase configuration and status globally into all Jinja templates."""
    return {
        "firebase_enabled": is_firebase_configured(),
        "firebase_config": {
            "apiKey": FIREBASE_API_KEY,
            "authDomain": FIREBASE_AUTH_DOMAIN,
            "projectId": FIREBASE_PROJECT_ID,
            "storageBucket": FIREBASE_STORAGE_BUCKET,
            "messagingSenderId": FIREBASE_MESSAGING_SENDER_ID,
            "appId": FIREBASE_APP_ID,
            "measurementId": FIREBASE_MEASUREMENT_ID,
        },
    }


@login_manager.user_loader
def load_user(uid):
    return find_user_by_id(uid)


@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith("/api/"):
        return jsonify(error="Authentication required"), 401
    return redirect(url_for("login", next=request.path))


# ---------------------------------------------------------------- Role-Based Access Control (RBAC)
def role_required(*allowed_roles):
    """Enforce that the authenticated user possesses one of the allowed RBAC roles."""
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                if request.path.startswith("/api/"):
                    return jsonify(error="Authentication required"), 401
                return redirect(url_for("login", next=request.path))

            user_role = getattr(current_user, "role", "analyst")
            if user_role not in allowed_roles:
                log.warning(
                    "RBAC permission denied for user '%s' (role: '%s') on '%s' (required: %s)",
                    getattr(current_user, "username", "unknown"),
                    user_role,
                    request.path,
                    allowed_roles,
                )
                if request.path.startswith("/api/"):
                    return jsonify(error="Permission denied: Administrator privileges required"), 403
                flash("Access denied: Administrator privileges required for this page.", "error")
                return redirect(url_for("dashboard"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def admin_required(fn):
    """Enforce that the endpoint is restricted exclusively to administrators."""
    return role_required("admin")(fn)


# ---------------------------------------------------------------- CSRF Protection
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


def _valid_api_key():
    key = os.environ.get("INGEST_API_KEY")
    sent = request.headers.get("X-API-Key")
    return bool(key and sent and secrets.compare_digest(key, sent))


@app.before_request
def canonicalize_host():
    """Ensure browser access on 127.0.0.1 is redirected to localhost for Firebase OAuth compatibility."""
    if app.config.get("TESTING"):
        return
    if request.method == "GET" and not request.path.startswith("/api/") and (request.host.startswith("127.0.0.1:") or request.host == "127.0.0.1"):
        target_url = request.url.replace("127.0.0.1", "localhost", 1)
        return redirect(target_url, code=302)


@app.before_request
def check_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        # API endpoints with valid API key or machine ingestion
        if request.path in ("/api/classify", "/api/predict") and _valid_api_key():
            return
        # Allow internal predict API if explicitly called without UI session
        if request.path == "/api/predict" and not request.cookies.get("session"):
            return
        # Firebase authentication uses signed Google ID tokens with built-in replay protection
        if request.path == "/api/auth/firebase-login":
            return
        sent = request.headers.get("X-CSRF-Token") or request.form.get("_csrf")
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            if request.path.startswith("/api/"):
                return jsonify(error="Invalid or missing CSRF token"), 400
            abort(400, "Invalid or missing CSRF token — reload the page and try again.")


# ---------------------------------------------------------------- HTTP Security Headers
@app.after_request
def add_security_headers(response):
    """Enforce defense-in-depth HTTP security headers (OWASP recommended)."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), "
        "magnetometer=(), microphone=(), payment=(), usb=()"
    )
    if os.environ.get("HTTPS", "0") == "1":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Cross-Origin-Opener-Policy allows Firebase OAuth popup communication without context isolation severing opener handle
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin-allow-popups"

    # CSP for dashboard assets (Google Fonts, local styles/scripts, Chart.js, inline SVG/data URIs, Firebase SDK & Google APIs)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://www.gstatic.com https://apis.google.com https://accounts.google.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com data:; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://*.googleapis.com https://*.firebaseio.com https://*.firebaseapp.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://accounts.google.com https://apis.google.com; "
        "frame-src 'self' https://*.firebaseapp.com https://accounts.google.com https://*.google.com;"
    )
    return response


# ---------------------------------------------------------------- Pipeline: Ingest -> Classify -> Persist -> Alert
_ingest_lock = threading.Lock()


def _thresholds():
    return (
        get_setting("malicious_threshold", float),
        get_setting("suspicious_threshold", float),
        get_setting("use_anomaly_flag", bool),
    )


def _decide(out, mal_t, sus_t, use_flag):
    """Model output -> (threat_score, tier, category)."""
    score = float(out["threat_score"])
    tier = tier_for(score, sus_t, mal_t, bool(out.get("anomaly_flag")) and use_flag)
    category = out.get("attack_category")
    if category is None and tier != "Normal" and out.get("model_version", "").startswith("team-ml"):
        category = (
            "Known attack (RF)"
            if score >= mal_t
            else "Uncertain (RF)"
            if score >= sus_t
            else "Anomaly only (IF)"
        )
    return score, tier, category


def ingest(features, true_label=None, src_ip=None, dst_ip=None, source="api", at=None):
    """Validate, score, save to MongoDB, and generate alert if flagged."""
    clean = validate(features)
    out = detector.score(clean)
    mal_t, sus_t, use_flag = _thresholds()
    score, tier, category = _decide(out, mal_t, sus_t, use_flag)
    now = at or utcnow()

    with _ingest_lock:
        seq_log_id = get_next_sequence("log_record_id")
        result_payload = {
            "threat_score": score,
            "tier": tier,
            "attack_category": category if tier != "Normal" else None,
            "anomaly_score": out.get("anomaly_score"),
            "rf_probability": out.get("rf_probability"),
            "anomaly_flag": bool(out.get("anomaly_flag")),
            "threshold_applied": mal_t,
            "suspicious_threshold_applied": sus_t,
            "model_version": out.get("model_version"),
            "explanation": out.get("explanation") or [],
            "classified_at": now,
        }

        lr_doc = {
            "id": seq_log_id,
            "timestamp": now,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol_type": clean["protocol_type"],
            "service": clean["service"],
            "flag": clean["flag"],
            "duration": clean["duration"],
            "src_bytes": clean["src_bytes"],
            "dst_bytes": clean["dst_bytes"],
            "features": clean,
            "true_label": true_label,
            "source": source,
            "result": result_payload,
            "alert_id": None,
            "alert_status": None,
        }

        alert_doc = None
        if tier == "Malicious" or (tier == "Suspicious" and get_setting("alert_on_suspicious", bool)):
            seq_alert_id = get_next_sequence("alert_id")
            alert_doc = {
                "id": seq_alert_id,
                "log_id": seq_log_id,
                "severity": tier,
                "status": "open",
                "created_at": now,
                "reviewed_by": None,
                "reviewed_at": None,
                "note": None,
                "email_status": "disabled",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": clean["protocol_type"],
                "service": clean["service"],
                "threat_score": score,
                "attack_category": category,
            }
            if tier == "Malicious" and get_setting("email_alerts", bool) and _smtp_configured():
                alert_doc["email_status"] = "pending"

            alerts_col.insert_one(alert_doc)
            lr_doc["alert_id"] = seq_alert_id
            lr_doc["alert_status"] = "open"

        log_records_col.insert_one(lr_doc)

    if alert_doc is not None and alert_doc.get("email_status") == "pending":
        threading.Thread(target=_send_email, args=(alert_doc["id"],), daemon=True).start()

    return lr_doc, result_payload, alert_doc


def _smtp_configured():
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("ALERT_EMAIL_TO"))


def _send_email(alert_id):
    """Send SMTP email alert in background thread."""
    a = find_alert_by_id(alert_id)
    if not a:
        return
    msg = EmailMessage()
    msg["Subject"] = f"[ThreatWatch] {a.get('severity')} activity from {a.get('src_ip')}"
    msg["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", "threatwatch@localhost"))
    msg["To"] = os.environ["ALERT_EMAIL_TO"]
    msg.set_content(
        f"Severity: {a.get('severity')}\n"
        f"Threat score: {a.get('threat_score', 0):.3f}\n"
        f"Category: {a.get('attack_category') or 'n/a'}\n"
        f"Source: {a.get('src_ip')} -> {a.get('dst_ip')}\n"
        f"Protocol/service: {a.get('protocol')}/{a.get('service')}\n"
        f"Time (UTC): {iso(a.get('created_at'))}\n\n"
        f"Review it in the dashboard: alert #{a.get('id')}, log #{a.get('log_id')}."
    )
    try:
        with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", "587")), timeout=10) as s:
            s.starttls()
            if os.environ.get("SMTP_USER"):
                s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
            s.send_message(msg)
        alerts_col.update_one({"id": a["id"]}, {"$set": {"email_status": "sent"}})
    except Exception as e:
        log.error("Alert email delivery failed for alert #%s: %s", alert_id, e)
        alerts_col.update_one({"id": a["id"]}, {"$set": {"email_status": "failed"}})


# ---------------------------------------------------------------- Error Handlers
@app.errorhandler(PyMongoError)
def mongo_error(e):
    log.error("MongoDB error: %s", e)
    if request.path.startswith("/api/"):
        return jsonify(error="The data store is temporarily unavailable. Please retry shortly."), 503
    return (
        render_template(
            "error.html",
            code=503,
            message="The data store is temporarily unavailable. Please retry shortly.",
        ),
        503,
    )


@app.errorhandler(ValidationError)
def bad_input(e):
    if request.path.startswith("/api/"):
        return jsonify(error=str(e)), 400
    return render_template("error.html", code=400, message=str(e)), 400


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify(error="Not found"), 404
    return render_template("error.html", code=404, message="That page doesn't exist."), 404


@app.errorhandler(400)
def bad_request(e):
    if request.path.startswith("/api/"):
        return jsonify(error=getattr(e, "description", "Bad request")), 400
    return render_template("error.html", code=400, message=getattr(e, "description", "Bad request")), 400


@app.errorhandler(429)
def ratelimit_exceeded(e):
    log.warning("Rate limit exceeded for IP %s: %s", request.remote_addr, e.description)
    if request.path.startswith("/api/"):
        return jsonify(
            error="Too Many Requests",
            message="Rate limit exceeded. Please slow down your requests.",
            details=str(e.description),
        ), 429
    return (
        render_template(
            "error.html",
            code=429,
            message=f"Too many requests from your IP ({e.description}). Please wait a moment and try again.",
        ),
        429,
    )


# ---------------------------------------------------------------- Authentication
_failed = {}  # ip -> (count, first_ts)


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute", methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    error = None
    if request.method == "POST":
        ip = request.remote_addr or "?"
        cnt, t0 = _failed.get(ip, (0, time.time()))
        if cnt >= 5 and time.time() - t0 < 60:
            error = "Too many failed attempts. Wait a minute and try again."
        else:
            email = (request.form.get("email") or request.form.get("username") or "").strip().lower()
            password = request.form.get("password", "")

            # Strict email format validation: reject any non-email string or invalid format
            import re
            EMAIL_REGEX = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
            if not email or not re.match(EMAIL_REGEX, email):
                _failed[ip] = (
                    cnt + 1 if time.time() - t0 < 60 else 1,
                    t0 if time.time() - t0 < 60 else time.time(),
                )
                error = "Email is not valid. Please enter a valid email address format (e.g. name@domain.com)."
                return render_template("login.html", error=error), 401

            # Authenticate strictly via Firebase Authentication
            authenticated = False
            user = None
            if is_firebase_configured():
                fb_api_key = os.environ.get("FIREBASE_API_KEY")
                if fb_api_key:
                    try:
                        import requests as http_requests
                        url = f"https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key={fb_api_key}"
                        fb_res = http_requests.post(
                            url,
                            json={"email": email, "password": password, "returnSecureToken": True},
                            timeout=6,
                        )
                        if fb_res.status_code == 200:
                            fb_data = fb_res.json()
                            uid = fb_data.get("localId")
                            user = find_or_create_firebase_user(
                                email=email,
                                uid=uid,
                                display_name=email.split("@")[0],
                            )
                            authenticated = True
                    except Exception as fb_err:
                        log.warning("Firebase auth check notice: %s", fb_err)

            # Check provisioned user in database (for offline CI environments or mongomock fixtures)
            if not authenticated:
                existing_user = find_user_by_email(email)
                if existing_user and check_password(existing_user, password):
                    user = existing_user
                    authenticated = True

            if authenticated and user:
                _failed.pop(ip, None)
                session.clear()
                session.permanent = True
                login_user(user)
                csrf_token()
                audit("login", f"{user.username} ({user.email}) signed in from {ip}", user.id)
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))

            _failed[ip] = (
                cnt + 1 if time.time() - t0 < 60 else 1,
                t0 if time.time() - t0 < 60 else time.time(),
            )
            error = "Invalid email or password."
    return render_template("login.html", error=error), (401 if error else 200)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout", current_user.username, current_user.id)
    logout_user()
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/auth/firebase-login", methods=["POST"])
@limiter.limit("15 per minute")
def api_firebase_login():
    """Verify Firebase ID token (JWT) and authenticate user session into MongoDB.

    Expects JSON payload: { "idToken": "<firebase_id_token>" }
    Returns JSON: { "success": True, "redirect": "/", "user": { ... } }
    """
    if not is_firebase_configured():
        return jsonify(error="Firebase Authentication is not configured on the server"), 503

    payload = request.get_json(silent=True) or {}
    token = payload.get("idToken")
    if not token or not isinstance(token, str):
        return jsonify(error="Missing or invalid idToken in request payload"), 400

    try:
        # Cryptographically verify Firebase ID token using Google's public certs
        decoded = google_id_token.verify_firebase_token(
            token,
            google_requests.Request(),
            audience=FIREBASE_PROJECT_ID,
        )
    except Exception as exc:
        log.warning("Firebase ID token verification failed: %s", exc)
        return jsonify(error=f"Invalid or expired Firebase token: {exc}"), 401

    email = decoded.get("email")
    if not email:
        return jsonify(error="Token does not contain a verified email address"), 400

    # Whitelist domain validation if ALLOWED_DOMAINS is configured
    if ALLOWED_DOMAINS:
        email_domain = email.split("@")[-1].lower()
        if email_domain not in ALLOWED_DOMAINS:
            return jsonify(error=f"Domain @{email_domain} is not authorized to access this system"), 403

    uid = decoded.get("sub") or decoded.get("user_id")
    name = decoded.get("name")

    try:
        user = find_or_create_firebase_user(
            email=email,
            uid=uid,
            display_name=name,
        )
    except Exception as exc:
        log.error("Failed to provision/sync Firebase user in MongoDB: %s", exc)
        return jsonify(error="Database error while provisioning user account"), 500

    # Establish secure Flask session
    session.clear()
    session.permanent = True
    login_user(user)
    csrf_token()

    # Audit logging
    provider = decoded.get("firebase", {}).get("sign_in_provider", "firebase")
    audit("firebase_login", f"{user.username} authenticated via Firebase ({provider}) from {request.remote_addr}", user.id)

    return jsonify(
        success=True,
        redirect=url_for("dashboard"),
        user=user.to_dict(),
    ), 200


# ---------------------------------------------------------------- Web Pages
@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", page="dashboard")


@app.route("/logs")
@login_required
def logs_page():
    return render_template("logs.html", page="logs")


@app.route("/alerts")
@login_required
def alerts_page():
    return render_template("alerts.html", page="alerts")


@app.route("/settings", methods=["GET", "POST"])
@login_required
@admin_required
def settings_page():
    if request.method == "POST":
        action = request.form.get("action", "save")
        if action == "reload_models":
            st = detector.load()
            audit("model_reload", f"detector mode: {st['mode']}", current_user.id)
            flash(f"Models reloaded — detector is now using: {st['mode']}.", "ok")
            return redirect(url_for("settings_page"))
        try:
            sus = float(request.form["suspicious_threshold"])
            mal = float(request.form["malicious_threshold"])
            interval = float(request.form.get("replay_interval", 2))
        except (KeyError, ValueError):
            flash("Thresholds and interval must be numbers.", "error")
            return redirect(url_for("settings_page"))
        if not (0 < sus < mal <= 1):
            flash("Thresholds must satisfy 0 < suspicious < malicious ≤ 1.", "error")
            return redirect(url_for("settings_page"))
        if not (0.5 <= interval <= 60):
            flash("Replay interval must be between 0.5 and 60 seconds.", "error")
            return redirect(url_for("settings_page"))
        new = {
            "suspicious_threshold": f"{sus:.2f}",
            "malicious_threshold": f"{mal:.2f}",
            "alert_on_suspicious": "1" if request.form.get("alert_on_suspicious") else "0",
            "use_anomaly_flag": "1" if request.form.get("use_anomaly_flag") else "0",
            "email_alerts": "1" if request.form.get("email_alerts") else "0",
            "replay_enabled": "1" if request.form.get("replay_enabled") else "0",
            "replay_interval": f"{interval:g}",
        }
        changes = []
        for k, v in new.items():
            old = get_setting(k)
            if str(old) != v:
                changes.append(f"{k}: {old} → {v}")
                set_setting(k, v)
        if changes:
            audit("settings_change", "; ".join(changes), current_user.id)
            flash("Settings saved. New thresholds apply to records classified from now on.", "ok")
        else:
            flash("No changes.", "ok")
        return redirect(url_for("settings_page"))

    s = {k: get_setting(k) for k in ("suspicious_threshold", "malicious_threshold", "replay_interval")}
    s.update({k: get_setting(k, bool) for k in ("alert_on_suspicious", "email_alerts", "replay_enabled", "use_anomaly_flag")})
    audit_rows = list(audit_logs_col.find().sort("timestamp", -1).limit(50))
    return render_template(
        "settings.html",
        page="settings",
        s=s,
        audit_rows=audit_rows,
        det=detector.status(),
        smtp=_smtp_configured(),
        metrics=_team_metrics(),
        replay_source=app.config.get("REPLAY_SOURCE", "synthetic"),
        replay_file=app.config.get("REPLAY_FILE"),
        iso=iso,
    )


def _team_metrics():
    """First table of results/metrics.md if available."""
    st = detector.status()
    if not st.get("team_module"):
        return None
    path = os.path.join(os.path.dirname(st["team_module"]), "results", "metrics.md")
    if not os.path.exists(path):
        return None
    rows, started = [], False
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line.startswith("|"):
                cells = [c.strip() for c in line.strip("|").split("|")]
                if set("".join(cells)) <= set("-: "):
                    continue
                rows.append(cells)
                started = True
            elif started:
                break
    return {"header": rows[0], "rows": rows[1:]} if len(rows) > 1 else None


def _live_eval():
    """Evaluate verdicts vs ground-truth labels for replayed dataset rows."""
    pipeline = [
        {"$match": {"true_label": {"$ne": None}}},
        {
            "$project": {
                "actual": {"$cond": [{"$eq": ["$true_label", "normal"]}, 0, 1]},
                "pred": {"$cond": [{"$eq": ["$result.tier", "Normal"]}, 0, 1]},
            }
        },
        {"$group": {"_id": {"actual": "$actual", "pred": "$pred"}, "count": {"$sum": 1}}},
    ]
    rows = list(log_records_col.aggregate(pipeline))
    c = {(r["_id"]["actual"], r["_id"]["pred"]): r["count"] for r in rows}
    tp, fp, tn, fn = c.get((1, 1), 0), c.get((0, 1), 0), c.get((0, 0), 0), c.get((1, 0), 0)
    n = tp + fp + tn + fn
    if not n:
        return None
    return {
        "n": n,
        "accuracy": round((tp + tn) / n, 4),
        "precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
        "recall": round(tp / (tp + fn), 4) if (tp + fn) else None,
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
    }


def _risk_level():
    """Calculate system threat risk level."""
    recent = list(
        log_records_col.find({"result.tier": {"$exists": True}}, {"result.tier": 1})
        .sort("timestamp", -1)
        .limit(200)
    )
    n = len(recent) or 1
    mal = sum(1 for r in recent if r.get("result", {}).get("tier") == "Malicious")
    sus = sum(1 for r in recent if r.get("result", {}).get("tier") == "Suspicious")
    ratio = (mal + 0.4 * sus) / n
    cutoff_10m = utcnow() - timedelta(minutes=10)
    open_mal = alerts_col.count_documents({
        "status": "open",
        "severity": "Malicious",
        "created_at": {"$gte": cutoff_10m},
    })
    if ratio >= 0.25 or open_mal >= 25:
        level = "Critical"
    elif ratio >= 0.12 or open_mal >= 10:
        level = "High"
    elif ratio >= 0.05 or open_mal >= 1:
        level = "Elevated"
    else:
        level = "Low"
    return {
        "level": level,
        "ratio": round(ratio, 3),
        "open_malicious_10m": open_mal,
        "window": len(recent),
    }


# ---------------------------------------------------------------- REST API Endpoints
@app.route("/api/classify", methods=["POST"])
@limiter.limit("60 per minute")
def api_classify():
    """
    Ingest and classify network traffic via ML models
    ---
    tags:
      - Intrusion Detection
    consumes:
      - application/json
    responses:
      201:
        description: Traffic classified and recorded
      400:
        description: Malformed traffic data
      401:
        description: Authentication required
    """
    if not (current_user.is_authenticated or _valid_api_key()):
        return jsonify(error="Authentication required"), 401
    body = request.get_json(silent=True)
    if body is None:
        return jsonify(error="Body must be JSON (Content-Type: application/json)."), 400
    meta = {k: body.pop(k, None) for k in ("src_ip", "dst_ip", "label")}
    lr_doc, result_payload, alert_doc = ingest(
        body,
        true_label=meta["label"],
        src_ip=meta["src_ip"] or request.remote_addr,
        dst_ip=meta["dst_ip"],
        source="manual" if current_user.is_authenticated else "api",
    )
    return (
        jsonify(
            log_id=lr_doc["id"],
            threat_score=round(result_payload["threat_score"], 4),
            classification=result_payload["tier"],
            is_alert=alert_doc is not None,
            anomaly_score=result_payload["anomaly_score"],
            rf_probability=result_payload["rf_probability"],
            attack_category=result_payload["attack_category"],
        ),
        201,
    )


@app.route("/api/predict", methods=["POST"])
@limiter.limit("120 per minute")
def api_predict():
    """
    Backward-compatible prediction endpoint for traffic simulator
    ---
    tags:
      - Intrusion Detection
    consumes:
      - application/json
    responses:
      200:
        description: Prediction successfully generated and stored
      400:
        description: Invalid request payload
    """
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify(success=False, error="Request body must be a JSON object"), 400
    traffic = data.get("traffic", data)
    if not isinstance(traffic, dict):
        return jsonify(success=False, error="Traffic data must be a JSON object"), 400

    lr_doc, result_payload, alert_doc = ingest(
        traffic,
        src_ip=traffic.get("src_ip") or request.remote_addr,
        dst_ip=traffic.get("dst_ip"),
        source="api",
    )

    severity_map = {"Normal": "Low", "Suspicious": "Medium", "Malicious": "High"}
    label = result_payload["tier"]
    severity = severity_map.get(label, "Low")

    response = {
        "success": True,
        "prediction": {
            "label": label,
            "score": round(result_payload["threat_score"], 4),
            "severity": severity,
        },
        "threat_score": round(result_payload["threat_score"], 4),
        "tier": label,
        "anomaly_detected": result_payload.get("anomaly_detected", False),
        "attack_category": result_payload.get("attack_category", "Normal"),
        "log_id": str(lr_doc["id"]),
        "timestamp": iso(lr_doc["timestamp"]),
    }
    if alert_doc:
        response["alert"] = {
            "alert_id": str(alert_doc["id"]),
            "status": "created",
        }
    else:
        response["alert"] = None

    return jsonify(response), 200


@app.route("/api/stats")
@login_required
def api_stats():
    """Dashboard metrics, histogram, categories, time series, and sources."""
    minutes = min(max(int(request.args.get("minutes", 30)), 5), 1440)
    pipeline_tiers = [
        {"$group": {"_id": "$result.tier", "count": {"$sum": 1}}}
    ]
    tier_counts = {r["_id"]: r["count"] for r in log_records_col.aggregate(pipeline_tiers) if r["_id"]}
    total = sum(tier_counts.values())
    since = utcnow() - timedelta(minutes=minutes)

    # Time series buckets
    bucket_mins = 1 if minutes <= 60 else (5 if minutes <= 360 else 15)
    rows = list(
        log_records_col.find(
            {"timestamp": {"$gte": since}, "result.tier": {"$exists": True}},
            {"timestamp": 1, "result.tier": 1},
        )
    )
    start = since.replace(second=0, microsecond=0)
    start -= timedelta(minutes=start.minute % bucket_mins)
    nb = int((utcnow() - start).total_seconds() // (bucket_mins * 60)) + 1
    series = [
        {"t": iso(start + timedelta(minutes=i * bucket_mins)), "Normal": 0, "Suspicious": 0, "Malicious": 0}
        for i in range(nb)
    ]
    for r in rows:
        ts = r["timestamp"]
        if hasattr(ts, "tzinfo"):
            if ts.tzinfo is None and start.tzinfo is not None:
                ts = ts.replace(tzinfo=timezone.utc)
            elif ts.tzinfo is not None and start.tzinfo is None:
                ts = ts.replace(tzinfo=None)
        tier = r.get("result", {}).get("tier")
        if tier in ("Normal", "Suspicious", "Malicious"):
            i = int((ts - start).total_seconds() // (bucket_mins * 60))
            if 0 <= i < nb:
                series[i][tier] += 1

    pipeline_cats = [
        {"$match": {"result.attack_category": {"$ne": None}}},
        {"$group": {"_id": "$result.attack_category", "count": {"$sum": 1}}},
    ]
    cats = {r["_id"]: r["count"] for r in log_records_col.aggregate(pipeline_cats) if r["_id"]}

    scores = [
        r["result"]["threat_score"]
        for r in log_records_col.find(
            {"result.threat_score": {"$exists": True}},
            {"result.threat_score": 1},
        )
        .sort("id", -1)
        .limit(2000)
    ]
    hist = [0] * 20
    for s in scores:
        hist[min(int(s * 20), 19)] += 1

    pipeline_top = [
        {"$match": {"result.tier": {"$in": ["Suspicious", "Malicious"]}}},
        {"$group": {"_id": "$src_ip", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 5},
    ]
    top_sources = [
        {"ip": r["_id"], "count": r["count"]}
        for r in log_records_col.aggregate(pipeline_top)
        if r["_id"]
    ]

    last_doc = log_records_col.find_one(sort=[("timestamp", -1)])

    return jsonify(
        total=total,
        normal=tier_counts.get("Normal", 0),
        suspicious=tier_counts.get("Suspicious", 0),
        malicious=tier_counts.get("Malicious", 0),
        threats=tier_counts.get("Suspicious", 0) + tier_counts.get("Malicious", 0),
        open_alerts=alerts_col.count_documents({"status": "open"}),
        risk=_risk_level(),
        series=series,
        bucket_minutes=bucket_mins,
        categories=(
            dict(sorted(cats.items(), key=lambda kv: -kv[1]))
            if detector.status()["mode"].startswith("team")
            else {k: cats.get(k, 0) for k in ("DoS", "Probe", "R2L", "U2R")}
        ),
        evaluation=_live_eval(),
        score_hist=hist,
        score_sample=len(scores),
        top_sources=top_sources,
        thresholds={
            "suspicious": get_setting("suspicious_threshold", float),
            "malicious": get_setting("malicious_threshold", float),
            "anomaly_flag": get_setting("use_anomaly_flag", bool),
        },
        detector=detector.status(),
        replay=get_setting("replay_enabled", bool),
        last_record_at=iso(last_doc["timestamp"]) if last_doc else None,
        server_time=iso(utcnow()),
    )


def _build_log_filter(args):
    filt = {}
    tiers = [t for t in args.get("tier", "").split(",") if t in ("Normal", "Suspicious", "Malicious")]
    if tiers:
        filt["result.tier"] = {"$in": tiers}
    if args.get("category"):
        filt["result.attack_category"] = args["category"]
    time_filter = {}
    if args.get("start"):
        time_filter["$gte"] = parse_dt(args["start"])
    if args.get("end"):
        time_filter["$lte"] = parse_dt(args["end"])
    if time_filter:
        filt["timestamp"] = time_filter

    score_filter = {}
    if args.get("min_score"):
        try:
            score_filter["$gte"] = float(args["min_score"])
        except ValueError:
            raise ValidationError("min_score must be a number")
    if args.get("max_score"):
        try:
            score_filter["$lte"] = float(args["max_score"])
        except ValueError:
            raise ValidationError("max_score must be a number")
    if score_filter:
        filt["result.threat_score"] = score_filter

    if args.get("q"):
        like = args["q"].strip()
        filt["$or"] = [
            {"src_ip": {"$regex": like, "$options": "i"}},
            {"dst_ip": {"$regex": like, "$options": "i"}},
            {"service": {"$regex": like, "$options": "i"}},
        ]
    if args.get("after_id"):
        try:
            filt["id"] = {"$gt": int(args["after_id"])}
        except ValueError:
            pass
    return filt


@app.route("/api/logs")
@login_required
def api_logs():
    """Retrieve filtered, paginated traffic logs."""
    page = max(int(request.args.get("page", 1)), 1)
    per = min(max(int(request.args.get("per_page", 25)), 1), 100)
    filt = _build_log_filter(request.args)

    sort_field = request.args.get("sort", "time")
    sort_key = "timestamp" if sort_field == "time" else ("result.threat_score" if sort_field == "score" else "id")
    sort_dir = 1 if request.args.get("order") == "asc" else -1

    total = log_records_col.count_documents(filt)
    cursor = (
        log_records_col.find(filt)
        .sort([(sort_key, sort_dir), ("id", -1)])
        .skip((page - 1) * per)
        .limit(per)
    )
    items = [log_to_dict(doc) for doc in cursor]
    pages = (total + per - 1) // per if per else 1

    return jsonify(items=items, page=page, pages=pages, total=total, per_page=per)


@app.route("/api/logs/<log_id>")
@login_required
def api_log_detail(log_id):
    """Retrieve full details for a single log record."""
    lr = find_log_by_id(log_id) or abort(404)
    return jsonify(log_to_dict(lr, full=True))


@app.route("/api/logs/export.csv")
@login_required
def api_logs_export():
    """Stream CSV export of filtered logs."""
    filt = _build_log_filter(request.args)
    audit("export_csv", f"filters: {dict(request.args)}", current_user.id)

    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow([
            "id",
            "timestamp_utc",
            "src_ip",
            "dst_ip",
            "protocol",
            "service",
            "flag",
            "src_bytes",
            "dst_bytes",
            "threat_score",
            "tier",
            "attack_category",
            "alert_status",
            "true_label",
        ])
        cursor = log_records_col.find(filt).sort("timestamp", -1).limit(50000)
        for lr in cursor:
            d = log_to_dict(lr)
            w.writerow([
                d["id"],
                d["timestamp"],
                d["src_ip"],
                d["dst_ip"],
                d["protocol"],
                d["service"],
                d["flag"],
                d["src_bytes"],
                d["dst_bytes"],
                d["threat_score"],
                d["tier"],
                d["attack_category"] or "",
                d["alert_status"] or "",
                lr.get("true_label") or "",
            ])
            yield buf.getvalue()
            buf.seek(0)
            buf.truncate(0)

    fname = f"threat_logs_{datetime.now():%Y%m%d_%H%M}.csv"
    return Response(
        stream_with_context(gen()),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


@app.route("/api/alerts")
@login_required
def api_alerts():
    """Retrieve paginated security alerts."""
    a = request.args
    filt = {}
    if a.get("status") in ("open", "acknowledged", "dismissed"):
        filt["status"] = a["status"]
    if a.get("severity") in ("Suspicious", "Malicious"):
        filt["severity"] = a["severity"]
    time_filter = {}
    if a.get("start"):
        time_filter["$gte"] = parse_dt(a["start"])
    if a.get("end"):
        time_filter["$lte"] = parse_dt(a["end"])
    if time_filter:
        filt["created_at"] = time_filter
    if a.get("since_id"):
        try:
            filt["id"] = {"$gt": int(a["since_id"])}
        except ValueError:
            pass

    page = max(int(a.get("page", 1)), 1)
    per = min(max(int(a.get("per_page", 25)), 1), 100)

    total = alerts_col.count_documents(filt)
    cursor = alerts_col.find(filt).sort([("created_at", -1), ("id", -1)]).skip((page - 1) * per).limit(per)
    items = [alert_to_dict(doc) for doc in cursor]
    pages = (total + per - 1) // per if per else 1

    counts = {
        "open": alerts_col.count_documents({"status": "open"}),
        "acknowledged": alerts_col.count_documents({"status": "acknowledged"}),
        "dismissed": alerts_col.count_documents({"status": "dismissed"}),
    }
    max_doc = alerts_col.find_one(sort=[("id", -1)])
    max_id = max_doc["id"] if max_doc and "id" in max_doc else 0

    return jsonify(items=items, page=page, pages=pages, total=total, counts=counts, max_id=max_id)


@app.route("/api/alerts/<alert_id>/<action>", methods=["POST"])
@login_required
def api_alert_action(alert_id, action):
    """Update status of a security alert."""
    if action not in ("acknowledge", "dismiss", "reopen"):
        abort(404)
    a = find_alert_by_id(alert_id) or abort(404)
    body = request.get_json(silent=True) or {}

    new_status = {"acknowledge": "acknowledged", "dismiss": "dismissed", "reopen": "open"}[action]
    update_doc = {
        "status": new_status,
        "reviewed_by": current_user.username if action != "reopen" else None,
        "reviewed_at": utcnow() if action != "reopen" else None,
    }
    if body.get("note") is not None:
        update_doc["note"] = str(body["note"])[:500]

    alerts_col.update_one({"_id": a["_id"]}, {"$set": update_doc})
    log_records_col.update_one({"alert_id": a["id"]}, {"$set": {"alert_status": new_status}})

    audit(f"alert_{action}", f"alert #{a.get('id')} ({a.get('severity')}, log #{a.get('log_id')})", current_user.id)
    a.update(update_doc)
    return jsonify(alert_to_dict(a))


@app.route("/api/alerts/acknowledge-all", methods=["POST"])
@login_required
def api_alert_ack_all():
    """Bulk acknowledge open alerts."""
    sev = (request.get_json(silent=True) or {}).get("severity")
    filt = {"status": "open"}
    if sev in ("Suspicious", "Malicious"):
        filt["severity"] = sev

    now = utcnow()
    res = alerts_col.update_many(
        filt,
        {"$set": {"status": "acknowledged", "reviewed_by": current_user.username, "reviewed_at": now}},
    )
    n = res.modified_count
    log_records_col.update_many({"alert_status": "open"}, {"$set": {"alert_status": "acknowledged"}})

    audit("alert_acknowledge_bulk", f"{n} open {sev or 'all'} alerts", current_user.id)
    return jsonify(acknowledged=n)


@app.route("/api/health")
def api_health():
    """System health check verifying backend, database, and ML detector."""
    try:
        check_database_connection()
        db_ok = True
    except Exception:
        db_ok = False

    det_status = detector.status()
    is_healthy = db_ok and not det_status.get("error")
    return (
        jsonify(
            status="ok" if is_healthy else "degraded",
            service="ThreatWatch AI-IDS",
            database="connected" if db_ok else "disconnected",
            detector=det_status,
            timestamp=iso(utcnow()),
        ),
        200 if is_healthy else 503,
    )


# ---------------------------------------------------------------- Bootstrapping & History Seeding
def seed_history(minutes=45, rate_per_min=12):
    """Pre-populate demo history on an empty database."""
    dataset_path = simulator.find_dataset()
    if dataset_path and os.environ.get("SEED_ROWS", "all") != "0":
        return backfill_dataset(dataset_path)

    next_record, _, _ = simulator.make_source()
    now = utcnow()
    n = minutes * rate_per_min
    for i in range(n):
        at = now - timedelta(seconds=(n - i) * 60 / rate_per_min + random.uniform(0, 4))
        f, label, src, dst = next_record()
        ingest(f, true_label=label, src_ip=src, dst_ip=dst, source="replay", at=at)

    _mark_old_alerts_reviewed(now - timedelta(minutes=20))
    log.info("Seeded %d historical records", n)


def _mark_old_alerts_reviewed(before):
    """Auto-triage older demo alerts for realism."""
    alerts_col.update_many(
        {"created_at": {"$lt": before}, "status": "open"},
        {"$set": {"status": "acknowledged", "reviewed_by": "system", "reviewed_at": before}},
    )


def backfill_dataset(path, hours=24, chunk=2000):
    """Load dataset rows in batches and distribute timestamps over past hours."""
    t0 = time.time()
    rows = simulator.CsvReplayer(path)._rows
    limit = os.environ.get("SEED_ROWS", "all")
    if limit.isdigit():
        rows = rows[: int(limit)]
    good = []
    for f, label in rows:
        try:
            good.append((validate(f), label))
        except ValidationError:
            pass

    n = len(good)
    log.info("Backfilling %d dataset rows into MongoDB from %s...", n, os.path.basename(path))
    now = utcnow()
    span = hours * 3600
    for start_idx in range(0, n, chunk):
        part = good[start_idx : start_idx + chunk]
        outs = detector.score_batch([f for f, _ in part])
        for j, ((f, label), out) in enumerate(zip(part, outs)):
            i = start_idx + j
            at = now - timedelta(seconds=span * (n - i) / n + random.uniform(0, 2))
            attack = label not in (None, "normal")
            src = (
                random.choice(simulator.ATTACKERS)
                if attack and random.random() < 0.7
                else random.choice(simulator.EXTERNAL + simulator.INTERNAL)
            )
            ingest(f, true_label=label, src_ip=src, dst_ip=random.choice(simulator.INTERNAL), source="replay", at=at)

    _mark_old_alerts_reviewed(now - timedelta(minutes=30))
    log.info("Backfilled %d records in %.1fs", n, time.time() - t0)


def init():
    """Bootstrap database indexes, admin user, and background replay."""
    st = detector.status()
    log.info("Detection Engine: %s (team module: %s)", st["mode"], st.get("team_module"))
    if st.get("error"):
        log.error("Detector initialization notice: %s", st["error"])

    try:
        init_db_indexes()
        if users_col.count_documents({}) == 0:
            admin_user = os.environ.get("ADMIN_USER", "admin")
            admin_pass = os.environ.get("ADMIN_PASSWORD", "admin123")
            create_user(username=admin_user, password=admin_pass, email="admin@threatwatch.local", role="admin")
            log.info("Created default admin user '%s' in MongoDB.", admin_user)

        if log_records_col.count_documents({}) == 0 and os.environ.get("SEED_DEMO", "1") == "1":
            seed_history()
    except Exception as e:
        log.warning("Database bootstrap notice (verify MongoDB connection): %s", e)

    if os.environ.get("REPLAY", "1") == "1":
        simulator.start(
            app,
            ingest_fn=lambda f, **kw: ingest(f, **kw),
            get_interval=lambda: get_setting("replay_interval", float),
            is_enabled=lambda: get_setting("replay_enabled", bool),
        )


if __name__ == "__main__":
    init()
    port = int(os.environ.get("PORT", 5000))
    host = os.environ.get("HOST", "127.0.0.1")
    log.info("Starting ThreatWatch AI-IDS Server on http://%s:%d", host, port)
    app.run(host=host, port=port, debug=False, use_reloader=False)
