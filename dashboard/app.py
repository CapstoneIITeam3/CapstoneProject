"""AI-Based Cyber Threat Detection & Alerting System — Flask dashboard (Team 38).

Run:   python app.py            -> http://127.0.0.1:5000   (login: admin / admin123 unless changed via env)
"""
import csv
import io
import json
import logging
import os
import secrets
import smtplib
import threading
import time
from datetime import datetime, timedelta
from email.message import EmailMessage
from functools import wraps

from flask import (Flask, Response, abort, flash, jsonify, redirect, render_template,
                   request, session, stream_with_context, url_for)
from flask_login import (LoginManager, current_user, login_required, login_user,
                         logout_user)
from sqlalchemy import func
from sqlalchemy.exc import OperationalError

import simulator
from detector import ValidationError, detector, tier_for, validate
from models import (Alert, AuditLog, ClassificationResult, LogRecord, Setting, User, db,
                    get_setting, set_setting, utcnow)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("dashboard")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "threats.db")),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=int(os.environ.get("SESSION_MINUTES", "30"))),
)
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.session_protection = "strong"


@login_manager.user_loader
def load_user(uid):
    return db.session.get(User, int(uid))


@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith("/api/"):
        return jsonify(error="Authentication required"), 401
    return redirect(url_for("login", next=request.path))


# ---------------------------------------------------------------- CSRF (tiny, no extra dependency)
def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        if request.path == "/api/classify" and _valid_api_key():
            return
        sent = request.headers.get("X-CSRF-Token") or request.form.get("_csrf")
        if not sent or not secrets.compare_digest(sent, session.get("_csrf", "")):
            if request.path.startswith("/api/"):
                return jsonify(error="Invalid or missing CSRF token"), 400
            abort(400, "Invalid or missing CSRF token — reload the page and try again.")


def _valid_api_key():
    key = os.environ.get("INGEST_API_KEY")
    sent = request.headers.get("X-API-Key")
    return bool(key and sent and secrets.compare_digest(key, sent))


def audit(action, details=""):
    db.session.add(AuditLog(user_id=current_user.id if current_user.is_authenticated else None,
                            action=action, details=details[:500]))


# ---------------------------------------------------------------- helpers
def iso(dt):
    return dt.isoformat(timespec="seconds") + "Z" if dt else None


def parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except ValueError:
        raise ValidationError(f"Bad date: {s}")


def log_to_dict(lr: LogRecord, full=False):
    r = lr.result
    d = {
        "id": lr.id, "timestamp": iso(lr.timestamp), "src_ip": lr.src_ip, "dst_ip": lr.dst_ip,
        "protocol": lr.protocol_type, "service": lr.service, "flag": lr.flag,
        "src_bytes": lr.src_bytes, "dst_bytes": lr.dst_bytes, "source": lr.source,
        "threat_score": round(r.threat_score, 4) if r else None,
        "tier": r.tier if r else None,
        "attack_category": r.attack_category if r else None,
        "alert_id": r.alert.id if r and r.alert else None,
        "alert_status": r.alert.status if r and r.alert else None,
    }
    if full:
        d.update(
            features=lr.features, true_label=lr.true_label,
            anomaly_score=r.anomaly_score, rf_probability=r.rf_probability,
            threshold_applied=r.threshold_applied, suspicious_threshold_applied=r.suspicious_threshold_applied,
            model_version=r.model_version, classified_at=iso(r.classified_at),
            explanation=json.loads(r.explanation_json or "[]"),
        )
    return d


def alert_to_dict(a: Alert):
    r = a.result
    lr = r.log
    return {
        "id": a.id, "severity": a.severity, "status": a.status, "created_at": iso(a.created_at),
        "log_id": lr.id, "src_ip": lr.src_ip, "dst_ip": lr.dst_ip, "protocol": lr.protocol_type,
        "service": lr.service, "threat_score": round(r.threat_score, 4), "attack_category": r.attack_category,
        "reviewed_by": a.reviewed_by.username if a.reviewed_by else None, "reviewed_at": iso(a.reviewed_at),
        "note": a.note, "email_status": a.email_status,
    }


# ---------------------------------------------------------------- pipeline: ingest -> classify -> alert
_ingest_lock = threading.Lock()


def _thresholds():
    return (get_setting("malicious_threshold", float), get_setting("suspicious_threshold", float),
            get_setting("use_anomaly_flag", bool))


def _decide(out, mal_t, sus_t, use_flag):
    """Model output -> (threat_score, tier, category). Same rule for live and bulk ingest."""
    score = float(out["threat_score"])
    tier = tier_for(score, sus_t, mal_t, bool(out.get("anomaly_flag")) and use_flag)
    category = out.get("attack_category")
    if category is None and tier != "Normal" and out.get("model_version", "").startswith("team-ml"):
        # binary model: record WHAT triggered the flag instead of an attack family
        category = ("Known attack (RF)" if score >= mal_t
                    else "Uncertain (RF)" if score >= sus_t else "Anomaly only (IF)")
    return score, tier, category


def ingest(features, true_label=None, src_ip=None, dst_ip=None, source="api", at=None):
    """Validate, score, persist and (maybe) alert. Returns (LogRecord, ClassificationResult, Alert|None)."""
    clean = validate(features)
    out = detector.score(clean)
    mal_t, sus_t, use_flag = _thresholds()
    score, tier, category = _decide(out, mal_t, sus_t, use_flag)
    now = at or utcnow()
    with _ingest_lock:
        lr = LogRecord(timestamp=now, src_ip=src_ip, dst_ip=dst_ip, protocol_type=clean["protocol_type"],
                       service=clean["service"], flag=clean["flag"], duration=clean["duration"],
                       src_bytes=clean["src_bytes"], dst_bytes=clean["dst_bytes"],
                       features_json=json.dumps(clean), true_label=true_label, source=source)
        cr = ClassificationResult(log=lr, anomaly_score=out.get("anomaly_score"),
                                  rf_probability=out.get("rf_probability"), threat_score=score, tier=tier,
                                  attack_category=category if tier != "Normal" else None,
                                  threshold_applied=mal_t, suspicious_threshold_applied=sus_t,
                                  model_version=out.get("model_version"),
                                  explanation_json=json.dumps(out.get("explanation") or []),
                                  classified_at=now)
        alert = None
        if tier == "Malicious" or (tier == "Suspicious" and get_setting("alert_on_suspicious", bool)):
            alert = Alert(result=cr, severity=tier, created_at=now)
            if tier == "Malicious" and get_setting("email_alerts", bool) and _smtp_configured():
                alert.email_status = "pending"
        db.session.add(lr)
        db.session.commit()
    if alert is not None and alert.email_status == "pending":
        threading.Thread(target=_send_email, args=(alert.id,), daemon=True).start()
    return lr, cr, alert


def _smtp_configured():
    return bool(os.environ.get("SMTP_HOST") and os.environ.get("ALERT_EMAIL_TO"))


def _send_email(alert_id):
    """SMTP over TLS (SRS §2.1.4.4). Failure is recorded but never blocks the on-screen banner."""
    with app.app_context():
        a = db.session.get(Alert, alert_id)
        if not a:
            return
        lr = a.result.log
        msg = EmailMessage()
        msg["Subject"] = f"[ThreatWatch] {a.severity} activity from {lr.src_ip}"
        msg["From"] = os.environ.get("SMTP_FROM", os.environ.get("SMTP_USER", "threatwatch@localhost"))
        msg["To"] = os.environ["ALERT_EMAIL_TO"]
        msg.set_content(
            f"Severity: {a.severity}\nThreat score: {a.result.threat_score:.3f}\n"
            f"Category: {a.result.attack_category or 'n/a'}\nSource: {lr.src_ip} -> {lr.dst_ip}\n"
            f"Protocol/service: {lr.protocol_type}/{lr.service}\nTime (UTC): {lr.timestamp}\n\n"
            f"Review it in the dashboard: alert #{a.id}, log #{lr.id}.")
        try:
            with smtplib.SMTP(os.environ["SMTP_HOST"], int(os.environ.get("SMTP_PORT", "587")), timeout=10) as s:
                s.starttls()
                if os.environ.get("SMTP_USER"):
                    s.login(os.environ["SMTP_USER"], os.environ.get("SMTP_PASSWORD", ""))
                s.send_message(msg)
            a.email_status = "sent"
        except Exception as e:
            log.error("Alert e-mail failed for alert %s: %s", alert_id, e)
            a.email_status = "failed"
        db.session.commit()


# ---------------------------------------------------------------- errors (SRS §3.2.8)
@app.errorhandler(OperationalError)
def db_down(e):
    db.session.rollback()
    log.error("Data store error: %s", e)
    if request.path.startswith("/api/"):
        return jsonify(error="The data store is temporarily unavailable. Please retry shortly."), 503
    return render_template("error.html", code=503,
                           message="The data store is temporarily unavailable. Please retry shortly."), 503


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


# ---------------------------------------------------------------- auth
_failed = {}  # ip -> (count, first_ts)


@app.route("/login", methods=["GET", "POST"])
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
            u = User.query.filter_by(username=request.form.get("username", "").strip()).first()
            if u and u.check_password(request.form.get("password", "")):
                _failed.pop(ip, None)
                session.clear()
                session.permanent = True
                login_user(u)
                csrf_token()
                audit("login", f"{u.username} signed in from {ip}")
                db.session.commit()
                nxt = request.args.get("next", "")
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("dashboard"))
            _failed[ip] = (cnt + 1 if time.time() - t0 < 60 else 1, t0 if time.time() - t0 < 60 else time.time())
            error = "Invalid username or password."
    return render_template("login.html", error=error), (401 if error else 200)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    audit("logout", current_user.username)
    db.session.commit()
    logout_user()
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- pages
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
def settings_page():
    if request.method == "POST":
        action = request.form.get("action", "save")
        if action == "reload_models":
            st = detector.load()
            audit("model_reload", f"detector mode: {st['mode']}")
            db.session.commit()
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
            "suspicious_threshold": f"{sus:.2f}", "malicious_threshold": f"{mal:.2f}",
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
            audit("settings_change", "; ".join(changes))
            flash("Settings saved. New thresholds apply to records classified from now on.", "ok")
        else:
            flash("No changes.", "ok")
        db.session.commit()
        return redirect(url_for("settings_page"))
    s = {k: get_setting(k) for k in ("suspicious_threshold", "malicious_threshold", "replay_interval")}
    s.update({k: get_setting(k, bool) for k in ("alert_on_suspicious", "email_alerts", "replay_enabled", "use_anomaly_flag")})
    audit_rows = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()
    return render_template("settings.html", page="settings", s=s, audit_rows=audit_rows,
                           det=detector.status(), smtp=_smtp_configured(), metrics=_team_metrics(),
                           replay_source=app.config.get("REPLAY_SOURCE", "synthetic"),
                           replay_file=app.config.get("REPLAY_FILE"), iso=iso)


def _team_metrics():
    """First table of the ML teammate's results/metrics.md, if the repo is alongside."""
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
    """Dashboard verdicts vs ground-truth labels for every replayed dataset row.
    Positive = attack; Suspicious and Malicious both count as 'flagged' (same as the team's hybrid metric)."""
    actual = db.case((LogRecord.true_label == "normal", 0), else_=1)
    pred = db.case((ClassificationResult.tier == "Normal", 0), else_=1)
    rows = (db.session.query(actual, pred, func.count()).join(ClassificationResult)
            .filter(LogRecord.true_label.isnot(None)).group_by(actual, pred).all())
    c = {(a, p): n for a, p, n in rows}
    tp, fp, tn, fn = c.get((1, 1), 0), c.get((0, 1), 0), c.get((0, 0), 0), c.get((1, 0), 0)
    n = tp + fp + tn + fn
    if not n:
        return None
    return {"n": n, "accuracy": round((tp + tn) / n, 4),
            "precision": round(tp / (tp + fp), 4) if tp + fp else None,
            "recall": round(tp / (tp + fn), 4) if tp + fn else None,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn}


# ---------------------------------------------------------------- REST API
@app.route("/api/classify", methods=["POST"])
def api_classify():
    if not (current_user.is_authenticated or _valid_api_key()):
        return jsonify(error="Authentication required"), 401
    body = request.get_json(silent=True)
    if body is None:
        return jsonify(error="Body must be JSON (Content-Type: application/json)."), 400
    meta = {k: body.pop(k, None) for k in ("src_ip", "dst_ip", "label")}
    lr, cr, alert = ingest(body, true_label=meta["label"], src_ip=meta["src_ip"] or request.remote_addr,
                           dst_ip=meta["dst_ip"], source="manual" if current_user.is_authenticated else "api")
    return jsonify(log_id=lr.id, threat_score=round(cr.threat_score, 4), classification=cr.tier,
                   is_alert=alert is not None, anomaly_score=cr.anomaly_score,
                   rf_probability=cr.rf_probability, attack_category=cr.attack_category), 201


def _risk_level():
    """Risk indicator from the last 200 records: weighted threat ratio + open malicious alerts (last 10 min)."""
    recent = (db.session.query(ClassificationResult.tier)
              .order_by(ClassificationResult.id.desc()).limit(200).all())
    n = len(recent) or 1
    mal = sum(1 for (t,) in recent if t == "Malicious")
    sus = sum(1 for (t,) in recent if t == "Suspicious")
    ratio = (mal + 0.4 * sus) / n
    open_mal = Alert.query.filter(Alert.status == "open", Alert.severity == "Malicious",
                                  Alert.created_at >= utcnow() - timedelta(minutes=10)).count()
    if ratio >= 0.25 or open_mal >= 25:
        level = "Critical"
    elif ratio >= 0.12 or open_mal >= 10:
        level = "High"
    elif ratio >= 0.05 or open_mal >= 1:
        level = "Elevated"
    else:
        level = "Low"
    return {"level": level, "ratio": round(ratio, 3), "open_malicious_10m": open_mal, "window": len(recent)}


@app.route("/api/stats")
@login_required
def api_stats():
    minutes = min(max(int(request.args.get("minutes", 30)), 5), 1440)
    tier_counts = dict(db.session.query(ClassificationResult.tier, func.count()).group_by(ClassificationResult.tier).all())
    total = sum(tier_counts.values())
    since = utcnow() - timedelta(minutes=minutes)

    # per-minute buckets (bucket in Python; works on SQLite and Postgres alike)
    bucket_mins = 1 if minutes <= 60 else (5 if minutes <= 360 else 15)
    rows = (db.session.query(ClassificationResult.classified_at, ClassificationResult.tier)
            .filter(ClassificationResult.classified_at >= since).all())
    start = since.replace(second=0, microsecond=0)
    start -= timedelta(minutes=start.minute % bucket_mins)
    nb = int((utcnow() - start).total_seconds() // (bucket_mins * 60)) + 1
    series = [{"t": iso(start + timedelta(minutes=i * bucket_mins)), "Normal": 0, "Suspicious": 0, "Malicious": 0}
              for i in range(nb)]
    for ts, tier in rows:
        i = int((ts - start).total_seconds() // (bucket_mins * 60))
        if 0 <= i < nb:
            series[i][tier] += 1

    cats = dict(db.session.query(ClassificationResult.attack_category, func.count())
                .filter(ClassificationResult.attack_category.isnot(None))
                .group_by(ClassificationResult.attack_category).all())
    scores = [s for (s,) in db.session.query(ClassificationResult.threat_score)
              .order_by(ClassificationResult.id.desc()).limit(2000).all()]
    hist = [0] * 20
    for s in scores:
        hist[min(int(s * 20), 19)] += 1
    top_sources = (db.session.query(LogRecord.src_ip, func.count())
                   .join(ClassificationResult).filter(ClassificationResult.tier != "Normal")
                   .group_by(LogRecord.src_ip).order_by(func.count().desc()).limit(5).all())
    last = LogRecord.query.order_by(LogRecord.id.desc()).first()
    return jsonify(
        total=total, normal=tier_counts.get("Normal", 0), suspicious=tier_counts.get("Suspicious", 0),
        malicious=tier_counts.get("Malicious", 0),
        threats=tier_counts.get("Suspicious", 0) + tier_counts.get("Malicious", 0),
        open_alerts=Alert.query.filter_by(status="open").count(),
        risk=_risk_level(), series=series, bucket_minutes=bucket_mins,
        categories=(dict(sorted(cats.items(), key=lambda kv: -kv[1])) if detector.status()["mode"].startswith("team")
                    else {k: cats.get(k, 0) for k in ("DoS", "Probe", "R2L", "U2R")}),
        evaluation=_live_eval(),
        score_hist=hist, score_sample=len(scores),
        top_sources=[{"ip": ip, "count": c} for ip, c in top_sources],
        thresholds={"suspicious": get_setting("suspicious_threshold", float),
                    "malicious": get_setting("malicious_threshold", float),
                    "anomaly_flag": get_setting("use_anomaly_flag", bool)},
        detector=detector.status(), replay=get_setting("replay_enabled", bool),
        last_record_at=iso(last.timestamp) if last else None, server_time=iso(utcnow()),
    )


def _filtered_logs():
    q = LogRecord.query.join(ClassificationResult)
    a = request.args
    tiers = [t for t in a.get("tier", "").split(",") if t in ("Normal", "Suspicious", "Malicious")]
    if tiers:
        q = q.filter(ClassificationResult.tier.in_(tiers))
    if a.get("category"):
        q = q.filter(ClassificationResult.attack_category == a["category"])
    if a.get("start"):
        q = q.filter(LogRecord.timestamp >= parse_dt(a["start"]))
    if a.get("end"):
        q = q.filter(LogRecord.timestamp <= parse_dt(a["end"]))
    for arg, op in (("min_score", "__ge__"), ("max_score", "__le__")):
        if a.get(arg):
            try:
                v = float(a[arg])
            except ValueError:
                raise ValidationError(f"{arg} must be a number")
            q = q.filter(getattr(ClassificationResult.threat_score, op)(v))
    if a.get("q"):
        like = f"%{a['q'].strip()}%"
        q = q.filter(db.or_(LogRecord.src_ip.like(like), LogRecord.dst_ip.like(like),
                            LogRecord.service.like(like)))
    sort_col = {"time": LogRecord.timestamp, "score": ClassificationResult.threat_score,
                "id": LogRecord.id}.get(a.get("sort", "time"), LogRecord.timestamp)
    q = q.order_by(sort_col.asc() if a.get("order") == "asc" else sort_col.desc(), LogRecord.id.desc())
    return q


@app.route("/api/logs")
@login_required
def api_logs():
    page = max(int(request.args.get("page", 1)), 1)
    per = min(max(int(request.args.get("per_page", 25)), 1), 100)
    q = _filtered_logs()
    if request.args.get("after_id"):
        q = q.filter(LogRecord.id > int(request.args["after_id"]))
    p = q.paginate(page=page, per_page=per, error_out=False)
    return jsonify(items=[log_to_dict(x) for x in p.items], page=p.page, pages=p.pages,
                   total=p.total, per_page=per)


@app.route("/api/logs/<int:log_id>")
@login_required
def api_log_detail(log_id):
    lr = db.session.get(LogRecord, log_id) or abort(404)
    return jsonify(log_to_dict(lr, full=True))


@app.route("/api/logs/export.csv")
@login_required
def api_logs_export():
    q = _filtered_logs().limit(50000)
    audit("export_csv", f"filters: {dict(request.args)}")
    db.session.commit()

    def gen():
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["id", "timestamp_utc", "src_ip", "dst_ip", "protocol", "service", "flag", "src_bytes",
                    "dst_bytes", "threat_score", "tier", "attack_category", "alert_status", "true_label"])
        for lr in q.yield_per(500):
            d = log_to_dict(lr)
            w.writerow([d["id"], d["timestamp"], d["src_ip"], d["dst_ip"], d["protocol"], d["service"], d["flag"],
                        d["src_bytes"], d["dst_bytes"], d["threat_score"], d["tier"], d["attack_category"] or "",
                        d["alert_status"] or "", lr.true_label or ""])
            yield buf.getvalue()
            buf.seek(0); buf.truncate(0)

    fname = f"threat_logs_{datetime.now():%Y%m%d_%H%M}.csv"
    return Response(stream_with_context(gen()), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={fname}"})


@app.route("/api/alerts")
@login_required
def api_alerts():
    q = Alert.query
    a = request.args
    if a.get("status") in ("open", "acknowledged", "dismissed"):
        q = q.filter(Alert.status == a["status"])
    if a.get("severity") in ("Suspicious", "Malicious"):
        q = q.filter(Alert.severity == a["severity"])
    if a.get("start"):
        q = q.filter(Alert.created_at >= parse_dt(a["start"]))
    if a.get("end"):
        q = q.filter(Alert.created_at <= parse_dt(a["end"]))
    if a.get("since_id"):
        q = q.filter(Alert.id > int(a["since_id"]))
    q = q.order_by(Alert.created_at.desc(), Alert.id.desc())
    page = max(int(a.get("page", 1)), 1)
    per = min(max(int(a.get("per_page", 25)), 1), 100)
    p = q.paginate(page=page, per_page=per, error_out=False)
    counts = dict(db.session.query(Alert.status, func.count()).group_by(Alert.status).all())
    return jsonify(items=[alert_to_dict(x) for x in p.items], page=p.page, pages=p.pages, total=p.total,
                   counts={k: counts.get(k, 0) for k in ("open", "acknowledged", "dismissed")},
                   max_id=db.session.query(func.max(Alert.id)).scalar() or 0)


@app.route("/api/alerts/<int:alert_id>/<action>", methods=["POST"])
@login_required
def api_alert_action(alert_id, action):
    if action not in ("acknowledge", "dismiss", "reopen"):
        abort(404)
    a = db.session.get(Alert, alert_id) or abort(404)
    body = request.get_json(silent=True) or {}
    a.status = {"acknowledge": "acknowledged", "dismiss": "dismissed", "reopen": "open"}[action]
    a.reviewed_by_id = current_user.id if action != "reopen" else None
    a.reviewed_at = utcnow() if action != "reopen" else None
    if body.get("note") is not None:
        a.note = str(body["note"])[:500]
    audit(f"alert_{action}", f"alert #{a.id} ({a.severity}, log #{a.result.log_id})")
    db.session.commit()
    return jsonify(alert_to_dict(a))


@app.route("/api/alerts/acknowledge-all", methods=["POST"])
@login_required
def api_alert_ack_all():
    sev = (request.get_json(silent=True) or {}).get("severity")
    q = Alert.query.filter_by(status="open")
    if sev in ("Suspicious", "Malicious"):
        q = q.filter_by(severity=sev)
    n = 0
    for a in q.all():
        a.status, a.reviewed_by_id, a.reviewed_at = "acknowledged", current_user.id, utcnow()
        n += 1
    audit("alert_acknowledge_bulk", f"{n} open {sev or 'all'} alerts")
    db.session.commit()
    return jsonify(acknowledged=n)


@app.route("/api/health")
def api_health():
    try:
        db.session.execute(db.text("SELECT 1"))
        ok = True
    except Exception:
        ok = False
    return jsonify(status="ok" if ok else "degraded", database=ok, detector=detector.status()), (200 if ok else 503)


# ---------------------------------------------------------------- bootstrapping
def seed_history(minutes=45, rate_per_min=12):
    """First launch on an empty DB. With a dataset file: load ALL of it (spread over the last 24 h).
    Without one: ~45 min of synthetic demo traffic so the charts aren't empty."""
    import random
    path = simulator.find_dataset()
    if path and os.environ.get("SEED_ROWS", "all") != "0":
        return backfill_dataset(path)
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
    """Demo realism: older alerts were already triaged. Flags on rows the dataset labels 'normal'
    are dismissed as false positives; real attacks are acknowledged. Two set-based UPDATEs, so it
    stays fast with tens of thousands of alerts."""
    admin = User.query.first()
    for status, is_normal in (("dismissed", True), ("acknowledged", False)):
        label_cond = (LogRecord.true_label == "normal") if is_normal else \
            db.or_(LogRecord.true_label.is_(None), LogRecord.true_label != "normal")
        ids = (db.select(Alert.id)
               .join(ClassificationResult, Alert.result_id == ClassificationResult.id)
               .join(LogRecord, ClassificationResult.log_id == LogRecord.id)
               .where(Alert.created_at < before, Alert.status == "open", label_cond))
        db.session.execute(db.update(Alert).where(Alert.id.in_(ids))
                           .values(status=status, reviewed_by_id=admin.id, reviewed_at=Alert.created_at)
                           .execution_options(synchronize_session=False))
    db.session.commit()


def backfill_dataset(path, hours=24, chunk=5000):
    """Score every row of the dataset in batches and store it with timestamps spread over the last `hours`."""
    import random
    import time as _t
    t0 = _t.time()
    rows = simulator.CsvReplayer(path)._rows  # already shuffled
    limit = os.environ.get("SEED_ROWS", "all")
    if limit.isdigit():
        rows = rows[:int(limit)]
    good = []
    for f, label in rows:
        try:
            good.append((validate(f), label))
        except ValidationError:
            pass
    skipped = len(rows) - len(good)
    log.info("Backfilling %d dataset rows from %s (about %d s)...", len(good), os.path.basename(path), max(10, len(good) // 1500))
    mal_t, sus_t, use_flag = _thresholds()
    now = utcnow()
    span = hours * 3600
    n = len(good)
    for start in range(0, n, chunk):
        part = good[start:start + chunk]
        outs = detector.score_batch([f for f, _ in part])
        for j, ((f, label), out) in enumerate(zip(part, outs)):
            i = start + j
            at = now - timedelta(seconds=span * (n - i) / n + random.uniform(0, 2))
            score, tier, category = _decide(out, mal_t, sus_t, use_flag)
            attack = label not in (None, "normal")
            src = random.choice(simulator.ATTACKERS) if attack and random.random() < 0.7 else \
                random.choice(simulator.EXTERNAL + simulator.INTERNAL)
            lr = LogRecord(timestamp=at, src_ip=src, dst_ip=random.choice(simulator.INTERNAL),
                           protocol_type=f["protocol_type"], service=f["service"], flag=f["flag"],
                           duration=f["duration"], src_bytes=f["src_bytes"], dst_bytes=f["dst_bytes"],
                           features_json=json.dumps(f), true_label=label, source="replay")
            cr = ClassificationResult(log=lr, anomaly_score=out["anomaly_score"], rf_probability=out["rf_probability"],
                                      threat_score=score, tier=tier,
                                      attack_category=category if tier != "Normal" else None,
                                      threshold_applied=mal_t, suspicious_threshold_applied=sus_t,
                                      model_version=out["model_version"],
                                      explanation_json=json.dumps(out["explanation"]), classified_at=at)
            if tier == "Malicious" or (tier == "Suspicious" and get_setting("alert_on_suspicious", bool)):
                Alert(result=cr, severity=tier, created_at=at)
            db.session.add(lr)
        db.session.commit()
        log.info("  %d / %d", min(start + chunk, n), n)
    _mark_old_alerts_reviewed(now - timedelta(minutes=30))
    log.info("Backfilled %d records in %.0fs%s", n, _t.time() - t0, f" ({skipped} invalid rows skipped)" if skipped else "")


def init():
    st = detector.status()
    log.info("Detector: %s%s", st["mode"], f" (from {st['team_module']})" if st["team_module"] else "")
    if st["error"]:
        log.error(st["error"])
    with app.app_context():
        db.create_all()
        if not User.query.first():
            u = User(username=os.environ.get("ADMIN_USER", "admin"), role="admin")
            u.set_password(os.environ.get("ADMIN_PASSWORD", "admin123"))
            db.session.add(u)
            db.session.commit()
            log.info("Created admin user '%s' (change ADMIN_PASSWORD for anything beyond a demo)", u.username)
        if LogRecord.query.count() == 0 and os.environ.get("SEED_DEMO", "1") == "1":
            seed_history()
    if os.environ.get("REPLAY", "1") == "1":
        simulator.start(
            app,
            ingest_fn=lambda f, **kw: ingest(f, **kw),
            get_interval=lambda: get_setting("replay_interval", float),
            is_enabled=lambda: get_setting("replay_enabled", bool),
        )


if __name__ == "__main__":
    init()
    app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 5000)), debug=False)
