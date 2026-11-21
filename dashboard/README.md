# ThreatWatch: Dashboard for the AI-Based Cyber Threat Detection & Alerting System (Team 38)

This is the Flask + Jinja2 + Chart.js dashboard described in the SRS (§2.1.2, §3.1.1, §3.2.3 to §3.2.7, wireframes §6.6).
It runs end-to-end out of the box with a **demo detector**, so you can build, test and present it
before the ML models are ready. When the trained models are dropped in, it uses them automatically.

## Quick start

```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 and log in with **admin / admin123**.

On first launch the app creates `threats.db` (SQLite) and the admin user, then backfills history. **If a dataset file is found, every row is loaded** (KDDTest+ has 22,544 rows; about 15 s with the team model, spread over the last 24 h). Without a dataset file it backfills about 45 minutes of synthetic demo traffic instead. Set `SEED_ROWS=5000` to load fewer rows, or `SEED_ROWS=0` to skip the dataset backfill.

**Choosing the dataset:** set `DATASET` to a file name in `data/`, e.g. in PowerShell `$env:DATASET="KDDTrain+.txt"`. KDDTrain+ (125,973 rows) takes about a minute to backfill and makes `threats.db` about 290 MB. The models were *trained* on KDDTrain+, so its accuracy (0.946, recall 1.0) is not a fair test. Quote the KDDTest+ numbers (0.856) as model performance.
A replay thread then streams new records every ~2 s. To start fresh, delete `threats.db`.

## What's in it

| Screen | SRS requirement |
|---|---|
| **Login**: bcrypt-hashed passwords, 30-min session, lockout after 5 failed tries, no sign-up | §3.2.6, UC-1, TC-04 |
| **Dashboard**: stat cards (Total logs / Threats / Risk level / Open alerts), threat-activity chart (30m/3h/24h), score histogram with threshold lines, attack categories, tier breakdown, top sources, live log feed (auto-refresh 3 s, pause, threats-only) | §2.1.2, §3.2.4, FR-4 |
| **Alert banner**: red, high-contrast, on every page, collapsible, "View" + "Acknowledge"; re-expands when a newer alert arrives | §3.2.3, FR-3 |
| **Log detail modal**: all 41 features, IF score, RF probability, thresholds applied, "why it was flagged" | §3.2.4 |
| **Analyze a record**: manual entry with client-side validation and 5 attack presets (good for the demo/viva) | §3.1.1 |
| **Logs**: filter by date range, tier, category, min score and IP/service; sort; paginate; "no results found" message; CSV export | §3.2.5, UC-6, TC-06 |
| **Alerts**: Open / Acknowledged / Dismissed tabs, acknowledge, dismiss (false positive), reopen, bulk-acknowledge | §3.2.3, UC-5 |
| **Settings**: suspicious/malicious thresholds (with live preview), alert-on-suspicious, e-mail toggle, replay on/off and speed, model status + reload, audit log | §3.2.7, FR-7 |
| Errors: a DB outage returns a friendly 503, bad input returns a clear 400, the UI shows an "offline" bar | §3.2.8, FR-8 |

## ML integration (team module: `feature/adwitiya-ml`)

The dashboard uses the team's `ml/` package directly: `ml/predict.py`, `ml/rf_model.pkl` and `ml/iso_model.pkl`.
It looks for `ml/` **next to `app.py`**, or **one folder up**, so both of these work:

```
Option A (inside the repo)              Option B (standalone)
CapstoneProject/                         threat-dashboard/
├── ml/            <- team module        ├── ml/        <- copied from the repo
├── data/KDDTest+.txt                    ├── data/KDDTest+.txt
├── results/metrics.md                   ├── app.py ...
└── dashboard/     <- this folder
    └── app.py ...
```

- **Decision rule:** identical to `ml.predict._label()`. Threat score = RF P(attack). Score ≥ 0.50 is Malicious. Score ≥ 0.20, *or* the Isolation Forest calls the record an outlier, is Suspicious. Otherwise Normal.
  These are the defaults on the Settings page and can be changed there (SRS §3.2.7).
- **Verified:** on 3,000 random KDDTest+ rows the dashboard gives the same label as `predict()` for **3,000/3,000**.
  Accuracy 0.860, precision 0.931, recall 0.817, in line with `results/metrics.md` (0.856 / 0.923 / 0.816).
- **Attack families:** the model is binary (attack vs normal), so it has no DoS/Probe/R2L/U2R output. Instead, each flag records what triggered it:
  *Known attack (RF)*, *Uncertain (RF)* or *Anomaly only (IF)*.
- **Accuracy chip:** compares the dashboard's verdicts with the dataset's true labels for every replayed record. With the full KDDTest+ loaded it reads accuracy 0.856, precision 0.923, recall 0.815, which matches `results/metrics.md`.
- **scikit-learn must be 1.8.0** (pinned in requirements). That is the version `ml/*.pkl` were actually saved with; the ML README still says 1.6.1, but that is out of date. With any other version the app prints `InconsistentVersionWarning` on startup.
- **Speed:** about 18 ms per record. The RF's `n_jobs` is set to 1 at load time because threads only slow down single-row prediction, and the predictions don't change.
- **No `ml/` folder?** The app falls back to `ml_models/*.joblib`, then to the demo heuristic.

## REST API (all JSON, session-authenticated)

| Method & path | Purpose |
|---|---|
| `POST /api/classify` | body: NSL-KDD features (`duration, protocol_type, service, flag, src_bytes, dst_bytes` required; others default to 0), optional `src_ip, dst_ip, label` → `{threat_score, classification, is_alert, log_id, …}` |
| `GET /api/stats?minutes=30` | summary counters, risk level, time series, histogram, categories |
| `GET /api/logs?page&per_page&tier=Suspicious,Malicious&category&start&end&min_score&q&sort=time\|score&order` | paginated history |
| `GET /api/logs/<id>` | one record with all features and the explanation |
| `GET /api/logs/export.csv?<same filters>` | CSV export |
| `GET /api/alerts?status&severity&page` | paginated alerts and counts |
| `POST /api/alerts/<id>/acknowledge\|dismiss\|reopen` | update alert status (audited) |
| `GET /api/health` | DB + detector status (no auth) |

State-changing calls need the `X-CSRF-Token` header (the front end sends it automatically).
For machine-to-machine ingestion, set `INGEST_API_KEY` and send it as `X-API-Key` to `/api/classify`.

## Configuration (environment variables)

| Var | Default | |
|---|---|---|
| `ADMIN_USER` / `ADMIN_PASSWORD` | admin / admin123 | used only when the DB is first created |
| `SECRET_KEY` | random per start | **set this**, otherwise sessions reset when the app restarts |
| `DATABASE_URL` | `sqlite:///threats.db` | any SQLAlchemy URL (e.g. Postgres) |
| `SESSION_MINUTES` | 30 | session expiry |
| `SEED_DEMO` | 1 | backfill demo history on an empty DB |
| `REPLAY` | 1 | start the replay thread |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, `SMTP_FROM`, `ALERT_EMAIL_TO` | | e-mail alerts (STARTTLS), then enable them in Settings |
| `INGEST_API_KEY` | | allows `/api/classify` without a browser session |
| `HTTPS` | 0 | set to 1 behind TLS to mark cookies Secure |

For Gmail use an App Password: `SMTP_HOST=smtp.gmail.com SMTP_PORT=587`.

## Project layout

```
app.py            routes, REST API, auth, alerting, ingest pipeline
models.py         SQLAlchemy models: User, LogRecord, ClassificationResult, Alert, Setting, AuditLog (ERD §6.5)
detector.py       ML adapter + validation + decision rule   <- ML teammate's file
simulator.py      replay thread (data/replay.csv or synthetic NSL-KDD-style traffic)
templates/        base, login, dashboard, logs, alerts, settings, error
static/           css/style.css, js/common.js, js/dashboard.js, vendor/chart.umd.min.js (Chart.js 4, bundled so it works offline)
ml_models/        drop .joblib files here
data/             put replay.csv here
```
