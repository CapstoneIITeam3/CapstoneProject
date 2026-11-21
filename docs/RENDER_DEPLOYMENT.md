# ThreatWatch Production Deployment Guide (Render)

This guide documents the production deployment of the **ThreatWatch AI-Based Cyber Threat Detection & Alerting System** on [Render](https://render.com).

---

## 1. Architecture Overview

ThreatWatch operates as a production containerized Python web service backed by a managed MongoDB data store and Google Firebase identity management:

- **Application Server:** Python 3.11 with Gunicorn (`gthread` worker model, 2 workers × 4 concurrent threads).
- **Frontend / UI:** Responsive security operations center (SOC) dashboard styled with dark-mode Inter typography and Chart.js telemetry canvases.
- **Machine Learning Engine:** Multi-model ensemble combining Random Forest (`RandomForestClassifier`) and Isolation Forest (`IsolationForest`) running inference against 41 NSL-KDD network traffic attributes.
- **Data Persistence:** Pure PyMongo ODM layer backed by MongoDB Atlas or managed MongoDB.
- **Authentication & Security:** Firebase Web SDK + server-side RS256 JWT cryptographic validation (`google.oauth2.id_token.verify_firebase_token`), Flask-Limiter IP rate limiting, OWASP HTTP headers, and CSP.

---

## 2. Deployment Methods

### Option A: Blueprint Deployment (Recommended)
ThreatWatch includes a declarative Infrastructure-as-Code specification (`render.yaml`).

1. Log in to the [Render Dashboard](https://dashboard.render.com).
2. Click **Blueprints** → **New Blueprint Instance**.
3. Connect the repository: `https://github.com/CapstoneIITeam3/CapstoneProject.git`.
4. Select the target branch: `feature/dhyey-integration` (or `main`).
5. Render will automatically parse `render.yaml` and configure:
   - Web service name: `threatwatch-ai-ids`
   - Runtime: `python-3.11.9` (via `runtime.txt`)
   - Build command: `pip install -r requirements.txt`
   - Start command: `gunicorn --config gunicorn.conf.py app:app`
   - Health check path: `/api/health`
6. Fill in the sensitive environment variables (such as `MONGO_URI` and `ADMIN_PASSWORD`).
7. Click **Apply**.

---

### Option B: Manual Web Service Creation

1. In the Render Dashboard, click **New +** → **Web Service**.
2. Connect your Git repository.
3. Configure service parameters:
   - **Name:** `threatwatch-ai-ids`
   - **Region:** `Oregon (US West)` or your preferred region
   - **Branch:** `feature/dhyey-integration`
   - **Runtime:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn --config gunicorn.conf.py app:app`
   - **Plan:** `Free` or `Starter`
4. Under **Advanced**:
   - **Health Check Path:** `/api/health`
   - **Auto-Deploy:** `Yes`
5. Add the environment variables specified below.
6. Click **Create Web Service**.

---

## 3. Environment Variables Reference

| Variable | Description | Required | Example / Default |
|---|---|:---:|---|
| `PYTHON_VERSION` | Python runtime version | Yes | `3.11.9` |
| `PORT` | Listening TCP port (assigned by Render) | Yes | `10000` |
| `SECRET_KEY` | Cryptographic session signing key | Yes | *(Render auto-generates)* |
| `MONGO_URI` | MongoDB Atlas or remote connection URI | Yes | `mongodb+srv://<user>:<pw>@cluster.mongodb.net/ai_ids_db` |
| `MONGO_DB_NAME` | Database name | Yes | `ai_ids_db` |
| `SEED_DEMO` | Backfill historic traffic for SOC demo | No | `1` (enabled) |
| `REPLAY` | Background network traffic simulator | No | `1` (enabled) |
| `ADMIN_USER` | Initial administrative username | Yes | `admin` |
| `ADMIN_PASSWORD` | Initial administrative password | Yes | `<StrongPassword#2026>` |
| `FIREBASE_PROJECT_ID` | Google Firebase Project ID | Yes | `threatwatch-a41a0` |
| `FIREBASE_API_KEY` | Firebase Client Web API Key | Yes | `AIzaSyD8MwBtD4jb_xvqSwiE5PpfTJH1AyWKghU` |
| `FIREBASE_AUTH_DOMAIN` | Firebase Authentication Domain | Yes | `threatwatch-a41a0.firebaseapp.com` |
| `FIREBASE_STORAGE_BUCKET` | Firebase Cloud Storage Bucket | Yes | `threatwatch-a41a0.firebasestorage.app` |
| `FIREBASE_MESSAGING_SENDER_ID` | Firebase Messaging Sender ID | Yes | `289561180633` |
| `FIREBASE_APP_ID` | Firebase Web App ID | Yes | `1:289561180633:web:87b2d30ba98b043ac641c8` |
| `FIREBASE_MEASUREMENT_ID` | Firebase Analytics Measurement ID | No | `G-F5N5Y35YXX` |

---

## 4. Post-Deployment Configuration

### A. Firebase Authorized Domains
To allow Google Sign-In popups and automated password resets to function from your Render production URL:
1. Open the [Firebase Console](https://console.firebase.google.com/project/threatwatch-a41a0/authentication/settings).
2. Navigate to **Authentication** → **Settings** → **Authorized domains**.
3. Click **Add domain**.
4. Enter your Render domain (e.g., `threatwatch-ai-ids.onrender.com`).
5. Click **Save**.

### B. MongoDB Atlas Network Access
If using MongoDB Atlas:
1. Navigate to **Network Access** in the MongoDB Atlas console.
2. Ensure Render's outbound traffic is permitted by adding `0.0.0.0/0` (Allow Access from Anywhere) or configuring Render static outbound IP addresses.

---

## 5. Verification & Health Monitoring Checklist

After deployment succeeds on Render, verify system health using the following endpoints:

1. **System Health Endpoint:**
   ```bash
   curl -i https://<your-app-name>.onrender.com/api/health
   ```
   *Expected Response:* HTTP 200 with JSON payload confirming `status: "ok"`, `database: "connected"`, and `detector: { "mode": "team ML (RF + IF)" }`.

2. **Swagger OpenAPI Documentation:**
   Navigate to `https://<your-app-name>.onrender.com/apidocs/` to test interactive REST endpoints.

3. **Authentication Verification:**
   - Log in using the seeded admin credentials.
   - Test Google Sign-In via Firebase popup.
   - Test Password Recovery email dispatch via the login modal.

4. **SOC Dashboard & Live Simulator:**
   - Observe real-time traffic statistics updating on the dashboard.
   - Trigger manual traffic classification via the **Analyze traffic** modal.
