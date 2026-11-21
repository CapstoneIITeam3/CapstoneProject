# ThreatWatch Postman API Testing Collection

This directory contains the exportable **Postman Collection (v2.1.0)** and **Postman Environment** configuration for the **ThreatWatch AI-Based Cyber Threat Detection & Alerting System**.

---

## Files in this Directory

| File | Description |
| :--- | :--- |
| `ThreatWatch.postman_collection.json` | Complete API test suite containing 10 requests across 4 functional modules with automated assertions. |
| `ThreatWatch.postman_environment.json` | Environment variables configuration (`baseUrl`, `adminUser`, `adminPass`, `csrfToken`, `apiKey`). |

---

## Test Suites & Coverage

1. **System Health & OpenAPI Documentation**
   - `GET /api/health`: Verifies operational health, detector engine state, MongoDB connection, latency (<800ms), and security headers.
   - `GET /apidocs/`: Asserts interactive Swagger UI renders with HTTP 200.
   - `GET /apispec_1.json`: Validates OpenAPI specification endpoints.

2. **Authentication & Session Lifecycle**
   - `GET /login (Fetch CSRF Token)`: Automated regex test script extracting the CSRF token into environment variables.
   - `POST /login (Admin Session Auth)`: Dispatches form login data with session cookies and assertions verifying session creation.

3. **Threat Detection & ML Inference**
   - `POST /api/predict`: Validates live ML classification against Random Forest and Isolation Forest pipelines.
   - `POST /api/classify`: Tests network traffic classification and database persistence.
   - `POST /api/predict (Malformed Payload)`: Asserts input validation rejects empty payloads with HTTP 400.

4. **Logs & Alerts Triage**
   - `GET /api/logs`: Queries recent network traffic logs.
   - `GET /api/alerts`: Retrieves active security alerts.
   - `PATCH /api/alerts/:id`: Tests alert triage status updates (dismiss/resolve).

---

## Running in Postman App

1. Open **Postman Desktop**.
2. Click **Import** (top left).
3. Drag and drop both files:
   - `ThreatWatch.postman_collection.json`
   - `ThreatWatch.postman_environment.json`
4. Select the **"ThreatWatch Local Environment"** in the top right environment dropdown.
5. Click on the collection name > click **Run Collection** to execute all automated test assertions!

---

## Running Headlessly in CI/CD via Newman

You can execute the entire test suite from the command line or within a Jenkins CI/CD pipeline using **Newman**:

```bash
# Install Newman globally (if not already installed)
npm install -g newman newman-reporter-junit

# Run collection with environment and generate JUnit test report
newman run postman/ThreatWatch.postman_collection.json \
  -e postman/ThreatWatch.postman_environment.json \
  --reporters cli,junit \
  --reporter-junit-export postman-junit-report.xml
```
