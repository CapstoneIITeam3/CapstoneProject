# ThreatWatch — Role-Based Access Control (RBAC) Credentials

This document provides dedicated credential sets for each supported role level within the **ThreatWatch AI-Based Cyber Threat Detection & Alerting System**.

All accounts are fully registered and synchronized across both **Firebase Authentication** (Google Identity Toolkit) and **MongoDB Atlas** (`users` collection with bcrypt password hashing).

---

## 1. Role Permission Matrix

| Capability / Route | Administrator (`admin`) | Security Analyst (`analyst`) |
| :--- | :---: | :---: |
| **Real-Time Security Dashboard (`/dashboard`)** | Allowed | Allowed |
| **Live Traffic Log Inspection (`/logs`)** | Allowed | Allowed |
| **Filtered Log Export (`/api/logs/export.csv`)** | Allowed | Allowed |
| **Alert Investigation & Triage (`/alerts`)** | Allowed | Allowed |
| **Alert Status Transition (`open`/`acknowledged`/`dismissed`)** | Allowed | Allowed |
| **Real-Time Prediction API (`/api/predict`, `/api/classify`)** | Allowed | Allowed |
| **System Settings View (`/settings`)** | Allowed | **Blocked (HTTP 403 / Redirect)** |
| **Threat Score Threshold Tuning** | Allowed | **Blocked** |
| **Traffic Simulator / Replay Controls** | Allowed | **Blocked** |
| **Machine Learning Model Reloading** | Allowed | **Blocked** |
| **Administrative Audit Trail Inspection** | Allowed | **Blocked** |

---

## 2. Administrator Credentials (Role: `admin`)

Administrators have unrestricted access across the entire application, including the configuration of threat score classification thresholds (Suspicious / Malicious), traffic replay intervals, and administrative controls on the [`/settings`](http://localhost:5000/settings) endpoint.

### Set 1 — Primary Lead Administrator
* **Email Address:** `admin1@threatwatch.local`
* **Password:** `AdminSecure2026!#`
* **Assigned Role:** `admin`
* **Authentication Provider:** Firebase Auth & MongoDB Atlas
* **Firebase UID:** `YcX47qhFzJPEJiSBpiLJ2cPxNGN2`

### Set 2 — SecOps Incident Commander
* **Email Address:** `admin2@threatwatch.local`
* **Password:** `SecOpsAdmin2026!$`
* **Assigned Role:** `admin`
* **Authentication Provider:** Firebase Auth & MongoDB Atlas
* **Firebase UID:** `P6DpOchv9oSXBXiMFppV8FnFFtE3`

---

## 3. Security Analyst Credentials (Role: `analyst`)

Security Analysts have full operational access to monitor network traffic, inspect raw features, filter and export logs, and triage high-priority alerts. If an analyst attempts to navigate to `/settings`, the backend RBAC guard (`@admin_required`) intercepts the request and redirects to `/dashboard` with an explicit flash notice: *"Access denied: Administrator privileges required for this page."*

### Set 1 — Tier-1 SOC Monitoring Analyst
* **Email Address:** `analyst1@threatwatch.local`
* **Password:** `AnalystTier1!2026`
* **Assigned Role:** `analyst`
* **Authentication Provider:** Firebase Auth & MongoDB Atlas
* **Firebase UID:** `hUbpYpGCv4aLZVxxchLqLbVYRlf1`

### Set 2 — Tier-2 Threat Hunter & Forensics Analyst
* **Email Address:** `analyst2@threatwatch.local`
* **Password:** `AnalystTier2!2026`
* **Assigned Role:** `analyst`
* **Authentication Provider:** Firebase Auth & MongoDB Atlas
* **Firebase UID:** `WOmiT6uTkBTclSTctoHAb6WxQQp1`

---

## 4. Automated Testing Credentials (CI/CD & E2E)

Dedicated account configured across automated Pytest fixtures and Selenium headless Chrome browser integration suites:

* **Email Address:** `testadmin@threatwatch.local`
* **Password:** `TestPassword123!`
* **Assigned Role:** `admin`
* **Authentication Provider:** Firebase Auth & MongoDB Atlas
* **Firebase UID:** `ErnYLBRFixSEFDvH0MnBg63WMU12`

---

## 5. Security & Password Policy Compliance

All provisioned passwords comply with NIST SP 800-63B and OWASP ASVS guidelines enforced by the ThreatWatch security engine:
- Minimum length $\ge 8$ characters.
- At least one uppercase ASCII letter (`A-Z`).
- At least one lowercase ASCII letter (`a-z`).
- At least one numeric digit (`0-9`).
- At least one special symbol (`!@#$%^&*()_+-=[]{}|;:,.<>?`).
