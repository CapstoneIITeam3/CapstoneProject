# ThreatWatch Jenkins CI/CD Pipeline

Automated Continuous Integration and Continuous Deployment (CI/CD) pipeline for ThreatWatch AI-IDS, providing automated test execution, JUnit analytics, regression protection, and contributor email alerting.

---

## Architecture Overview

- **Pipeline Type:** Declarative Jenkins Pipeline (`Jenkinsfile`)
- **Cross-Platform Compatibility:** Built-in dynamic branching (`isUnix()`) supporting both Linux (Ubuntu/Debian) and Windows build agents.
- **Test Automation Stages:**
  1. **Checkout:** Clones the repository and checks out the target branch.
  2. **Environment Setup:** Creates a clean virtual environment and installs dependencies from `requirements.txt`.
  3. **Unit & Integration Tests:** Executes 29 Pytest tests covering ML detection, authentication, NIST password strength policies, security headers, and Swagger specs.
  4. **Selenium E2E Tests:** Executes 11 browser test cases against headless Google Chrome with automated ChromeDriver resolution.
  5. **Security & Architecture Verification:** Validates environment hygiene, secret safety, and repository integrity.
- **Reporting:** Automatic JUnit XML test analytics publishing for both unit (`reports/unit-results.xml`) and E2E (`reports/e2e-results.xml`) test suites.
- **Automated Alerts:** Dispatches styled HTML build reports and regression alerts via the `email-ext` plugin to all repository contributors upon build completion.

---

## Contributor Notification Roster

Every automated Jenkins build report (Success, Failure, Unstable) is dispatched to all 4 project contributors:

| Contributor | Role | Email Address |
|---|---|---|
| **Adwitiya Sinha** | ML & AI Lead | `adwitiyasinha25@gmail.com` |
| **Akanksha Joshi** | Backend & Database Lead | `akankshajoshi294@gmail.com` |
| **Disha Sharma** | Frontend & UI Lead | `disha.sharma23@st.niituniversity.in` |
| **Dhyey Pujara** | Integration & DevOps Lead | `dhyey.pujara23@st.niituniversity.in` |

---

## SMTP Configuration in Jenkins

To enable automated email alerts, configure Jenkins Extended E-mail Notification:

1. Navigate to **Manage Jenkins** → **System** → **Extended E-mail Notification**.
2. Set the following parameters:
   - **SMTP Server:** `smtp.gmail.com`
   - **SMTP Port:** `587`
   - **Use SMTP Authentication:** Checked
   - **Username:** `<your-gmail-address>@gmail.com`
   - **Password:** `<your-google-app-password>` *(Generate via Google Account → Security → App Passwords)*
   - **Use TLS / STARTTLS:** Checked
   - **Default Content Type:** `HTML (text/html)`
   - **Default Recipients:** `adwitiyasinha25@gmail.com, akankshajoshi294@gmail.com, disha.sharma23@st.niituniversity.in, dhyey.pujara23@st.niituniversity.in`
3. Click **Test configuration by sending test e-mail** to verify connectivity.
4. Click **Save**.

---

## How to Set Up the Pipeline in Jenkins

1. Open the Jenkins dashboard (`http://localhost:8080`).
2. Click **New Item** → Name: `ThreatWatch-CI` → Select **Pipeline** → Click **OK**.
3. In the job configuration:
   - Check **This project is parameterized**.
   - Under **Pipeline Definition**, select **Pipeline script from SCM**.
   - SCM: **Git**
   - Repository URL: `https://github.com/CapstoneIITeam3/CapstoneProject.git`
   - Branch Specifier: `*/feature/dhyey-integration` (or `*/main`)
   - Script Path: `Jenkinsfile`
4. Click **Save**.

---

## Live Demonstration Procedure for Capstone Evaluation

### Step 1: Standard Green Build (Passing Pipeline)
1. In Jenkins, click **Build with Parameters**.
2. Leave `SIMULATE_BUILD_FAILURE` unchecked (default `false`).
3. Click **Build**.
4. **Expected Result:**
   - All 5 pipeline stages complete successfully (all green).
   - Pytest unit suite passes (29/29).
   - Selenium E2E suite passes (11/11).
   - JUnit reports are published and visible in Jenkins at `testReport/`.
   - A **green success email** (`[ThreatWatch CI] SUCCESS: Build #X`) is delivered to all 4 contributors.

### Step 2: Deliberate Build Failure Demonstration (Red Build & Alert Verification)
1. In Jenkins, click **Build with Parameters**.
2. Check the `SIMULATE_BUILD_FAILURE` checkbox (`true`).
3. Click **Build**.
4. **Expected Result:**
   - Pipeline begins execution and halts during the `Unit & Integration Tests (Pytest)` stage.
   - The test `test_jenkins_pipeline_failure_demonstration` in `tests/test_jenkins_failure_demo.py` deliberately fails with a clear diagnostic assertion message.
   - Build status turns **RED (FAILED)**.
   - JUnit test analytics at `${BUILD_URL}testReport/` highlights the deliberate test failure in red.
   - An **urgent red failure email** (`[ThreatWatch CI] FAILURE: Build #Y`) is immediately dispatched via `email-ext` to all 4 contributors, proving end-to-end regression alerting.

### Step 3: Pipeline Recovery
1. Re-run **Build with Parameters** with `SIMULATE_BUILD_FAILURE` unchecked.
2. Build status recovers to **GREEN (PASSED)**.
3. Recovery email is dispatched.
