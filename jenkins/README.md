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

---

## Prerequisites for Jenkins Server

1. **Java Runtime:** OpenJDK 17 LTS or 21 LTS
2. **Jenkins:** Jenkins 2.440+ LTS
3. **Required Jenkins Plugins:**
   - Git Plugin
   - Pipeline Plugin
   - JUnit Plugin
   - Email Extension Plugin (`email-ext`)
   - Timestamper Plugin
4. **Agent Runtime:**
   - Python 3.10+ (with `pip` and `venv`)
   - Google Chrome (for headless Selenium execution)

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

## Running the Pipeline

- **Standard Build (Green / Passing):**
  Click **Build with Parameters** → Leave `SIMULATE_BUILD_FAILURE` unchecked → Click **Build**.
- **Failure Demo Build (Red / Alert Demonstration):**
  Click **Build with Parameters** → Check `SIMULATE_BUILD_FAILURE` → Click **Build**.
