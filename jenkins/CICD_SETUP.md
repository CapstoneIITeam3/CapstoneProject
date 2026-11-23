# ThreatWatch CI/CD: GitHub → ngrok → Jenkins → Docker → e-mail

This guide covers the full pipeline on a Windows laptop running Jenkins, plus the live demo
(a green build, a deliberate red build with e-mail to everyone, and recovery).

```
 git push ──► GitHub ──webhook──► ngrok (public URL) ──► Jenkins on your laptop :8080
                                                           │
   1 Checkout          2 Environment Setup (venv + pip)    │
   3 Unit tests (39)   4 Selenium E2E (14, headless Chrome, videos)
   5 Security check    6 Docker build + health check   7 Deploy → http://localhost:8000
                                                           │
                         e-mail (green or red) to all 4 contributors ◄──┘
```

If any test fails, the build stops there (red), the Docker stages are skipped, and the failure e-mail goes out.

---

## 1. Install once

| Tool | Get it | Check it works |
|---|---|---|
| Docker Desktop | docker.com → Docker Desktop for Windows | `docker run hello-world` |
| Jenkins (LTS) | jenkins.io → Windows installer (runs on http://localhost:8080) | dashboard opens |
| Python 3.11, Git, Google Chrome | already on your laptop | `python --version`, `git --version` |
| ngrok | ngrok.com → sign up (free) → download for Windows | `ngrok version` |

**Jenkins plugins.** Go to *Manage Jenkins → Plugins → Available* and install: **Pipeline**, **Git**, **GitHub**,
**Email Extension**, and **JUnit** (usually preinstalled). Restart Jenkins when asked.

### Make Jenkins able to use Python, Git, Chrome and Docker

The Windows installer runs Jenkins as a background service under a system account. That account often can't
see your Python, Git or Docker Desktop. The simplest fix is to run the service as **your** Windows user:

1. Press `Win + R`, type `services.msc`, and press Enter.
2. Right-click **Jenkins**, then *Properties → Log On → This account*. Enter your Windows username and password.
3. Right-click **Jenkins** and choose *Restart*.

To check: in Jenkins, *New Item → Freestyle → Build Steps → Execute Windows batch command* with
`python --version & git --version & docker version`, then build it. All three should print a version.

---

## 2. E-mail (Gmail SMTP)

1. Use a Gmail account for sending (one teammate's, or a new one).
   Turn on 2-Step Verification, then open https://myaccount.google.com/apppasswords → create an app password and copy the 16 characters.
2. In Jenkins, go to *Manage Jenkins → System*:
   - **Jenkins Location → Jenkins URL**: your ngrok URL (step 4), e.g. `https://your-name.ngrok-free.app/`.
     This makes the links in the e-mails open for your teammates too.
   - **System Admin e-mail address**: the Gmail address.
   - **Extended E-mail Notification**: SMTP server `smtp.gmail.com`, port `587`, *Advanced* →
     add credentials (Gmail address + app password), tick **Use TLS**, Default Content Type **HTML**.
3. Click **Save**. Send a test from *E-mail Notification → Test configuration* (fill in the same SMTP details there).

The recipients are already in the `Jenkinsfile` (`to:`): Adwitiya, Akanksha, Disha and Dhyey.
University inboxes sometimes put the first Jenkins mail in **Spam/Quarantine**. Check there and mark it "Not spam".

---

## 3. Create the pipeline job

1. Click *New Item* → name **ThreatWatch-CI** → **Pipeline** → OK.
2. Under **Build Triggers**, tick **GitHub hook trigger for GITScm polling**.
3. Under **Pipeline**, choose *Definition: Pipeline script from SCM*, SCM **Git**
   - Repository URL: `https://github.com/CapstoneIITeam3/CapstoneProject.git`
   - Branch Specifier: `*/main`
   - Script Path: `Jenkinsfile`
4. Click **Save**, then **Build Now** once. The first build loads the `Jenkinsfile`, and after it
   **Build with Parameters** appears with `SIMULATE_BUILD_FAILURE` and `RUN_DOCKER`.

The first build is slow (5–10 min: pip install, ChromeDriver download, Docker image build). Later builds reuse caches.

---

## 4. ngrok: give Jenkins a public URL for GitHub

GitHub can't reach `localhost`, so ngrok forwards a public HTTPS address to your Jenkins.

```powershell
ngrok config add-authtoken <your-token-from-dashboard.ngrok.com>
```

In the ngrok dashboard → **Domains**, claim your **free static domain** (e.g. `your-name.ngrok-free.app`).
That way the URL stays the same every time and you don't have to update GitHub again.

```powershell
ngrok http --url=your-name.ngrok-free.app 8080
```

Leave this window open during the demo. If it closes, GitHub can't reach Jenkins.

---

## 5. GitHub webhook

Repo → **Settings → Webhooks → Add webhook**:

| Field | Value |
|---|---|
| Payload URL | `https://your-name.ngrok-free.app/github-webhook/` (keep the slash at the end) |
| Content type | `application/json` |
| Events | *Just the push event* |

Save, then open the webhook → **Recent Deliveries**. GitHub sends a "ping", which should show a green ✓.
A red ✗ usually means ngrok isn't running, or the URL is missing `/github-webhook/`.

---

## 6. Live demo script (about 10 minutes)

### A. Green build, triggered by a real push
```powershell
git checkout main
git pull
Add-Content README_ML_INTEGRATION.txt ""
git commit -am "ci: demo trigger"
git push
```
Within a few seconds a build starts by itself in Jenkins (*Started by GitHub push*). Show sir:
- **Stage View**: all 7 stages go green.
- **Tests** (*Test Result* on the build page): 39 unit + 14 Selenium tests, all passed.
- **Artifacts**: the Selenium `.mp4` recordings.
- **http://localhost:8000**: the version that was just built, running in Docker (`docker ps` shows `threatwatch-live`).
- **Inbox**: `[ThreatWatch CI] SUCCESS: Build #N` reached all 4 of you.

### B. Fail a test on purpose → red build → e-mail to everyone
Open `tests/test_jenkins_failure_demo.py` and change the last line from `assert True` to:
```python
    assert False, "Deliberate failure for the CI demo"
```
```powershell
git commit -am "test: deliberately break a test (CI demo)"
git push
```
Jenkins builds automatically. **Unit & Integration Tests** turns red, and the Selenium/Docker/Deploy stages are skipped.
*Test Result* shows `test_jenkins_pipeline_failure_demonstration` failing with the message above.
The live app on :8000 keeps running the last good version, because a broken build is never deployed.
Everyone receives **`[ThreatWatch CI] FAILURE: Build #N+1`**.

*(No-git alternative: **Build with Parameters → tick SIMULATE_BUILD_FAILURE → Build** gives the same red build and e-mail.)*

### C. Fix it → green again
```powershell
git revert --no-edit HEAD
git push
```
The next automatic build is green again, and a SUCCESS e-mail goes out.

---

## 7. Docker on its own (outside Jenkins)

```powershell
docker compose up --build        # http://localhost:5000  (Swagger: /apidocs/)
docker compose down
```
`docker-compose.yml` passes your `.env` (MongoDB Atlas, SMTP, Firebase) into the container at run time.
The image itself never contains secrets (`.env` is in `.dockerignore`). Without `.env`, the app uses an
in-memory database, so it still starts. That's also how Jenkins checks the image.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `'python' / 'git' / 'docker' is not recognized` in the console | Section 1: run the Jenkins service as your Windows user, then restart Jenkins. |
| Docker stage: `error during connect ... docker_engine` | Docker Desktop isn't running. Start it, or untick `RUN_DOCKER`. |
| Selenium stage: `session not created` / Chrome errors | Update Google Chrome. ChromeDriver is downloaded automatically to match. |
| Push doesn't start a build | ngrok window closed, wrong Payload URL, or the job's *GitHub hook trigger* box isn't ticked. Check *Recent Deliveries* on GitHub. |
| Builds run, but no e-mail | Check the Extended E-mail SMTP settings and app password, then the **Spam** folder. The console log shows the email-ext result at the end. |
| `test_login_page_renders_with_firebase_and_csrf` fails | The Firebase web config is set in the `Jenkinsfile` `environment {}`. Make sure that block wasn't removed. |
| Port 8000 already in use | Something else uses it. Change `-p 8000:5000` in the Deploy stage. |
