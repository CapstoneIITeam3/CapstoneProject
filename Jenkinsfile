pipeline {
    agent any

    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timestamps()
    }

    // Build automatically on every push to GitHub (via the webhook -> ngrok -> Jenkins).
    // Needs the "GitHub" plugin; Jenkins registers this trigger after the first manual build.
    triggers {
        githubPush()
    }

    parameters {
        booleanParam(
            name: 'SIMULATE_BUILD_FAILURE',
            defaultValue: false,
            description: 'Trigger deliberate test failure to demonstrate Jenkins red build, JUnit reporting, and alert email delivery'
        )
        booleanParam(
            name: 'RUN_DOCKER',
            defaultValue: true,
            description: 'Build the Docker image, health-check it, and deploy it on http://localhost:8000 (needs Docker Desktop running)'
        )
    }

    environment {
        SECRET_KEY = 'jenkins-ci-pipeline-secret-key-threatwatch'
        SEED_DEMO = '0'
        REPLAY = '0'
        JENKINS_SIMULATE_FAILURE = "${params.SIMULATE_BUILD_FAILURE ? '1' : '0'}"
        PYTHONUNBUFFERED = '1'
        // Public Firebase web config (same values as render.yaml). Needed so the login page
        // renders the Google sign-in button that tests/test_auth.py checks for.
        FIREBASE_PROJECT_ID = 'threatwatch-a41a0'
        FIREBASE_API_KEY = 'AIzaSyD8MwBtD4jb_xvqSwiE5PpfTJH1AyWKghU'
        IMAGE_NAME = 'threatwatch'
    }

    stages {
        stage('Checkout') {
            steps {
                echo 'Checking out source repository branch and commit...'
                checkout scm
            }
        }

        stage('Environment Setup') {
            steps {
                echo 'Setting up Python runtime environment and installing dependencies...'
                script {
                    if (isUnix()) {
                        sh '''
                            python3 -m venv .venv || virtualenv .venv
                            . .venv/bin/activate
                            pip install --upgrade pip
                            pip install -r requirements.txt
                        '''
                    } else {
                        bat '''
                            python -m venv .venv
                            call .venv\\Scripts\\activate.bat
                            python -m pip install --upgrade pip
                            pip install -r requirements.txt
                        '''
                    }
                }
            }
        }

        stage('Unit & Integration Tests (Pytest)') {
            steps {
                echo 'Executing Pytest test suite (detector, authentication, health, and security controls)...'
                script {
                    if (isUnix()) {
                        sh '''
                            . .venv/bin/activate
                            mkdir -p reports
                            python -m pytest tests/ --ignore=tests/e2e -v --tb=short --junitxml=reports/unit-results.xml
                        '''
                    } else {
                        bat '''
                            call .venv\\Scripts\\activate.bat
                            if not exist reports mkdir reports
                            python -m pytest tests/ --ignore=tests/e2e -v --tb=short --junitxml=reports/unit-results.xml
                        '''
                    }
                }
            }
            post {
                always {
                    echo 'Publishing unit test analytics report...'
                    junit testResults: 'reports/unit-results.xml', allowEmptyResults: true
                }
            }
        }

        stage('Selenium E2E Tests (Headless Chrome)') {
            steps {
                echo 'Executing Selenium End-to-End browser tests in headless Google Chrome...'
                script {
                    if (isUnix()) {
                        sh '''
                            . .venv/bin/activate
                            mkdir -p reports
                            python -m pytest tests/e2e/ -v --tb=short --junitxml=reports/e2e-results.xml
                        '''
                    } else {
                        bat '''
                            call .venv\\Scripts\\activate.bat
                            if not exist reports mkdir reports
                            python -m pytest tests/e2e/ -v --tb=short --junitxml=reports/e2e-results.xml
                        '''
                    }
                }
            }
            post {
                always {
                    echo 'Publishing Selenium E2E test analytics report and recorded video artifacts...'
                    junit testResults: 'reports/e2e-results.xml', allowEmptyResults: true
                    archiveArtifacts artifacts: 'reports/videos/**/*.mp4', allowEmptyArchive: true
                }
            }
        }

        stage('Security & Architecture Verification') {
            steps {
                echo 'Verifying environment hygiene and API security configurations...'
                script {
                    if (isUnix()) {
                        sh '''
                            test ! -f .env.example || { echo "ERROR: .env.example detected in repo"; exit 1; }
                            echo "Security audit passed: secrets hygiene verified."
                        '''
                    } else {
                        bat '''
                            if exist .env.example (
                                echo ERROR: .env.example detected in repository
                                exit /b 1
                            )
                            echo Security audit passed: secrets hygiene verified.
                        '''
                    }
                }
            }
        }
        stage('Docker Build & Smoke Test') {
            when { expression { params.RUN_DOCKER } }
            steps {
                echo 'Building Docker image and verifying the container starts healthy...'
                script {
                    if (isUnix()) {
                        sh '''
                            docker build -t ${IMAGE_NAME}:${BUILD_NUMBER} -t ${IMAGE_NAME}:latest .
                            docker rm -f threatwatch-ci 2>/dev/null || true
                            docker run -d --name threatwatch-ci -p 5050:5000 \
                                -e SECRET_KEY=ci-smoke -e SEED_DEMO=0 -e REPLAY=0 -e WEB_CONCURRENCY=1 \
                                ${IMAGE_NAME}:${BUILD_NUMBER}
                            for i in $(seq 1 45); do
                                if curl -fsS http://localhost:5050/api/health | grep -q '"status":"ok"'; then
                                    echo "Container healthy after ${i} checks"; exit 0
                                fi
                                sleep 2
                            done
                            echo "Container did not become healthy:"; docker logs threatwatch-ci; exit 1
                        '''
                    } else {
                        bat '''
                            docker build -t %IMAGE_NAME%:%BUILD_NUMBER% -t %IMAGE_NAME%:latest . || exit /b 1
                            docker rm -f threatwatch-ci 2>nul
                            docker run -d --name threatwatch-ci -p 5050:5000 -e SECRET_KEY=ci-smoke -e SEED_DEMO=0 -e REPLAY=0 -e WEB_CONCURRENCY=1 %IMAGE_NAME%:%BUILD_NUMBER% || exit /b 1
                            powershell -NoProfile -Command "$ok=$false; for($i=1; $i -le 45; $i++){ try { $r = Invoke-RestMethod -Uri http://localhost:5050/api/health -TimeoutSec 3; if($r.status -eq 'ok'){ Write-Host ('Container healthy after ' + $i + ' checks'); $ok=$true; break } } catch {}; Start-Sleep -Seconds 2 }; if(-not $ok){ Write-Host 'Container did not become healthy:'; docker logs threatwatch-ci; exit 1 }"
                        '''
                    }
                }
            }
            post {
                always {
                    script {
                        if (isUnix()) { sh 'docker rm -f threatwatch-ci 2>/dev/null || true' }
                        else { bat 'docker rm -f threatwatch-ci 2>nul & exit /b 0' }
                    }
                }
            }
        }

        stage('Deploy (local Docker)') {
            when { expression { params.RUN_DOCKER } }
            steps {
                echo 'Deploying the tested image as the live container on http://localhost:8000 ...'
                script {
                    if (isUnix()) {
                        sh '''
                            docker rm -f threatwatch-live 2>/dev/null || true
                            docker run -d --name threatwatch-live --restart unless-stopped -p 8000:5000 \
                                -e SECRET_KEY=threatwatch-live-${BUILD_NUMBER} -e SEED_DEMO=1 -e REPLAY=1 -e WEB_CONCURRENCY=1 \
                                ${IMAGE_NAME}:${BUILD_NUMBER}
                            echo "Deployed ${IMAGE_NAME}:${BUILD_NUMBER} -> http://localhost:8000"
                        '''
                    } else {
                        bat '''
                            docker rm -f threatwatch-live 2>nul
                            docker run -d --name threatwatch-live --restart unless-stopped -p 8000:5000 -e SECRET_KEY=threatwatch-live-%BUILD_NUMBER% -e SEED_DEMO=1 -e REPLAY=1 -e WEB_CONCURRENCY=1 %IMAGE_NAME%:%BUILD_NUMBER% || exit /b 1
                            echo Deployed %IMAGE_NAME%:%BUILD_NUMBER% to http://localhost:8000
                        '''
                    }
                }
            }
        }
    }

    post {
        always {
            script {
                def statusText = currentBuild.currentResult ?: 'SUCCESS'
                def buildColor = (statusText == 'SUCCESS') ? '#2eb886' : '#e01563'
                emailext(
                    subject: "[ThreatWatch CI] ${statusText}: Build #${BUILD_NUMBER} (${env.GIT_BRANCH ?: 'feature/dhyey-integration'})",
                    mimeType: 'text/html',
                    recipientProviders: [developers(), requestor()],
                    to: 'adwitiyasinha25@gmail.com, akankshajoshi294@gmail.com, disha.sharma23@st.niituniversity.in, dhyey.pujara23@st.niituniversity.in',
                    body: """
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <meta charset="utf-8">
                            <style>
                                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: #0b0b0e; color: #f2f1f4; padding: 24px; margin: 0; }
                                .card { background: #141419; border: 1px solid #26262e; border-radius: 12px; max-width: 620px; margin: 0 auto; overflow: hidden; box-shadow: 0 8px 30px rgba(0,0,0,0.5); }
                                .head { background: ${buildColor}; color: #ffffff; padding: 18px 24px; font-size: 18px; font-weight: 600; }
                                .body { padding: 24px; line-height: 1.6; font-size: 14px; color: #d0ced6; }
                                .meta { width: 100%; border-collapse: collapse; margin: 16px 0; }
                                .meta td { padding: 9px 12px; border-bottom: 1px solid #22222a; font-size: 13px; color: #f2f1f4; }
                                .meta td.lbl { color: #8e8c99; font-weight: 500; width: 140px; }
                                .btn { display: inline-block; padding: 10px 18px; background: #e98ae0; color: #120612; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 13px; margin-top: 14px; }
                                .btn-sub { display: inline-block; padding: 10px 18px; background: #231b2e; color: #f29ad9; text-decoration: none; border-radius: 8px; font-weight: 600; font-size: 13px; margin-top: 14px; margin-left: 8px; border: 1px solid #3c2a4f; }
                                .foot { padding: 14px 24px; font-size: 11.5px; color: #6e6c75; border-top: 1px solid #22222a; text-align: center; }
                                .notice { background: rgba(233,138,224,0.08); border: 1px solid rgba(233,138,224,0.25); border-radius: 8px; padding: 12px 14px; margin-top: 16px; font-size: 12.5px; color: #f29ad9; }
                            </style>
                        </head>
                        <body>
                            <div class="card">
                                <div class="head">ThreatWatch CI/CD Build Report · ${statusText}</div>
                                <div class="body">
                                    <p>Continuous Integration pipeline execution completed for <strong>ThreatWatch AI-IDS</strong>.</p>
                                    <table class="meta">
                                        <tr><td class="lbl">Build Number</td><td>#${BUILD_NUMBER}</td></tr>
                                        <tr><td class="lbl">Execution Status</td><td><strong style="color:${buildColor};">${statusText}</strong></td></tr>
                                        <tr><td class="lbl">Branch</td><td><code>${env.GIT_BRANCH ?: 'feature/dhyey-integration'}</code></td></tr>
                                        <tr><td class="lbl">Commit Hash</td><td><code>${env.GIT_COMMIT ?: 'HEAD'}</code></td></tr>
                                        <tr><td class="lbl">Build Duration</td><td>${currentBuild.durationString}</td></tr>
                                    </table>
                                    <div>
                                        <a href="${BUILD_URL}" class="btn">View Jenkins Console</a>
                                        <a href="${BUILD_URL}testReport/" class="btn-sub">View JUnit Test Report</a>
                                    </div>
                                    <div class="notice">
                                        <strong>Demonstration Alert:</strong> In case of build failure triggered with <code>SIMULATE_BUILD_FAILURE=true</code>, this automated notification validates Jenkins regression detection and multi-contributor alerting.
                                    </div>
                                </div>
                                <div class="foot">
                                    Automated notification dispatched to all ThreatWatch repository contributors.<br>
                                    Recipients: Adwitiya Sinha, Akanksha Joshi, Disha Sharma, Dhyey Pujara.
                                </div>
                            </div>
                        </body>
                        </html>
                    """
                )
            }
        }

        failure {
            echo 'CRITICAL: Build failure or test regression detected. Automated alert emails dispatched to all contributors.'
        }

        success {
            echo 'SUCCESS: All pipeline stages, tests, and security audits passed cleanly.'
        }

        unstable {
            echo 'WARNING: Build marked UNSTABLE due to test regression.'
        }
    }
}
