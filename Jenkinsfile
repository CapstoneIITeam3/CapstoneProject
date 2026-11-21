pipeline {
    agent any

    options {
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        timestamps()
    }

    parameters {
        booleanParam(
            name: 'SIMULATE_BUILD_FAILURE',
            defaultValue: false,
            description: 'Trigger deliberate test failure to demonstrate Jenkins red build, JUnit reporting, and alert email delivery'
        )
    }

    environment {
        SECRET_KEY = 'jenkins-ci-pipeline-secret-key-threatwatch'
        SEED_DEMO = '0'
        REPLAY = '0'
        JENKINS_SIMULATE_FAILURE = "${params.SIMULATE_BUILD_FAILURE ? '1' : '0'}"
        PYTHONUNBUFFERED = '1'
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
                    echo 'Publishing Selenium E2E test analytics report...'
                    junit testResults: 'reports/e2e-results.xml', allowEmptyResults: true
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
    }
}
