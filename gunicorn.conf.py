"""Gunicorn Production WSGI Server Configuration for ThreatWatch AI-IDS.

Configured for production deployment on Render and Linux container runtimes.
"""
import os
import multiprocessing

# Network Binding
bind_port = os.environ.get("PORT", "5000")
bind = f"0.0.0.0:{bind_port}"

# Worker Concurrency & Threading
# On Render free/starter tiers, 2-4 concurrent threads per worker process balance memory and CPU.
workers = int(os.environ.get("WEB_CONCURRENCY", 2))
threads = int(os.environ.get("PYTHON_THREADS", 4))
worker_class = "gthread"

# Worker Lifecycle & Timeouts
# Timeout is set to 120s to allow cold-start initialization of scikit-learn models and MongoDB indexes.
timeout = int(os.environ.get("WEB_TIMEOUT", 120))
graceful_timeout = 30
keepalive = 5
max_requests = 1000
max_requests_jitter = 50

# Logging Configuration
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("LOG_LEVEL", "info")
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)sus'

# Process Management
preload_app = False
daemon = False


def post_fork(server, worker):
    """Lifecycle hook executed immediately after a worker process is forked.

    Initializes database indexes, verifies admin account seeding, and starts
    the background network traffic simulator thread.
    """
    server.log.info("Worker spawned (pid: %s) — initializing application runtime...", worker.pid)
    try:
        from app import init
        init()
        server.log.info("Worker initialization complete.")
    except Exception as e:
        server.log.error("Worker initialization error: %s", e)
