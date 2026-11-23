# ThreatWatch AI-IDS: production container image
#   docker build -t threatwatch .
#   docker run -p 5000:5000 --env-file .env threatwatch
# Secrets (MONGO_URI, SMTP, Firebase) are passed at run time with --env-file / -e.
# They are never baked into the image (.env is excluded by .dockerignore).

FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=5000

WORKDIR /app

# Dependencies first, so this layer is cached between code-only changes
COPY requirements.txt .
RUN pip install -r requirements.txt

# Application code + trained models (ml/*.pkl)
COPY . .

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 appuser && chown -R appuser /app
USER appuser

EXPOSE 5000

# python:slim has no curl, so the health check uses the standard library
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD python -c "import json,os,urllib.request,sys; r=urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"5000\")}/api/health',timeout=4); sys.exit(0 if json.load(r).get('status')=='ok' else 1)"

CMD ["gunicorn", "--config", "gunicorn.conf.py", "app:app"]
