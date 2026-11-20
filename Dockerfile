FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    HOST=0.0.0.0 \
    PORT=5000 \
    CYBER_SENTINEL_DB=/data/security.db

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --system --uid 10001 --create-home cyber \
    && mkdir -p /data \
    && chown cyber:cyber /data

# Whole package (routes/ included); tests and local databases are excluded by .dockerignore.
COPY backend /app/backend
USER cyber
EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "from urllib.request import urlopen; urlopen('http://127.0.0.1:5000/api/health', timeout=3)"

COPY gunicorn.conf.py /app/gunicorn.conf.py
CMD ["gunicorn", "--config=/app/gunicorn.conf.py", "backend.app:app"]
