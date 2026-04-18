# ================================================================
# ESO — Dockerfile (production-hardened)
# ================================================================

FROM python:3.12-slim

# Security: run as non-root user
RUN groupadd -r eso && useradd -r -g eso -d /app -s /sbin/nologin eso

WORKDIR /app

# System deps — minimal, pinned to slim image
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Install Python deps as root before switching user
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ src/
COPY config/ config/

# Own files by app user
RUN chown -R eso:eso /app

# Switch to non-root
USER eso

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Production: 2 workers, no reload
CMD ["uvicorn", "src.api.app:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--workers", "2", \
     "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
