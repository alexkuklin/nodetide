# Distriblog Python Docker Image
# Multi-stage build for smaller final image

# Build stage
FROM python:3.11-slim as builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY python/pyproject.toml .
COPY README.md .
COPY python/src/ src/

# Build wheel
RUN pip install --no-cache-dir build && \
    python -m build --wheel


# Runtime stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libffi8 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /bin/bash distriblog

# Copy wheel from builder and install
COPY --from=builder /build/dist/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm /tmp/*.whl

# Copy web client files
COPY web/ /app/web/

# Create data directory
RUN mkdir -p /data && chown distriblog:distriblog /data

# Switch to non-root user
USER distriblog

# Environment variables
ENV DISTRIBLOG_HOST=0.0.0.0
ENV DISTRIBLOG_PORT=4557
ENV DISTRIBLOG_DB_PATH=/data/distriblog.db
ENV DISTRIBLOG_WEB_ROOT=/app/web

# Expose API port
EXPOSE 4557

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:4557/health')" || exit 1

# Run the API server
CMD ["python", "-m", "distriblog.cli.main", "api", "start", \
     "--host", "0.0.0.0", \
     "--port", "4557"]
