# Distriblog Python Docker Image
# Uses pre-built base image with dependencies for faster builds

# Base image with pre-installed dependencies
ARG BASE_IMAGE=distriblog-python-base:latest
ARG GIT_COMMIT=unknown
FROM ${BASE_IMAGE}

WORKDIR /app

# Copy project files
COPY python/pyproject.toml .
COPY README.md .
COPY python/src/ src/

# Install the package (dependencies already in base image)
RUN pip install --no-cache-dir --no-deps .

# Copy web client files
COPY web/ /app/web/

# Switch to non-root user
USER distriblog

# Environment variables
ARG GIT_COMMIT
ENV GIT_COMMIT=${GIT_COMMIT}
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
