# Self-contained image for the test stack: the node, the test wallet and the claims echo all run from it.
# Build context is the repository root (see docker-compose.yml).
FROM python:3.12-slim

ARG GIT_COMMIT=unknown
ENV GIT_COMMIT=${GIT_COMMIT} PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

WORKDIR /app
COPY python/pyproject.toml README.md ./
COPY python/src/ src/
RUN pip install .

COPY web/ /app/web/
COPY deploy/test/entrypoint.sh /opt/entrypoint.sh
COPY deploy/test/wallet/ /opt/wallet/
COPY deploy/test/echo/ /opt/echo/
RUN chmod +x /opt/entrypoint.sh \
    && useradd --create-home --shell /bin/bash nodetide \
    && mkdir -p /data && chown nodetide:nodetide /data

USER nodetide
ENV NODETIDE_HOST=0.0.0.0 NODETIDE_PORT=4557 NODETIDE_DB_PATH=/data/nodetide.db NODETIDE_WEB_ROOT=/app/web
EXPOSE 4557
CMD ["/opt/entrypoint.sh"]
