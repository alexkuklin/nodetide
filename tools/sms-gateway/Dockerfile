# Nodetide SMS gateway: sends verification codes through a USB modem.
# Build from the repository root or from this directory:
#   docker build -t nodetide-sms-gateway tools/sms-gateway
FROM python:3.12-slim

RUN pip install --no-cache-dir pyserial==3.5 \
    && useradd --system --uid 10001 --no-create-home --home-dir /data gateway \
    && mkdir /data && chown gateway /data

COPY sms_gateway.py /app/sms_gateway.py

USER gateway
ENV PYTHONUNBUFFERED=1
VOLUME /data

# SMS_GATEWAY_SERVER, SMS_GATEWAY_DEVICE and SMS_GATEWAY_TOKEN (or a --token-file) come from the environment;
# the limits ledger lives in the /data volume so it survives container recreation.
ENTRYPOINT ["python", "/app/sms_gateway.py", "--state", "/data/ledger.json"]
