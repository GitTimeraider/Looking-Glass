FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY monraider ./monraider
RUN useradd --system --uid 10001 --home /data monraider \
    && mkdir -p /data && chown monraider /data

USER monraider
VOLUME ["/data"]
# 8080 = web UI, 5514 = syslog (udp + tcp)
EXPOSE 8080 5514/udp 5514/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"

ARG VERSION=dev
LABEL org.opencontainers.image.title="MonRaider" \
      org.opencontainers.image.description="OPNsense security monitoring: log collection, dashboards, detections, reports and an AI analyst" \
      org.opencontainers.image.version="${VERSION}"

CMD ["python", "-m", "monraider.main"]
