FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY lookingglass ./lookingglass
RUN useradd --system --uid 10001 --home /data lookingglass \
    && mkdir -p /data && chown lookingglass /data

USER lookingglass
VOLUME ["/data"]
# 8080 = web UI, 5514 = syslog (udp + tcp), 9200 = Zenarmor Elasticsearch-compatible stream receiver
EXPOSE 8080 5514/udp 5514/tcp 9200

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"

ARG VERSION=dev
LABEL org.opencontainers.image.title="Looking Glass" \
      org.opencontainers.image.description="OPNsense security monitoring: log collection, dashboards, detections, reports and an AI analyst" \
      org.opencontainers.image.version="${VERSION}"

CMD ["python", "-m", "lookingglass.main"]
