FROM python:3.14-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY lookingglass ./lookingglass
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
# Runs as an unprivileged user and needs no Linux capabilities, so it works with
#   --user <uid>:<gid> --cap-drop=ALL --security-opt=no-new-privileges:true
# /data is world-writable with the sticky bit (like /tmp) so a fresh named volume works for any --user;
# the encryption key inside it is created with mode 0600.
RUN groupadd --system --gid 10001 lookingglass \
    && useradd --system --uid 10001 --gid 10001 --home-dir /data --no-create-home --shell /usr/sbin/nologin lookingglass \
    && mkdir -p /data && chown 10001:10001 /data && chmod 1777 /data
USER 10001:10001
VOLUME ["/data"]
# 8080 = web UI, 5514 = syslog (udp + tcp), 9200 = Zenarmor Elasticsearch-compatible stream receiver
EXPOSE 8080 5514/udp 5514/tcp 9200

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"

ARG VERSION=dev
LABEL org.opencontainers.image.title="Looking Glass" \
      org.opencontainers.image.description="OPNsense security monitoring: log collection, dashboards, detections, reports and an AI analyst" \
      org.opencontainers.image.version="${VERSION}"

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["python", "-m", "lookingglass.main"]
