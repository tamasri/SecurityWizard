# SecurityWizard container image.
#
# Limitations (read before relying on it):
#   * A container sees only its own namespaces. To audit the HOST you must mount host paths read-only and run with
#     the host's PID/network namespaces, which weakens the isolation this image otherwise gives you. Running
#     SecurityWizard directly on the host (./setup.sh) gives the most accurate audit.
#   * Applying fixes from inside a container is not supported: keep SECURITYWIZARD_DRY_RUN_ONLY=1 (the default here).
#   * The dashboard has no TLS. Publish the port on 127.0.0.1 only and reach it through an SSH tunnel or a reverse proxy.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SECURITYWIZARD_DRY_RUN_ONLY=1 \
    SECURITYWIZARD_DATA_DIR=/data \
    SECURITYWIZARD_BACKUP_DIR=/data/backups

RUN useradd --system --uid 10001 --home-dir /app --shell /usr/sbin/nologin securitywizard \
    && mkdir -p /app /data \
    && chown securitywizard /data

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

USER securitywizard
VOLUME ["/data"]
EXPOSE 8443

# Inside a container the dashboard must listen on all interfaces to be reachable through a published port.
# This is the only place where a non-loopback bind is set; publish it as `-p 127.0.0.1:8443:8443`.
# Authentication stays enabled: read the generated credentials from the container log on the first start.
ENV SECURITYWIZARD_BIND=0.0.0.0 \
    SECURITYWIZARD_ALLOWED_HOSTS=127.0.0.1,localhost,[::1]

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8443/api/health', timeout=3)" || exit 1

CMD ["python", "main.py"]
