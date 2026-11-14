# ShipSafe demo app image - the "clean" Dockerfile the lint gate must pass on.
#
# - Base image pinned by exact version AND multi-arch index digest.
# - Debian security updates applied at build time (the digest pin freezes the
#   base image, so fixes published after it would otherwise be missing).
# - Dependencies come from the fully pinned requirements.txt; pip itself is
#   then removed - the app never needs it at runtime, and its vendored copies
#   of urllib3/msgpack/setuptools carry their own advisories.
# - Runs as a dedicated non-root user (uid/gid 10001).
# - No build args, secrets, or credentials are used or baked in.
# Build: docker build -t shipsafe-demo demo-app/
FROM python:3.13.18-slim-trixie@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Security updates only from the distro. --error-on=any makes an unreachable
# mirror fail the build instead of silently skipping the updates.
RUN apt-get update --error-on=any \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system --gid 10001 app \
    && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m pip uninstall --yes pip

COPY app/ ./app/

USER 10001:10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"]

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
