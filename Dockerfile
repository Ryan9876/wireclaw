ARG NODE_IMAGE=node:24.15.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6
ARG UBUNTU_IMAGE=ubuntu:24.04@sha256:a853f94d226358a79c740cfc7bce0c289748f3fe3488d921d038ccd752c61b60
ARG PYTHON_DEB_VERSION=3.12.3-1ubuntu0.17
ARG WIRESHARK_DEB_VERSION=4.2.2-1.1build3

FROM ${NODE_IMAGE} AS web-build
WORKDIR /src/apps/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci
COPY apps/web/ ./
COPY contracts/ /src/contracts/
RUN npm run build

FROM ${UBUNTU_IMAGE} AS python-build
ARG PYTHON_DEB_VERSION
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       python3.12=${PYTHON_DEB_VERSION} \
       python3.12-venv=${PYTHON_DEB_VERSION} \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY docker/requirements-runtime.lock ./
RUN python3.12 -m venv /opt/venv \
    && /opt/venv/bin/python -m pip install --no-cache-dir -r requirements-runtime.lock

FROM ${UBUNTU_IMAGE} AS core-files
ARG PYTHON_DEB_VERSION
ARG WIRESHARK_DEB_VERSION
ARG UBUNTU_IMAGE
ARG NODE_IMAGE
LABEL org.wireclaw.base-image="${UBUNTU_IMAGE}" \
      org.wireclaw.web-builder-image="${NODE_IMAGE}" \
      org.wireclaw.analyzer-lock="docker/analyzer-versions.lock"
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WIRECLAW_CONTRACTS_DIR=/opt/wireclaw/contracts \
    WIRECLAW_WEB_DIST=/opt/wireclaw/web
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates \
       python3.12=${PYTHON_DEB_VERSION} \
       tshark=${WIRESHARK_DEB_VERSION} \
       wireshark-common=${WIRESHARK_DEB_VERSION} \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 wireclaw \
    && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin wireclaw \
    && install -d -o 10001 -g 10001 /var/lib/wireclaw /opt/wireclaw
COPY --from=python-build /opt/venv /opt/venv
COPY --chown=10001:10001 services/analyzer/src/wireclaw_analyzer/ /opt/venv/lib/python3.12/site-packages/wireclaw_analyzer/
COPY --chown=10001:10001 services/api/src/wireclaw_api/ /opt/venv/lib/python3.12/site-packages/wireclaw_api/
COPY --from=web-build --chown=10001:10001 /src/apps/web/dist/ /opt/wireclaw/web/
COPY --chown=10001:10001 contracts/ /opt/wireclaw/contracts/
COPY --chown=10001:10001 docker/analyzer-versions.lock docker/requirements-runtime.lock docker/verify_analyzer_versions.py /opt/wireclaw/
ENV PATH=/opt/venv/bin:${PATH}
RUN python /opt/wireclaw/verify_analyzer_versions.py \
    && command -v tshark \
    && command -v capinfos \
    && command -v editcap \
    && command -v mergecap

FROM core-files AS core-test
USER 0:0
WORKDIR /opt/wireclaw
COPY pyproject.toml ./
COPY tests/ tests/
ENV PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp/test-home \
    TMPDIR=/tmp
RUN python -m pip install --no-cache-dir pytest==9.1.1 \
    && python -m pytest -q -p no:cacheprovider tests/unit tests/integration

FROM core-files AS core-runtime
USER 10001:10001
WORKDIR /var/lib/wireclaw
EXPOSE 8765
HEALTHCHECK --interval=10s --timeout=3s --start-period=15s --retries=5 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/health', timeout=2).read()"]
ENTRYPOINT ["python", "-m", "wireclaw_api.cli"]
CMD ["--data-root", "/var/lib/wireclaw", "--host", "0.0.0.0", "--port", "8765", "--container-network"]
