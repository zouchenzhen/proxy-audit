FROM python:3.12-slim-bookworm AS cores

ARG SINGBOX_VERSION=1.13.3
ARG SINGBOX_SHA256=8f5336cc671851147b695b28bb69a8ae9e7b7bb9ad0513a2099a1e9be413be8f
ARG XRAY_VERSION=26.3.27
ARG XRAY_SHA256=23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
RUN mkdir -p /runtime/source \
    && curl --fail --location --retry 3 \
      "https://github.com/SagerNet/sing-box/releases/download/v${SINGBOX_VERSION}/sing-box-${SINGBOX_VERSION}-linux-amd64-glibc.tar.gz" \
      --output sing-box.tar.gz \
    && echo "${SINGBOX_SHA256}  sing-box.tar.gz" | sha256sum --check --strict \
    && mkdir sing-box \
    && tar -xzf sing-box.tar.gz --strip-components=1 -C sing-box \
    && install -Dm755 sing-box/sing-box /runtime/bin/sing-box \
    && git clone --depth 1 --branch "v${SINGBOX_VERSION}" https://github.com/SagerNet/sing-box.git sing-box-source \
    && install -Dm644 sing-box-source/LICENSE /runtime/licenses/sing-box-LICENSE \
    && git -C sing-box-source archive --format=tar.gz --output=/runtime/source/sing-box-${SINGBOX_VERSION}-source.tar.gz HEAD

RUN curl --fail --location --retry 3 \
      "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" \
      --output xray.zip \
    && echo "${XRAY_SHA256}  xray.zip" | sha256sum --check --strict \
    && mkdir xray \
    && unzip -q xray.zip -d xray \
    && install -Dm755 xray/xray /runtime/bin/xray \
    && git clone --depth 1 --branch "v${XRAY_VERSION}" https://github.com/XTLS/Xray-core.git xray-source \
    && install -Dm644 xray-source/LICENSE /runtime/licenses/xray-LICENSE \
    && git -C xray-source archive --format=tar.gz --output=/runtime/source/xray-${XRAY_VERSION}-source.tar.gz HEAD

FROM cores AS core-verify
RUN /runtime/bin/sing-box version \
    && /runtime/bin/xray version \
    && test -s /runtime/licenses/sing-box-LICENSE \
    && test -s /runtime/licenses/xray-LICENSE \
    && test -s /runtime/source/sing-box-${SINGBOX_VERSION}-source.tar.gz \
    && test -s /runtime/source/xray-${XRAY_VERSION}-source.tar.gz

FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PROXY_AUDIT_SINGBOX_PATH=/opt/proxy-audit/third-party/bin/sing-box \
    PROXY_AUDIT_XRAY_PATH=/opt/proxy-audit/third-party/bin/xray \
    PORT=7860

RUN groupadd --gid 1000 app \
    && useradd --uid 1000 --gid app --create-home app

WORKDIR /app
COPY requirements.txt requirements-cloud.txt ./
RUN pip install --no-cache-dir --requirement requirements-cloud.txt

COPY --from=core-verify /runtime /opt/proxy-audit/third-party
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md ./
COPY scripts ./scripts
COPY web ./web

RUN mkdir -p input results/raw results/csv results/reports temp/configs temp/logs \
    && chown -R app:app /app /opt/proxy-audit

USER app
EXPOSE 7860
HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/api/health' % os.environ.get('PORT','7860'), timeout=3).read()"

# One worker is deliberate: anonymous sessions live only in this process memory.
CMD ["sh", "-c", "exec gunicorn --workers 1 --threads 8 --timeout 180 --bind 0.0.0.0:${PORT:-7860} --access-logfile - --error-logfile - --chdir scripts 'cloud_app:create_app()'"]
