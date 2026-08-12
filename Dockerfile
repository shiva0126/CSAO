FROM python:3.12-slim

# WeasyPrint (PDF report generation) needs these at runtime, not just
# cryptography/psycopg build-time deps. Retry loop guards against transient
# Debian mirror flakiness (hash mismatches / failed index fetches) observed
# during local builds.
RUN for i in 1 2 3 4 5; do \
        apt-get update && apt-get install -y --no-install-recommends \
            build-essential \
            libpq-dev \
            libffi-dev \
            libpango-1.0-0 \
            libpangocairo-1.0-0 \
            libcairo2 \
            libgdk-pixbuf-2.0-0 \
            shared-mime-info \
            fonts-liberation \
            curl \
            unzip \
            ca-certificates \
        && break || { echo "apt attempt $i failed, retrying..."; sleep 5; }; \
    done \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt requirements-collectors.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -r requirements-collectors.txt

# AWS CLI v2 -- official installer, arch-aware since this image may run on
# amd64 or arm64 depending on who deploys it (docker build's TARGETARCH
# build-arg is set automatically by buildx; falls back to `uname -m` for
# plain `docker build`).
#
# All network calls in this stage use explicit --connect-timeout/--max-time
# and a `timeout` wrapper around the plugin install: a previous build
# attempt hung indefinitely with no visible error on a stalled connection,
# burning 30+ minutes before it had to be killed manually. Fail fast and
# retry instead of hanging silently.
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH:-$(dpkg --print-architecture)}" in \
        amd64) AWSCLI_ARCH=x86_64 ;; \
        arm64) AWSCLI_ARCH=aarch64 ;; \
        *) AWSCLI_ARCH=x86_64 ;; \
    esac; \
    for i in 1 2 3 4 5; do \
        curl --connect-timeout 10 --max-time 60 -fsSL \
            "https://awscli.amazonaws.com/awscli-exe-linux-${AWSCLI_ARCH}.zip" -o /tmp/awscliv2.zip && \
        [ -s /tmp/awscliv2.zip ] && break || \
        { echo "aws cli download attempt $i failed, retrying..."; rm -f /tmp/awscliv2.zip; sleep 5; }; \
    done; \
    [ -s /tmp/awscliv2.zip ]; \
    unzip -q /tmp/awscliv2.zip -d /tmp; \
    /tmp/aws/install; \
    rm -rf /tmp/awscliv2.zip /tmp/aws

# Steampipe -- not pip-installable. The `aws` plugin is required for
# queries/aws/*.sql (see modules/steampipe_runner.py -- nothing else
# installs this plugin).
#
# Fetches the release tarball directly instead of running the official
# install script: that script does its own single-shot curl with no retry
# logic, and on at least one build host it failed two different ways --
# a DNS/routing timeout to raw.githubusercontent.com's Fastly range, and
# (once that leg was worked around) a mid-handshake TLS EOF downloading
# the release asset from GitHub, consistent with an MTU/packet-loss
# interaction with HTTP/2 framing on that network path. --http1.1 avoids
# the latter; the retry loop (same pattern used for AWS CLI above) covers
# the former. Downloaded to a file and checked non-empty before extracting
# rather than piping straight into a shell, so a transient curl failure
# fails the build loudly instead of silently extracting nothing.
RUN set -eux; \
    for i in 1 2 3 4 5; do \
        curl --connect-timeout 10 --max-time 120 -fsSL --http1.1 \
            -o /tmp/steampipe.tar.gz \
            https://github.com/turbot/steampipe/releases/latest/download/steampipe_linux_amd64.tar.gz && \
        [ -s /tmp/steampipe.tar.gz ] && break || \
        { echo "steampipe download attempt $i failed, retrying..."; rm -f /tmp/steampipe.tar.gz; sleep 5; }; \
    done; \
    [ -s /tmp/steampipe.tar.gz ]; \
    tar -xzf /tmp/steampipe.tar.gz -C /usr/local/bin steampipe; \
    mv /usr/local/bin/steampipe /usr/local/bin/steampipe-bin; \
    rm /tmp/steampipe.tar.gz; \
    chmod +x /usr/local/bin/steampipe-bin

# Steampipe refuses to run any command as root (it manages its own embedded
# Postgres engine and unix socket, and treats root as a security risk) --
# but this whole image otherwise runs as root, including at runtime inside
# the `worker` service (see docker-compose.yml, no `user:` override). Rather
# than rearchitect the container to run non-root end to end (which would
# break write access to the root-owned bind-mounted output/logs/cache dirs),
# a dedicated unprivileged user runs steampipe alone, with its own $HOME
# (separate from the bind-mounted /app) holding its install dir, plugins,
# and embedded DB. `steampipe` is a setpriv-based wrapper around the real
# binary so every existing `subprocess.run(["steampipe", ...])` call site in
# modules/steampipe_runner.py keeps working unmodified -- it transparently
# drops privileges before exec'ing, no app code change needed.
RUN set -eux; \
    groupadd -g 10001 steampipe; \
    useradd -u 10001 -g steampipe -m -d /home/steampipe -s /usr/sbin/nologin steampipe; \
    printf '#!/bin/sh\nexport HOME=/home/steampipe\nexec setpriv --reuid=10001 --regid=10001 --clear-groups /usr/local/bin/steampipe-bin "$@"\n' \
        > /usr/local/bin/steampipe; \
    chmod +x /usr/local/bin/steampipe; \
    command -v steampipe; \
    timeout 180 steampipe plugin install aws

# App code is bind-mounted by docker-compose.yml at runtime, not baked into
# the image -- this keeps local iteration fast (no rebuild on every edit).
