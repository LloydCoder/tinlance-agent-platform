# syntax=docker/dockerfile:1.7
ARG BASE_IMAGE=ubuntu@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852
ARG APT_SNAPSHOT=20261106T000000Z
FROM ${BASE_IMAGE}
ARG APT_SNAPSHOT

# Bootstrap HTTPS trust from the ephemeral build runner without persisting its
# trust bundle in an image layer. Both index resolution and package installation
# use one immutable, signature-verified Ubuntu snapshot.
RUN --mount=type=secret,id=ca_bundle,target=/tmp/host-ca-bundle.crt,required=true \
    DEBIAN_FRONTEND=noninteractive apt-get \
        -o Acquire::https::CaInfo=/tmp/host-ca-bundle.crt \
        -o Acquire::Retries=5 \
        -o Acquire::https::Timeout=30 \
        -o APT::Update::Error-Mode=any \
        --snapshot="${APT_SNAPSHOT}" update \
    && DEBIAN_FRONTEND=noninteractive apt-get \
        -o Acquire::https::CaInfo=/tmp/host-ca-bundle.crt \
        -o Acquire::Retries=5 \
        -o Acquire::https::Timeout=30 \
        --snapshot="${APT_SNAPSHOT}" install --yes --no-install-recommends \
        ca-certificates=20260816ubuntu0.24.04.2 \
        openssl=3.0.13-0ubuntu3.16 \
        libssl3t64=3.0.13-0ubuntu3.16 \
        git python3 nodejs npm util-linux \
    && install -d /usr/share/tinlance \
    && dpkg-query -W -f='${binary:Package}=${Version}\n' | sort > /usr/share/tinlance/w2-package-manifest.lock \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

RUN --network=none \
    find / -xdev ! -type l -perm /6000 -exec chmod a-s {} + \
    && find / -xdev ! -type l -perm /0022 -exec chmod go-w {} + \
    && find / -xdev -type d -perm /1000 -exec chmod -t {} +

COPY --chown=0:0 . /opt/tinlance-fixture/
RUN --network=none mkdir -p /workspace
RUN --network=none cd /opt/tinlance-fixture/node \
    && npm_config_cache=/tmp/w2-npm-cache npm install --package-lock-only --offline --ignore-scripts --no-audit --no-fund \
    && rm -rf /tmp/w2-npm-cache /root/.npm \
    && git -C /opt/tinlance-fixture init --quiet --initial-branch=main \
    && git -C /opt/tinlance-fixture config user.name "Tinlance W2 Fixture" \
    && git -C /opt/tinlance-fixture config user.email "fixture@invalid.example" \
    && git -C /opt/tinlance-fixture add . \
    && GIT_AUTHOR_DATE="2025-01-01T00:00:00Z" \
       GIT_COMMITTER_DATE="2025-01-01T00:00:00Z" \
       git -C /opt/tinlance-fixture commit --quiet -m "Add deterministic developer workspace fixture" \
    && rm -rf /opt/tinlance-fixture/.git/index /opt/tinlance-fixture/.git/logs \
    && chmod 0555 /opt/tinlance-fixture/run-workspace.sh \
    && chmod -R a=rX /opt/tinlance-fixture \
    && chown -R 65532:65532 /opt/tinlance-fixture

CMD ["/bin/sh", "/opt/tinlance-fixture/run-workspace.sh"]
