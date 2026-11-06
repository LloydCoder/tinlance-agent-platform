ARG BASE_IMAGE
ARG APT_SNAPSHOT=20261106T000000Z
FROM ${BASE_IMAGE}
ARG APT_SNAPSHOT

RUN DEBIAN_FRONTEND=noninteractive apt-get --snapshot="${APT_SNAPSHOT}" update \
    && DEBIAN_FRONTEND=noninteractive apt-get --snapshot="${APT_SNAPSHOT}" install --yes --no-install-recommends git python3 nodejs npm ca-certificates util-linux \
    && install -d /usr/share/tinlance \
    && dpkg-query -W -f='${binary:Package}=${Version}\\n' | sort > /usr/share/tinlance/w2-package-manifest.lock \
    && rm -rf /var/lib/apt/lists/*

COPY --chown=0:0 . /opt/tinlance-fixture/
RUN mkdir -p /workspace
RUN git -C /opt/tinlance-fixture init --quiet \
    && git -C /opt/tinlance-fixture config user.name "Tinlance W2 Fixture" \
    && git -C /opt/tinlance-fixture config user.email "fixture@invalid.example" \
    && git -C /opt/tinlance-fixture add . \
    && git -C /opt/tinlance-fixture commit --quiet -m "Add deterministic developer workspace fixture" \
    && chmod 0555 /opt/tinlance-fixture/run-workspace.sh \
    && chmod -R a=rX /opt/tinlance-fixture \
    && chown -R 65532:65532 /opt/tinlance-fixture

CMD ["/bin/sh", "/opt/tinlance-fixture/run-workspace.sh"]
