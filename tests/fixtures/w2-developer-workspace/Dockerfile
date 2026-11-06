ARG BASE_IMAGE
FROM ${BASE_IMAGE}

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends git python3 nodejs npm ca-certificates util-linux \
    && rm -rf /var/lib/apt/lists/*

COPY --chown=0:0 . /opt/tinlance-fixture/
RUN git -C /opt/tinlance-fixture init --quiet \
    && git -C /opt/tinlance-fixture config user.name "Tinlance W2 Fixture" \
    && git -C /opt/tinlance-fixture config user.email "fixture@invalid.example" \
    && git -C /opt/tinlance-fixture add . \
    && git -C /opt/tinlance-fixture commit --quiet -m "Add deterministic developer workspace fixture" \
    && chmod 0555 /opt/tinlance-fixture/run-workspace.sh \
    && chmod -R a=rX /opt/tinlance-fixture \
    && chown -R 65532:65532 /opt/tinlance-fixture

CMD ["/bin/sh", "/opt/tinlance-fixture/run-workspace.sh"]
