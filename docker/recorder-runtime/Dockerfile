ARG BASE_IMAGE=docker.io/library/debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

FROM ${BASE_IMAGE}

ARG RECORD_UID=998
ARG RECORD_GID=998

RUN set -eu; \
    attempt=1; \
    while [ "${attempt}" -le 3 ]; do \
        rm -rf /var/lib/apt/lists/*; \
        if apt-get \
                -o Acquire::Retries=3 \
                -o Acquire::http::Timeout=30 \
                -o Acquire::https::Timeout=30 \
                update \
            && DEBIAN_FRONTEND=noninteractive apt-get \
                -o Acquire::Retries=3 \
                -o Acquire::http::Timeout=30 \
                -o Acquire::https::Timeout=30 \
                install --yes --no-install-recommends \
                    acl \
                    ca-certificates \
                    curl \
                    iproute2 \
                    iptables \
                    libgcc-s1 \
                    openssl \
                    procps; then \
            break; \
        fi; \
        if [ "${attempt}" -eq 3 ]; then \
            exit 1; \
        fi; \
        sleep_seconds=$((attempt * 2)); \
        printf 'package installation attempt %s failed; retrying in %s seconds\n' \
            "${attempt}" "${sleep_seconds}" >&2; \
        sleep "${sleep_seconds}"; \
        attempt=$((attempt + 1)); \
    done; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --gid "${RECORD_GID}" trp-record; \
    useradd \
        --uid "${RECORD_UID}" \
        --gid "${RECORD_GID}" \
        --no-create-home \
        --home-dir /workspace \
        --shell /usr/sbin/nologin \
        trp-record; \
    install --directory --owner "${RECORD_UID}" --group "${RECORD_GID}" /workspace

USER 0:0
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/traffic-e2e"]
