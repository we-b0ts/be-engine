ARG BASE_IMAGE=docker.io/library/debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

FROM ${BASE_IMAGE}

ARG TARGET_UID=998
ARG TARGET_GID=998

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
                    ca-certificates \
                    libgcc-s1 \
                    libssl3 \
                    tzdata; then \
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
    groupadd --gid "${TARGET_GID}" trp-record; \
    useradd \
        --uid "${TARGET_UID}" \
        --gid "${TARGET_GID}" \
        --no-create-home \
        --home-dir /app \
        --shell /usr/sbin/nologin \
        trp-record; \
    install --directory --owner "${TARGET_UID}" --group "${TARGET_GID}" \
        /app \
        /traffic-e2e \
        /traffic-e2e/config \
        /traffic-e2e/trust

ENV HOME=/app \
    TRAFFIC_E2E_CONFIG_DIR=/traffic-e2e/config

USER 998:998
WORKDIR /app
STOPSIGNAL SIGTERM
CMD []
