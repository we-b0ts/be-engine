FROM docker.io/library/debian:12-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iptables \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --shell /bin/bash trp-record
