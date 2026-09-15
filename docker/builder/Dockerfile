FROM docker.io/library/rust:1.86.0-bookworm@sha256:300ec56abce8cc9448ddea2172747d048ed902a3090e6b57babb2bf19f754081

ENV CARGO_HOME=/opt/rust/cargo \
    RUSTUP_TOOLCHAIN=1.98.1 \
    RUSTUP_DIST_SERVER=https://rsproxy.cn \
    RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup

RUN apt-get update \
    && apt-get install --yes --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*

RUN rustup toolchain install "${RUSTUP_TOOLCHAIN}" \
        --profile minimal \
        --target x86_64-unknown-linux-musl

COPY .cargo/config.toml ${CARGO_HOME}/config.toml
