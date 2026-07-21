ARG RUST_IMAGE=registry.api.demo.test/weibo_rd_if/rust-musl-builder:1.86.0-unittest-tarpaulin
ARG RUNTIME_IMAGE=registry.api.demo.test/weibo_rd_if/debian:12-slim
ARG RUST_TOOLCHAIN=1.88.0

FROM ${RUST_IMAGE} AS builder

ARG RUST_TOOLCHAIN
ENV CARGO_HOME=/opt/rust/cargo \
    CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu \
    RUSTUP_TOOLCHAIN=${RUST_TOOLCHAIN} \
    RUSTUP_DIST_SERVER=https://rsproxy.cn \
    RUSTUP_UPDATE_ROOT=https://rsproxy.cn/rustup

WORKDIR /build/traffic-record

RUN rustup toolchain install "${RUST_TOOLCHAIN}" --profile minimal

COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo
COPY src ./src

RUN cargo build --locked --release \
    && binary="$(find target -type f -path '*/release/traffic-e2e' -print -quit)" \
    && test -n "${binary}" \
    && cp "${binary}" /tmp/traffic-e2e

FROM ${RUNTIME_IMAGE}

ENV RUST_LOG=info

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        iptables \
        sudo \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --shell /bin/bash trp-record \
    && mkdir -p /data/config /data/recordings /data/replay /data/tls

COPY --from=builder /tmp/traffic-e2e /usr/local/bin/traffic-e2e
COPY config/recorder.example.toml /data/config/recorder.toml

WORKDIR /data

EXPOSE 17171

ENTRYPOINT ["/usr/local/bin/traffic-e2e"]
CMD ["record", "--config", "/data/config/recorder.toml", "--no-dns"]
