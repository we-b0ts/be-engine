ARG RUST_IMAGE=registry.api.demo.test/weibo_rd_if/rust-builder:1.98.1@sha256:99fe1fa7319ef65993c61ca9aa9f3e58a10573a2701a19109adabca46007a670
ARG RUNTIME_IMAGE=registry.api.demo.test/weibo_rd_if/traffic-e2e-recorder-runtime:0.0.1-dev@sha256:c71fa374b229bc6fbf7ad34c5bb5cede1c27b2314a7b274b62ce2d44d3213107

FROM ${RUST_IMAGE} AS builder

ENV CARGO_HOME=/opt/rust/cargo \
    RUSTUP_TOOLCHAIN=1.98.1

WORKDIR /build/traffic-record

COPY Cargo.toml Cargo.lock ./
COPY .cargo ./.cargo

RUN mkdir src \
    && printf 'pub fn dependency_cache_anchor() {}\n' > src/lib.rs \
    && printf 'fn main() {}\n' > src/main.rs \
    && cargo build --locked --release \
    && rm -rf src

COPY src ./src

RUN touch src/lib.rs src/main.rs \
    && cargo build --locked --release \
    && binary="$(find target -type f -path '*/release/traffic-e2e' -print -quit)" \
    && test -n "${binary}" \
    && cp "${binary}" /tmp/traffic-e2e

FROM ${RUNTIME_IMAGE}

ENV RUST_LOG=info

RUN mkdir -p /data/config /data/recordings /data/replay /data/tls

COPY --from=builder /tmp/traffic-e2e /usr/local/bin/traffic-e2e
COPY config/project.example.yaml /data/config/project.yaml
COPY config/source-traffic-policy.example.yaml /data/config/source-traffic-policy.example.yaml

WORKDIR /data

EXPOSE 4080

ENTRYPOINT ["/usr/local/bin/traffic-e2e"]
CMD ["record", "--config", "/data/config/project.yaml", "--no-dns"]
