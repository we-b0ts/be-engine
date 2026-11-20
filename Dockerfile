ARG RUST_IMAGE=docker.io/library/rust:1.98.1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e
# Build docker/recorder-runtime first, or pass a published runtime image by digest.
ARG RUNTIME_IMAGE=be-engine-recorder-runtime:local
FROM ${RUST_IMAGE} AS builder

WORKDIR /build
COPY Cargo.toml Cargo.lock build.rs ./
COPY .cargo ./.cargo
COPY crates ./crates
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    cargo build --locked --release --bin traffic-e2e \
    && install -m 0755 /build/target/release/traffic-e2e /tmp/traffic-e2e

FROM ${RUNTIME_IMAGE}

ENV RUST_LOG=info

RUN mkdir -p /data/.traffic-e2e /data/recordings /data/replay /data/tls

COPY --from=builder /tmp/traffic-e2e /usr/local/bin/traffic-e2e
COPY config/project.example.yaml /data/.traffic-e2e/project.yaml
COPY config/policy.example.yaml /data/.traffic-e2e/policy.yaml
COPY config/apis.example.yaml /data/.traffic-e2e/apis.yaml

WORKDIR /data

EXPOSE 4080

ENTRYPOINT ["/usr/local/bin/traffic-e2e"]
CMD ["record", "--config", "/data/.traffic-e2e/project.yaml", "--no-dns"]
