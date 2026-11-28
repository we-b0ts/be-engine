# Build context contains only the three prebuilt Linux/amd64 executables.
# scripts/build-engine.sh builds and stages them before invoking Docker.
ARG RUNTIME_IMAGE=be-engine-recorder-runtime:local
FROM ${RUNTIME_IMAGE}

ARG ENGINE_REVISION=unknown
ARG ENGINE_VERSION=unknown
LABEL org.opencontainers.image.title="traffic-e2e engine" \
      org.opencontainers.image.version="${ENGINE_VERSION}" \
      org.opencontainers.image.revision="${ENGINE_REVISION}"

USER 0:0
COPY --chmod=0755 traffic-e2e be-replay backend-rewrite-admin /usr/local/bin/
RUN traffic-e2e --version && be-replay --version && backend-rewrite-admin --version

ENV RUST_LOG=info
WORKDIR /workspace
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/traffic-e2e"]
CMD ["--help"]
