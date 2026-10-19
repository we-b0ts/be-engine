# Distribution artifact for multi-stage COPY into a project's recording image.
# scripts/build-kubectl.sh validates and stages the static Linux/amd64 executable.
FROM scratch
ARG KUBECTL_VERSION
ARG KUBECTL_SHA256
COPY --chmod=0755 kubectl /usr/local/bin/kubectl
LABEL org.opencontainers.image.title="kubectl" \
      org.opencontainers.image.version="${KUBECTL_VERSION}" \
      io.traffic-e2e.kubectl.version="${KUBECTL_VERSION}" \
      io.traffic-e2e.kubectl.sha256="${KUBECTL_SHA256}"
USER 0:0
ENTRYPOINT ["/usr/local/bin/kubectl"]
