#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

docker buildx build --load --platform linux/amd64 --network none \
  --tag be-engine-network-anchor:local docker/network-anchor

for component in recorder-runtime target-runtime network-probe; do
  docker buildx build --load --platform linux/amd64 \
    --network "${BE_ENGINE_BUILD_NETWORK:-default}" \
    --build-arg HTTP_PROXY --build-arg HTTPS_PROXY --build-arg ALL_PROXY --build-arg NO_PROXY \
    --tag "be-engine-$component:local" "docker/$component"
done
