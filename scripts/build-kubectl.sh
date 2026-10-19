#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: build-kubectl.sh [--kubectl PATH] [--tag IMAGE] [--publish]

Package an existing static Linux/amd64 kubectl in a standalone binary image.
Only the executable is staged in a temporary Docker build context.

  --kubectl PATH  Existing binary; defaults to KUBECTL_BINARY or kubectl on PATH.
  --tag IMAGE     Defaults to registry.api.demo.test/weibo_rd_if/kubectl:<version>.
  --publish      Push after local verification; refuses to overwrite an existing tag.

Example:
  ./scripts/build-kubectl.sh --kubectl /data0/icy/bin/kubectl --publish

The image contains only kubectl; project recording images copy the executable.
No kubeconfig or credentials enter this image or its build context.
EOF
}

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

kubectl_binary="${KUBECTL_BINARY:-}"
image_tag=''
publish=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --kubectl)
      [[ $# -ge 2 && -n "$2" ]] || fail '--kubectl requires a binary path.'
      kubectl_binary="$2"
      shift 2
      ;;
    --tag)
      [[ $# -ge 2 && -n "$2" ]] || fail '--tag requires an image reference.'
      image_tag="$2"
      shift 2
      ;;
    --publish) publish=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
done

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] ||
  fail 'Build on Linux/amd64 to match the kubectl executable.'
for program in docker file sha256sum python3; do
  command -v "$program" >/dev/null 2>&1 || fail "$program is required."
done
kubectl_binary="${kubectl_binary:-$(command -v kubectl || true)}"
[[ -f "$kubectl_binary" && -x "$kubectl_binary" ]] ||
  fail 'Provide an executable kubectl through --kubectl, KUBECTL_BINARY, or PATH.'
binary_description="$(LC_ALL=C file --brief --dereference -- "$kubectl_binary")"
[[ "$binary_description" == 'ELF 64-bit LSB executable, x86-64,'*'statically linked'* ]] ||
  fail 'kubectl must be a statically linked Linux/amd64 ELF executable.'

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
staging_dir="$(mktemp -d "${TMPDIR:-/tmp}/traffic-e2e-kubectl.XXXXXX")"
trap 'rm -rf -- "$staging_dir"' EXIT
install --mode=0755 "$kubectl_binary" "$staging_dir/kubectl"
kubectl_version="$("$staging_dir/kubectl" version --client --output=json | python3 -c '
import json, sys
version = json.load(sys.stdin)["clientVersion"]
if version["platform"] != "linux/amd64":
    sys.exit("kubectl must report linux/amd64")
print(version["gitVersion"])
')"
[[ "$kubectl_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  fail 'kubectl must report a stable semantic client version.'
image_tag="${image_tag:-registry.api.demo.test/weibo_rd_if/kubectl:${kubectl_version#v}}"
kubectl_sha256="$(sha256sum "$staging_dir/kubectl")"
kubectl_sha256="${kubectl_sha256%% *}"
printf 'kubectl: %s; SHA256: %s\n' "$kubectl_version" "$kubectl_sha256"

if [[ "$publish" == true ]]; then
  if remote_manifest="$(docker manifest inspect "$image_tag" 2>&1)"; then
    fail "Image tag already exists: $image_tag. Reuse its digest or choose a new tag."
  fi
  case "$remote_manifest" in
    *'manifest unknown'*|*'name unknown'*|*'not found'*|*'no such manifest'*) ;;
    *) fail "Cannot verify that the publication tag is unused: $remote_manifest" ;;
  esac
fi

docker buildx build --load --platform linux/amd64 --network none \
  --file "$repo_root/docker/kubectl/Dockerfile" \
  --build-arg "KUBECTL_VERSION=$kubectl_version" \
  --build-arg "KUBECTL_SHA256=$kubectl_sha256" \
  --tag "$image_tag" "$staging_dir"
docker run --rm --network none --read-only --cap-drop=ALL \
  --entrypoint /usr/local/bin/kubectl "$image_tag" version --client --output=json
if [[ "$publish" == true ]]; then
  docker push "$image_tag"
  docker buildx imagetools inspect "$image_tag"
fi
printf 'kubectl image: %s\n' "$image_tag"
