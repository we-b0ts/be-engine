#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: build-engine.sh [--publish] [--skip-build] [--tag <image>]

Build the three release binaries, package them, and optionally push the image.
Run from any directory. Docker receives only the staged executables.

  --publish     Push after a successful image build; requires a clean checkout.
  --skip-build  Package existing release binaries after checking their revision.
  --tag IMAGE   Override the default registry/repository:<version> tag.

Image versions come from docker/engine/VERSION. Increment its 0.0.x patch
version before each new release. Git revision remains embedded in the binaries
and image metadata.

Environment:
  ENGINE_IMAGE_REPOSITORY  Default local image repository: be-engine
  RECORDER_RUNTIME_IMAGE Default: be-engine-recorder-runtime:local.
  ENGINE_BIN_DIR          Existing binary directory (only with --skip-build).
  CARGO_TARGET_DIR        Cargo output directory (default: <repository>/target).

Examples:
  ./scripts/build-engine.sh
  ENGINE_IMAGE_REPOSITORY=ghcr.io/owner/be-engine ./scripts/build-engine.sh --publish
  ./scripts/build-engine.sh --skip-build --tag ghcr.io/owner/be-engine:0.0.1 --publish
EOF
}

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

publish=false
skip_build=false
image_tag=''
while [[ $# -gt 0 ]]; do
  case "$1" in
    --publish) publish=true; shift ;;
    --skip-build) skip_build=true; shift ;;
    --tag)
      [[ $# -ge 2 && -n "$2" ]] || fail '--tag requires an image reference.'
      image_tag="$2"
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) fail "Unknown option: $1" ;;
  esac
done

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] ||
  fail 'Build on Linux/amd64 to match the published runtime and project Source images.'
revision="$(git rev-parse --short=12 HEAD)"
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  [[ "$publish" == false ]] || fail 'Commit changes before publishing an engine image.'
  revision+='-dirty'
fi
if [[ "$publish" == true && -z "$image_tag" && -z "${ENGINE_IMAGE_REPOSITORY:-}" ]]; then
  fail '--publish requires --tag or ENGINE_IMAGE_REPOSITORY.'
fi
repository="${ENGINE_IMAGE_REPOSITORY:-be-engine}"
image_version="$(cat "$repo_root/docker/engine/VERSION")"
[[ "$image_version" =~ ^0\.0\.[1-9][0-9]*$ ]] ||
  fail 'docker/engine/VERSION must contain a version such as 0.0.1.'
if [[ "$revision" == *-dirty ]]; then
  image_version+='-dev'
fi
image_tag="${image_tag:-$repository:$image_version}"
command -v docker >/dev/null 2>&1 || fail 'Docker is required.'

cargo_target_dir="${CARGO_TARGET_DIR:-$repo_root/target}"
if [[ "$skip_build" == false ]]; then
  [[ -z "${ENGINE_BIN_DIR:-}" ]] || fail 'ENGINE_BIN_DIR requires --skip-build.'
  TRAFFIC_E2E_BUILD_REVISION="$revision" \
    cargo build --locked --release --bins --target-dir "$cargo_target_dir"
fi
binary_dir="${ENGINE_BIN_DIR:-$cargo_target_dir/release}"
staging_dir="$(mktemp -d "${TMPDIR:-/tmp}/traffic-e2e-engine.XXXXXX")"
trap 'rm -rf -- "$staging_dir"' EXIT
for binary in traffic-e2e be-replay backend-rewrite-admin; do
  executable="$binary_dir/$binary"
  [[ -x "$executable" ]] || fail "Release executable not found: $executable"
  version="$("$executable" --version)"
  [[ "$version" == *"revision $revision;"* ]] ||
    fail "$binary revision differs from $revision; rebuild before packaging."
  install --mode=0755 "$executable" "$staging_dir/$binary"
done

docker buildx build --load --platform linux/amd64 --network none \
  --file "$repo_root/docker/engine/Dockerfile" \
  --build-arg "RUNTIME_IMAGE=${RECORDER_RUNTIME_IMAGE:-be-engine-recorder-runtime:local}" \
  --build-arg "ENGINE_REVISION=$revision" \
  --build-arg "ENGINE_VERSION=$image_version" \
  --tag "$image_tag" "$staging_dir"
if [[ "$publish" == true ]]; then
  docker push "$image_tag"
fi
printf 'Engine image: %s\n' "$image_tag"
