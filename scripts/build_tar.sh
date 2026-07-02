#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${ROOT_DIR}/dist"
IMAGE_NAME="${IMAGE_NAME:-mikrotik-wg-easy}"

mkdir -p "${DIST_DIR}"

build_one() {
  local platform="$1"
  local suffix="$2"
  local tag="${IMAGE_NAME}:${suffix}"
  local tar_path="${DIST_DIR}/${IMAGE_NAME}-${suffix}.tar"

  docker buildx build \
    --platform "${platform}" \
    --tag "${tag}" \
    --load \
    "${ROOT_DIR}"

  docker save "${tag}" --output "${tar_path}"
  gzip -f "${tar_path}"
  echo "Wrote ${tar_path}.gz"
}

build_one "linux/arm64" "arm64"
build_one "linux/arm/v7" "armv7"

