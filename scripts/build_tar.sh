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
  local raw_path="${DIST_DIR}/${IMAGE_NAME}-${suffix}.raw.tar"

  docker buildx build \
    --platform "${platform}" \
    --tag "${tag}" \
    --provenance=false \
    --output "type=docker,dest=${raw_path}" \
    "${ROOT_DIR}"

  python3 "${ROOT_DIR}/scripts/routeros_archive.py" \
    "${raw_path}" \
    "${tar_path}" \
    --repo-tag "${tag}"

  rm -f "${raw_path}"
  gzip -f "${tar_path}"
  gunzip -k "${tar_path}.gz"
  echo "Wrote ${tar_path}"
  echo "Wrote ${tar_path}.gz"
}

build_one "linux/arm64" "arm64"
build_one "linux/arm/v7" "armv7"
