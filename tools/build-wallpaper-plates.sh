#!/usr/bin/env bash
# Regenerate the topographic wallpaper plates from USGS 3DEP elevation data.
#
# This is a developer tool, not part of any image build: the plates it writes
# are committed, and the image build only copies shell/ into the tree. Running
# it needs network access to the USGS public S3 bucket; a normal image build
# does not, and must not.
#
# The GDAL toolchain is pinned by digest for the same reason every other Punar
# toolchain is (rust, shellcheck, qmllint): a plate is a build output, and a
# build output that depends on "whatever :latest resolved to today" is not
# reproducible.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON_IMAGE="python:3.12-slim"
GDAL_IMAGE="ghcr.io/osgeo/gdal@sha256:871c211b12f559514c6643f6ab339823551663f598f69a042bfe2628a6acab86"
MANIFEST="${REPO_ROOT}/tools/wallpaper-plates.json"
OUT_DIR="${REPO_ROOT}/shell/punar-shell/Wallpaper/plates"
WORK_DIR="${PUNAR_PLATE_WORK:-${REPO_ROOT}/os/images/cache/wallpaper-plates}"
FONT_FILE="os/modules/desktop/fonts/geist-mono/GeistMono-Medium.ttf"

die() {
    echo "error: $*" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || die "docker is required"
[ -f "${MANIFEST}" ] || die "manifest is missing: ${MANIFEST}"
[ -f "${REPO_ROOT}/${FONT_FILE}" ] || die "vendored font is missing: ${FONT_FILE}"

mkdir -p "${WORK_DIR}"

echo "==> Generating wallpaper plates from ${MANIFEST}"
echo "    elevation source: USGS 3DEP 1/3 arc-second (public domain, 17 U.S.C. 105)"
echo "    hydrography: USGS National Hydrography Dataset (public domain)"
echo "    cropped windows cached in ${WORK_DIR}"

# Two pinned toolchains: fontTools lives only in the python image (the same one
# tools/validate-schemas.sh uses), so the plate generator stays pure-stdlib and
# needs no font library. The glyph dump is an intermediate in the work dir, not
# a committed asset — there is no second place for the type to drift to.
GLYPHS="${WORK_DIR}/geist-mono-glyphs.json"
echo "==> Extracting type outlines from ${FONT_FILE##*/}"
docker run --rm \
    --user "$(id -u):$(id -g)" \
    --volume "${REPO_ROOT}:/work" \
    --workdir /work \
    --env HOME=/tmp \
    "${PYTHON_IMAGE}" \
    sh -c 'pip install --quiet --disable-pip-version-check --target /tmp/pylibs fonttools \
           && PYTHONPATH=/tmp/pylibs python3 "$@"' _ \
        /work/tools/wallpaper_glyphs.py \
        "/work/${FONT_FILE}" \
        "/work/${GLYPHS#"${REPO_ROOT}/"}"

echo "==> Generating plates"
docker run --rm \
    --user "$(id -u):$(id -g)" \
    --volume "${REPO_ROOT}:/work" \
    --workdir /work \
    --env HOME=/tmp \
    "${GDAL_IMAGE}" \
    python3 /work/tools/wallpaper_plate.py \
        /work/tools/wallpaper-plates.json \
        "/work/${OUT_DIR#"${REPO_ROOT}/"}" \
        "/work/${WORK_DIR#"${REPO_ROOT}/"}" \
        "/work/${GLYPHS#"${REPO_ROOT}/"}" \
        "$@"

echo "==> Plates written to ${OUT_DIR#"${REPO_ROOT}/"}"
