#!/usr/bin/env bash
# Build the deterministic, declarative live-root initrd member that mkosi
# appends to the installer UKI before ukify links the final PE/COFF image.
set -euo pipefail

usage() {
    echo "usage: $0 SOURCE_TREE OUTPUT_INITRD" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
SOURCE_TREE=$1
OUTPUT_INITRD=$2

[ -d "${SOURCE_TREE}" ] \
    || { echo "error: installer initrd source tree is missing: ${SOURCE_TREE}" >&2; exit 2; }
command -v cpio >/dev/null \
    || { echo "error: cpio is required to build the installer initrd" >&2; exit 2; }

OUTPUT_PARENT="$(dirname "${OUTPUT_INITRD}")"
mkdir -p "${OUTPUT_PARENT}"
WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/punar-installer-initrd.XXXXXX")"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

mkdir -p "${WORK}/tree"
cp -a "${SOURCE_TREE}/." "${WORK}/tree/"

# An initrd member is an archive, not a device namespace. Refuse special files
# so a repository checkout can never make the privileged builder read from a
# device, socket or pipe while packaging the live root.
if find "${WORK}/tree" -xdev \( -type b -o -type c -o -type p -o -type s \) \
        -print -quit | grep -q .; then
    echo "error: installer initrd source contains a special file" >&2
    exit 1
fi

# The timestamp is the immutable 2026-08-20 snapshot epoch used by the x86
# image pipeline. cpio's reproducible mode normalizes device/inode metadata;
# the explicit owner and sorted input remove checkout UID/GID/order variance,
# while clamping mtimes removes checkout-time variance.
find "${WORK}/tree" -exec touch -h --date='@1787184000' -- {} +
(
    cd "${WORK}/tree"
    find . -print0 | LC_ALL=C sort -z \
        | cpio --null --create --format=newc --reproducible \
            --owner=0:0 --quiet \
        > "${WORK}/punar-live.initrd"
)

[ -s "${WORK}/punar-live.initrd" ] \
    || { echo "error: generated installer initrd is empty" >&2; exit 1; }
install -m 0644 "${WORK}/punar-live.initrd" "${OUTPUT_INITRD}"
