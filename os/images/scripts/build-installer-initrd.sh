#!/usr/bin/env bash
# Build a deterministic, declarative initrd member that mkosi appends to the
# UKI before ukify links the final PE/COFF image: the installer's live-root
# units (os/images/installer-initrd) and, on every lane and profile, the step
# that frees the unpacked initramfs before switch-root (os/images/initrd-common).
set -euo pipefail

usage() {
    echo "usage: $0 SOURCE_TREE OUTPUT_INITRD" >&2
    exit 2
}

[ "$#" -eq 2 ] || usage
SOURCE_TREE=$1
OUTPUT_INITRD=$2
IMAGES_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
. "${IMAGES_DIR}/snapshot.env"

[ -d "${SOURCE_TREE}" ] \
    || { echo "error: initrd member source tree is missing: ${SOURCE_TREE}" >&2; exit 2; }
command -v cpio >/dev/null \
    || { echo "error: cpio is required to build an initrd member" >&2; exit 2; }

OUTPUT_PARENT="$(dirname "${OUTPUT_INITRD}")"
mkdir -p "${OUTPUT_PARENT}"
WORK="$(mktemp -d "${TMPDIR:-/var/tmp}/punar-installer-initrd.XXXXXX")"
cleanup() { rm -rf "${WORK}"; }
trap cleanup EXIT

mkdir -p "${WORK}/tree"
cp -a "${SOURCE_TREE}/." "${WORK}/tree/"

# An initrd member is an archive, not a device namespace. Refuse special files
# so a repository checkout can never make the privileged builder read from a
# device, socket or pipe while packaging a member.
if find "${WORK}/tree" -xdev \( -type b -o -type c -o -type p -o -type s \) \
        -print -quit | grep -q .; then
    echo "error: initrd member source contains a special file" >&2
    exit 1
fi

# Git records only the executable bit, so normalize every mode rather than
# inherit the checkout's umask. The kernel applies a member's directory modes
# to the directories it unpacks into, "/" included, and every UKI carries at
# least one member.
find "${WORK}/tree" -type d -exec chmod 0755 -- {} +
find "${WORK}/tree" -type f -perm -u+x -exec chmod 0755 -- {} +
find "${WORK}/tree" -type f ! -perm -u+x -exec chmod 0644 -- {} +

# The timestamp is the immutable snapshot epoch used by the x86
# image pipeline. cpio's reproducible mode normalizes device/inode metadata;
# the explicit owner and sorted input remove checkout UID/GID/order variance,
# while clamping mtimes removes checkout-time variance.
find "${WORK}/tree" -exec touch -h --date="@${PUNAR_SOURCE_DATE_EPOCH}" -- {} +
(
    cd "${WORK}/tree"
    find . -print0 | LC_ALL=C sort -z \
        | cpio --null --create --format=newc --reproducible \
            --owner=0:0 --quiet \
        > "${WORK}/punar-live.initrd"
)

[ -s "${WORK}/punar-live.initrd" ] \
    || { echo "error: generated initrd member is empty" >&2; exit 1; }
install -m 0644 "${WORK}/punar-live.initrd" "${OUTPUT_INITRD}"
