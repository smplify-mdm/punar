#!/usr/bin/env bash
# Download and verify the pinned Omarchy ISO. OWNER-GATED: never runs
# unless BENCH_OMARCHY_APPROVED=yes (tools/bench/README.md, "Omarchy lane").
#
#   BENCH_OMARCHY_APPROVED=yes tools/bench/omarchy/fetch-iso.sh DEST.iso
#
# The URL and SHA-256 come only from omarchy.env in this directory, never
# from arguments or the environment. The file is written to DEST.part and
# renamed only after its SHA-256 matches; a mismatch deletes it and fails.
# An existing DEST is re-verified instead of downloaded again.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${1:-}"

die() {
    echo "fetch-iso: $*" >&2
    exit 1
}

[ "${BENCH_OMARCHY_APPROVED:-}" = yes ] \
    || die "the Omarchy lane needs the owner's approval first (tools/bench/README.md); nothing downloaded"
[ -n "${DEST}" ] || die "usage: fetch-iso.sh DEST.iso"
url="$(awk -F= '$1 == "OMARCHY_ISO_URL" {print $2}' "${HERE}/omarchy.env")"
want="$(awk -F= '$1 == "OMARCHY_ISO_SHA256" {print $2}' "${HERE}/omarchy.env")"
case "${url}" in https://iso.omarchy.org/*.iso) ;; *) die "pinned URL is not an iso.omarchy.org ISO" ;; esac
case "${want}" in *[!0-9a-f]*|'') die "pinned SHA-256 is malformed" ;; esac
[ "${#want}" -eq 64 ] || die "pinned SHA-256 is malformed"

verify() {
    got="$(sha256sum "$1" | awk '{print $1}')"
    [ "${got}" = "${want}" ]
}

if [ -f "${DEST}" ]; then
    verify "${DEST}" || die "${DEST} exists but does not match the pinned SHA-256; delete it"
    echo "fetch-iso: ${DEST} verified (cached)"
    exit 0
fi
curl --fail --location --proto '=https' --tlsv1.2 --retry 3 --output "${DEST}.part" "${url}"
if ! verify "${DEST}.part"; then
    rm -f "${DEST}.part"
    die "downloaded ISO does not match the pinned SHA-256; deleted"
fi
mv "${DEST}.part" "${DEST}"
echo "fetch-iso: ${DEST} verified (${want})"
