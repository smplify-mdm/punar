#!/usr/bin/env bash
# Resolve Flathub pins for catalog entries, so adding or refreshing an app is a
# command rather than an afternoon.
#
# WHY THIS EXISTS. Every `flatpak` source row in catalog/catalog.json carries a
# commit, a runtime and a metadataSha256 that tools/verify-app-catalog.sh
# re-fetches and compares byte for byte. Those three values were previously
# obtained by hand, which put a real per-app cost on a catalog whose own design
# doc targets ~40 entries and allows 160 (docs/design/app-catalog.md section
# 8.1). A catalog that is expensive to extend stays small for the wrong reason.
#
# WHY A CONTAINER. `flatpak` does not exist on a macOS developer machine, and
# the pins must come from Flathub itself rather than from anything cached
# locally. The container is plain debian:trixie-slim with flatpak installed; it
# mounts the repo read-only and writes only a TSV to a scratch directory.
#
# THE ONE SUBTLE THING, and it is a real trap: verify-app-catalog.sh computes
# the digest over the raw stdout of `flatpak remote-info --show-metadata`
# REDIRECTED TO A FILE. A `$(...)` capture strips trailing newlines, so hashing
# a captured string yields a digest the verifier can never reproduce. This
# script therefore redirects to a file and hashes the file, exactly as the
# verifier does.
#
# USAGE
#   tools/pin-catalog-app.sh resolve <flathub-app-id> [<flathub-app-id>...]
#       Print ready-to-paste JSON source rows for the given apps, one object per
#       architecture, skipping architectures Flathub does not build.
#
#   tools/pin-catalog-app.sh refresh
#       Re-resolve every existing flatpak source in catalog/catalog.json to the
#       CURRENT Flathub commit and rewrite the file in place. Prints what moved.
#       Run tools/verify-app-catalog.sh afterwards; it is the authority.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG="${REPO_ROOT}/catalog/catalog.json"
IMAGE="debian:trixie-slim"

command -v docker >/dev/null 2>&1 || { echo "error: docker is required" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "error: python3 is required" >&2; exit 2; }

mode="${1:-}"
shift || true

case "${mode}" in
    resolve)
        [ "$#" -gt 0 ] || { echo "usage: $0 resolve <app-id>..." >&2; exit 2; }
        APP_IDS="$*"
        ;;
    refresh)
        APP_IDS="$(python3 -c '
import json, sys
doc = json.load(open(sys.argv[1]))
ids = sorted({s["appId"] for a in doc["apps"] for s in a["sources"] if s["kind"] == "flatpak"})
print(" ".join(ids))
' "${CATALOG}")"
        [ -n "${APP_IDS}" ] || { echo "error: no flatpak sources in ${CATALOG}" >&2; exit 1; }
        ;;
    *)
        sed -n '/^# USAGE/,/^set -euo/p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//; $d'
        exit 2
        ;;
esac

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/punar-pin.XXXXXX")"
cleanup() { rm -rf -- "${WORK_DIR}"; }
trap cleanup EXIT INT TERM

echo "==> resolving Flathub pins for $(echo "${APP_IDS}" | wc -w | tr -d ' ') app id(s)"

docker run --rm \
    -v "${REPO_ROOT}:/repo:ro" -v "${WORK_DIR}:/out" \
    -e APP_IDS="${APP_IDS}" \
    "${IMAGE}" bash -c '
        set -uo pipefail
        apt-get update -qq >/dev/null 2>&1
        apt-get install -y -qq flatpak ca-certificates >/dev/null 2>&1
        export XDG_DATA_HOME=/out/fp XDG_CONFIG_HOME=/out/fpc XDG_CACHE_HOME=/out/fpk
        flatpak remote-add --user --if-not-exists --from flathub \
            /repo/catalog/remotes/flathub.flatpakrepo >/dev/null 2>&1
        for app in ${APP_IDS}; do
            for arch in x86_64 aarch64; do
                ref="app/${app}/${arch}/stable"
                commit=$(flatpak remote-info --user "--arch=${arch}" --show-commit \
                    flathub "${ref}" 2>/dev/null | tr -d "[:space:]")
                [ -n "${commit}" ] || { printf "%s\t%s\tUNAVAILABLE\t\t\n" "${app}" "${arch}"; continue; }
                # Redirected to a FILE on purpose - see the header.
                mf="/out/meta.${app}.${arch}"
                flatpak remote-info --user "--arch=${arch}" "--commit=${commit}" \
                    --show-metadata flathub "${ref}" > "${mf}" 2>/dev/null
                [ -s "${mf}" ] || { printf "%s\t%s\tMETAFAIL\t\t\n" "${app}" "${arch}"; continue; }
                printf "%s\t%s\t%s\t%s\t%s\n" "${app}" "${arch}" "${commit}" \
                    "$(grep -m1 "^runtime=" "${mf}" | cut -d= -f2-)" \
                    "$(sha256sum "${mf}" | awk "{print \$1}")"
            done
        done
    ' > "${WORK_DIR}/pins.tsv"

python3 "${REPO_ROOT}/tools/pin_catalog_app.py" "${mode}" "${CATALOG}" "${WORK_DIR}/pins.tsv"

if [ "${mode}" = "refresh" ]; then
    echo "==> now run: tools/verify-app-catalog.sh   (it is the authority, not this script)"
fi
