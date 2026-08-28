#!/usr/bin/env bash
# Online release-maintainer check for every pinned Flatpak catalog source.
# It mutates only a mktemp-owned user Flatpak installation and never the host
# system installation. Schema validation remains the offline CI gate.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG="${REPO_ROOT}/catalog/catalog.json"
REMOTE_FILE="${REPO_ROOT}/catalog/remotes/flathub.flatpakrepo"

for command in flatpak jq; do
    command -v "${command}" >/dev/null 2>&1 \
        || { echo "error: ${command} is required" >&2; exit 2; }
done

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/punar-catalog.XXXXXX")"
cleanup() {
    rm -rf -- "${WORK_DIR}"
}
trap cleanup EXIT INT TERM

export XDG_DATA_HOME="${WORK_DIR}/data"
export XDG_CONFIG_HOME="${WORK_DIR}/config"
export XDG_CACHE_HOME="${WORK_DIR}/cache"

flatpak remote-add --user --if-not-exists --from flathub "${REMOTE_FILE}"

count="$(jq '[.apps[].sources[] | select(.kind == "flatpak")] | length' "${CATALOG}")"
for ((index = 0; index < count; index++)); do
    source_json="$(jq -c "[.apps[].sources[] | select(.kind == \"flatpak\")][${index}]" "${CATALOG}")"
    app_id="$(jq -r '.appId' <<<"${source_json}")"
    ref="$(jq -r '.ref' <<<"${source_json}")"
    arch="$(jq -r '.architectures[0]' <<<"${source_json}")"
    remote="$(jq -r '.remote' <<<"${source_json}")"
    commit="$(jq -r '.commit' <<<"${source_json}")"
    runtime="$(jq -r '.runtime' <<<"${source_json}")"
    expected_metadata="$(jq -r '.metadataSha256' <<<"${source_json}")"
    metadata_file="${WORK_DIR}/metadata-${index}"

    flatpak remote-info --user "--arch=${arch}" "--commit=${commit}" \
        --show-metadata "${remote}" "${ref}" > "${metadata_file}"
    observed_commit="$(flatpak remote-info --user "--arch=${arch}" \
        "--commit=${commit}" --show-commit "${remote}" "${ref}")"
    observed_metadata="$(sha256sum "${metadata_file}" | awk '{print $1}')"

    [ "${observed_commit}" = "${commit}" ] \
        || { echo "error: ${app_id}: commit mismatch" >&2; exit 1; }
    [ "${observed_metadata}" = "${expected_metadata}" ] \
        || { echo "error: ${app_id}: metadata digest mismatch" >&2; exit 1; }
    grep -Fqx "runtime=${runtime}" "${metadata_file}" \
        || { echo "error: ${app_id}: runtime mismatch" >&2; exit 1; }
    echo "ok   ${app_id} ${arch} ${commit}"
done

echo PUNAR_APP_CATALOG_OK
