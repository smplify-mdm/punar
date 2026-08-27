#!/usr/bin/env bash
# Render a systemd-repart definition set with explicit later-directory-wins
# semantics. systemd 261.2 gives the FIRST repeated --definitions= directory
# priority; Punar's encrypted installer overlay is intentionally conventional
# later-wins, so it is merged into a fresh /run directory before repart runs.
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 OUTPUT_DIR BASE_DIR [OVERLAY_DIR ...]" >&2
    exit 2
fi

OUTPUT_DIR="$1"
shift

case "${OUTPUT_DIR}" in
    /run/*) ;;
    *) echo "error: output must be a fresh directory below /run" >&2; exit 2 ;;
esac

if [ ! -d "${OUTPUT_DIR}" ]; then
    echo "error: output directory does not exist: ${OUTPUT_DIR}" >&2
    exit 2
fi
if find "${OUTPUT_DIR}" -mindepth 1 -print -quit | grep -q .; then
    echo "error: output directory is not empty: ${OUTPUT_DIR}" >&2
    exit 2
fi

for source_dir in "$@"; do
    if [ ! -d "${source_dir}" ]; then
        echo "error: definition directory does not exist: ${source_dir}" >&2
        exit 2
    fi

    while IFS= read -r -d '' definition; do
        install -m 0644 "${definition}" "${OUTPUT_DIR}/${definition##*/}"
    done < <(find "${source_dir}" -maxdepth 1 -type f -name '*.conf' -print0)
done

if ! find "${OUTPUT_DIR}" -maxdepth 1 -type f -name '*.conf' -print -quit | grep -q .; then
    echo "error: rendered definition set is empty" >&2
    exit 2
fi
