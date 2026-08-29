#!/bin/sh
# Launch a freedesktop Terminal=true application through Punar's warm Foot
# server, with a standalone Foot fallback. The command remains argv throughout:
# no shell fragment is generated from desktop-entry data.
set -eu

working_directory=
if [ "${1:-}" = "--working-directory" ]; then
    [ "$#" -ge 3 ] || exit 64
    working_directory=$2
    shift 2
fi
[ "${1:-}" = "--" ] || exit 64
shift
[ "$#" -gt 0 ] || exit 64

if [ -n "${working_directory}" ]; then
    cd -- "${working_directory}" || exit 66
fi

if footclient --no-wait -- "$@"; then
    exit 0
fi
exec foot -- "$@"
