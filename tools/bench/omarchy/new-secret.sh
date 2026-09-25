#!/usr/bin/env bash
# Write the Omarchy lane's per-cell throwaway secret (tools/bench/README.md).
#
#   tools/bench/omarchy/new-secret.sh OUT
#
# 24 characters of lowercase letters and digits (every one of them typeable
# over QMP), mode 0600, and NO trailing newline: `cryptsetup open
# --key-file` uses a key file byte for byte, so a newline would become part
# of the key and the disk the installer encrypted with the typed passphrase
# would never open. Refuses to overwrite OUT.
set -euo pipefail

OUT="${1:-}"
[ -n "${OUT}" ] || { echo "new-secret: usage: new-secret.sh OUT" >&2; exit 1; }
[ ! -e "${OUT}" ] || { echo "new-secret: ${OUT} already exists" >&2; exit 1; }
umask 077
python3 - "${OUT}" <<'PY'
import os, secrets, string, sys
alphabet = string.ascii_lowercase + string.digits
value = "".join(secrets.choice(alphabet) for _ in range(24))
fd = os.open(sys.argv[1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as handle:
    handle.write(value)
PY
