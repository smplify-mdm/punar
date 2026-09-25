#!/usr/bin/env bash
# Return an installed Omarchy disk to stock before it is measured.
#
# Called by tools/bench/inject-probe.sh --then, with the btrfs top level
# mounted at BENCH_MOUNT and the OS subvolume at BENCH_OSROOT (@). Undoes
# exactly what the harness's install phase added, and records the one
# deviation it keeps:
#
#   - sshd: disabled (the install enabled it only because authorized_keys
#     was on the CIDATA drive);
#   - ufw: the rule allowing port 22 removed from user.rules and user6.rules;
#   - the harness's authorized_keys deleted;
#   - DEVIATION, kept: one sudoers rule letting the person run exactly
#     `docker build -t bench-fixture /opt/bench/fixture`, because stock 4.0.4
#     gives them no docker group and the workload's container step needs it
#     (tools/bench/README.md). Recorded; the disk is discarded afterwards.
#
# Writes BENCH_RECORD (default ./restore-stock.txt): every file changed,
# with before/after digests and the removed rule lines.
set -euo pipefail

MNT="${BENCH_MOUNT:?}"
OS="${BENCH_OSROOT:?}"
USER_NAME="${BENCH_OMARCHY_USER:-bench}"
RECORD="${BENCH_RECORD:-restore-stock.txt}"
HOME_DIR="${MNT}/@home/${USER_NAME}"
[ -d "${HOME_DIR}" ] || HOME_DIR="${OS}/home/${USER_NAME}"

log() {
    printf '%s\n' "$*" >> "${RECORD}"
}

: > "${RECORD}"
log "# restore-stock: $(date -u +%Y-%m-%dT%H:%M:%SZ)"

for unit in sshd.service sshd.socket; do
    for link in "${OS}"/etc/systemd/system/*.wants/"${unit}"; do
        [ -L "${link}" ] || continue
        log "removed link ${link#"${OS}"} -> $(readlink "${link}")"
        rm -f "${link}"
    done
done

for rules in "${OS}/etc/ufw/user.rules" "${OS}/etc/ufw/user6.rules"; do
    [ -f "${rules}" ] || continue
    before="$(sha256sum "${rules}" | awk '{print $1}')"
    # A ufw user rule is a "### tuple ###" comment followed by its -A lines;
    # drop the block whose tuple allows port 22.
    awk '
        /^### tuple ###/ { skipping = ($0 ~ / 22 /); if (skipping) { print "REMOVED " $0 > "/dev/stderr"; next } }
        skipping && /^-A / { print "REMOVED " $0 > "/dev/stderr"; next }
        { skipping = 0; print }
    ' "${rules}" > "${rules}.bench" 2>> "${RECORD}"
    mv "${rules}.bench" "${rules}"
    log "edited ${rules#"${OS}"}: ${before} -> $(sha256sum "${rules}" | awk '{print $1}')"
done

if [ -f "${HOME_DIR}/.ssh/authorized_keys" ]; then
    log "removed ${HOME_DIR#"${MNT}"}/.ssh/authorized_keys"
    rm -f "${HOME_DIR}/.ssh/authorized_keys"
fi

install -d -m 0755 "${OS}/opt/bench/fixture"
printf '%s ALL=(root) NOPASSWD: /usr/bin/docker build -t bench-fixture /opt/bench/fixture\n' "${USER_NAME}" \
    > "${OS}/etc/sudoers.d/90-bench-docker-build"
chmod 0440 "${OS}/etc/sudoers.d/90-bench-docker-build"
log "DEVIATION added /etc/sudoers.d/90-bench-docker-build: ${USER_NAME} may run exactly 'docker build -t bench-fixture /opt/bench/fixture'"
log "added /opt/bench/fixture (empty; the workload fills it)"
echo "restore-stock: $(grep -c . "${RECORD}") lines recorded in ${RECORD}"
