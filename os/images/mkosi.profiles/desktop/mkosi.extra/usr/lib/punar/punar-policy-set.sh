#!/bin/sh
# punar-policy-set — re-authenticate, then set one device policy value.
#
# WHY A SCRIPT AND NOT TWO SPAWNS FROM THE SHELL. The change needs two
# processes chained by a pipe: a password goes into `punar-auth --admin`, and
# the ticket it prints goes into `punarctl policy set`. Quickshell's Process
# writes one stdin, so doing this from QML would mean holding the ticket in a
# QML property between two spawns — a bearer credential parked in the shell's
# object graph, where a later `console.log` or a crash dump would find it. Here
# it is a shell variable in a process that exits either way.
#
# WHAT IS ON THE COMMAND LINE, AND WHAT IS NOT. The capability, the value and
# the reason are arguments: none is a secret, and all three are already visible
# in the audit trail. The PASSWORD arrives on stdin and the TICKET never leaves
# this process except down a pipe, because both are readable from
# /proc/<pid>/cmdline for as long as a process runs.
#
# Usage: punar-policy-set.sh <capability> <value|--clear> <reason>   (password on stdin)
set -u

if [ "$#" -ne 3 ]; then
    printf '%s\n' 'usage: punar-policy-set.sh <capability> <value|--clear> <reason>' >&2
    exit 2
fi
capability="$1"
value="$2"
reason="$3"

password=''
if ! IFS= read -r password; then
    # An empty stdin is a caller that did not ask a person anything.
    printf '%s\n' 'No password arrived, so nothing was changed.' >&2
    exit 2
fi
if [ -z "${password}" ]; then
    printf '%s\n' 'No password was entered, so nothing was changed.' >&2
    exit 2
fi

verdict="$(printf '%s\n' "${password}" | /usr/bin/punar-auth --admin)"
password=''

case "${verdict}" in
    'ok '*)
        ticket="${verdict#ok }"
        ;;
    denied)
        printf '%s\n' 'That password was not accepted, so nothing was changed.' >&2
        exit 3
        ;;
    *)
        # Never rendered as a wrong password: this device could not ask, which
        # is a fault to fix rather than a fact about the secret.
        printf '%s\n' 'This device could not check your password just now, so nothing was changed.' >&2
        exit 4
        ;;
esac

if [ "${value}" = '--clear' ]; then
    printf '%s\n' "${ticket}" \
        | /usr/bin/punarctl policy clear "${capability}" --reason "${reason}" --ticket-stdin
else
    printf '%s\n' "${ticket}" \
        | /usr/bin/punarctl policy set "${capability}" "${value}" --reason "${reason}" --ticket-stdin
fi
