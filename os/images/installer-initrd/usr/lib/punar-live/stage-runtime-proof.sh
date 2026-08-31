#!/bin/sh
# Add a proof service only to the volatile live overlay. The signed release
# tree and the slot payload stay byte-identical; installed systems never carry
# this service. On physical media it is skipped because the named virtio port
# exists only when the QEMU gate deliberately attaches it.
set -eu

/usr/bin/cp -a /usr/lib/punar-live/rootfs/. /sysroot/
/usr/bin/mkdir -p /sysroot/usr/lib/systemd/system/multi-user.target.wants
/usr/bin/ln -sfn ../punar-installer-runtime-proof.service \
    /sysroot/usr/lib/systemd/system/multi-user.target.wants/punar-installer-runtime-proof.service

