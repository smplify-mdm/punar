#!/bin/sh
# Add proof services only to the volatile live overlay. The signed release
# tree and the slot payload stay byte-identical; installed systems never carry
# these services. On physical media they are skipped because the named virtio
# ports exist only when the QEMU gates deliberately attach them.
set -eu

copy_text() {
    source=$1
    destination=$2
    : > "${destination}"
    while IFS= read -r line || [ -n "${line}" ]; do
        printf '%s\n' "${line}"
    done < "${source}" > "${destination}"
}

# The minimal hardware initrd is guaranteed to carry mkdir and /bin/sh, but it
# does not promise the full coreutils cp/ln pair. Keep this staging path within
# those guaranteed primitives and enable the path watcher with a target drop-in
# rather than a symlink.
/usr/bin/mkdir -p \
    /sysroot/etc \
    /sysroot/usr/lib/punar \
    /sysroot/usr/lib/systemd/system \
    /sysroot/usr/lib/systemd/system/multi-user.target.d
copy_text \
    /usr/lib/punar-live/rootfs/etc/fstab \
    /sysroot/etc/fstab
copy_text \
    /usr/lib/punar-live/rootfs/etc/crypttab \
    /sysroot/etc/crypttab
copy_text \
    /usr/lib/punar-live/rootfs/usr/lib/punar/installer-runtime-proof.sh \
    /sysroot/usr/lib/punar/installer-runtime-proof.sh
copy_text \
    /usr/lib/punar-live/rootfs/usr/lib/systemd/system/punar-installer-runtime-proof.service \
    /sysroot/usr/lib/systemd/system/punar-installer-runtime-proof.service
copy_text \
    /usr/lib/punar-live/rootfs/usr/lib/systemd/system/punar-installer-runtime-proof.path \
    /sysroot/usr/lib/systemd/system/punar-installer-runtime-proof.path
copy_text \
    /usr/lib/punar-live/rootfs/usr/lib/systemd/system/punar-installer-apply-proof.service \
    /sysroot/usr/lib/systemd/system/punar-installer-apply-proof.service
copy_text \
    /usr/lib/punar-live/rootfs/usr/lib/systemd/system/punar-installer-apply-proof.path \
    /sysroot/usr/lib/systemd/system/punar-installer-apply-proof.path
copy_text \
    /usr/lib/punar-live/rootfs/usr/lib/systemd/system/multi-user.target.d/90-punar-installer-runtime-proof.conf \
    /sysroot/usr/lib/systemd/system/multi-user.target.d/90-punar-installer-runtime-proof.conf

printf 'PUNAR_INSTALL_RUNTIME_STAGE_OK\n'
