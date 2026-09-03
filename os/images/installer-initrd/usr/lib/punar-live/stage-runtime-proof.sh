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
    /sysroot/etc/systemd/system/punar-installer-unattended.service.d \
    /sysroot/usr/lib/punar \
    /sysroot/usr/share/punar/install-answer-keys \
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
    /usr/lib/punar-live/rootfs/usr/lib/systemd/system/punar-installer-refusal-proof.service \
    /sysroot/usr/lib/systemd/system/punar-installer-refusal-proof.service
copy_text \
    /usr/lib/punar-live/rootfs/usr/lib/systemd/system/punar-installer-refusal-proof.path \
    /sysroot/usr/lib/systemd/system/punar-installer-refusal-proof.path
copy_text \
    /usr/lib/punar-live/rootfs/usr/lib/systemd/system/multi-user.target.d/90-punar-installer-runtime-proof.conf \
    /sysroot/usr/lib/systemd/system/multi-user.target.d/90-punar-installer-runtime-proof.conf

# The CI signing key is per-run and enters only the volatile live overlay.
# It is admitted solely when the dedicated QEMU proof port is present; the
# product consumer, schema, signature verification and custody path are the
# same code shipped on physical media. Production releases provision their
# independently controlled key under /usr/share/punar/install-answer-keys.
ci_port=/dev/virtio-ports/punar.install-unattended-proof
ci_key=/sys/firmware/qemu_fw_cfg/by_name/opt/punar/install-answer-key/raw
if [ -c "${ci_port}" ] && [ -r "${ci_key}" ]; then
    copy_text \
        "${ci_key}" \
        /sysroot/usr/share/punar/install-answer-keys/ci.pub
    copy_text \
        /usr/lib/punar-live/rootfs/etc/systemd/system/punar-installer-unattended.service.d/90-ci-proof.conf \
        /sysroot/etc/systemd/system/punar-installer-unattended.service.d/90-ci-proof.conf
fi

printf 'PUNAR_INSTALL_RUNTIME_STAGE_OK\n'
