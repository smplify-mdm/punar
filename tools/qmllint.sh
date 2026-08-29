#!/usr/bin/env bash
# Lint every QML file in the shell against the SAME Qt and Quickshell the
# image ships.
#
# WHY A CONTAINER. qmllint resolves imports against installed modules, so a
# lint that cannot see Quickshell.Hyprland, Quickshell.Io or Quickshell.Wayland
# reports every one of them as an unknown import and its verdict is worthless.
# The versions have to match the image or the lint is checking a different
# program than the one that ships: Qt 6.11.2, quickshell 0.3.0, from the same
# Arch Linux Archive snapshot pinned in os/images/snapshot.env.
#
# WHY THIS EXISTS AT ALL. The shell grew to 40-odd QML files with no automated
# lint anywhere in CI — it had only ever been run by hand. A QML typo does not
# fail the build: mkosi copies the files in verbatim and the failure appears at
# runtime as a surface that refuses to open. surfaces-check.sh catches that in
# the VM, ~40 minutes into a run; this catches it in about a minute.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
source "${REPO_ROOT}/os/images/snapshot.env"

SNAP="${PUNAR_SNAPSHOT_DATE}"
IMAGE_TAG="punar-qmllint:${SNAP//\//-}"

if ! docker image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
    echo "==> building the qmllint container (${IMAGE_TAG})"
    # --platform is explicit: the pinned snapshot is x86_64 only, and on an
    # arm64 developer machine an unqualified build silently fails to resolve.
    docker build --platform linux/amd64 -t "${IMAGE_TAG}" -f - "${REPO_ROOT}" <<CONTAINERFILE
FROM ${PUNAR_BUILDER_BASE}
RUN printf 'Server=https://archive.archlinux.org/repos/${SNAP}/\$repo/os/\$arch\n' \
      > /etc/pacman.d/mirrorlist \\
 && sed -i 's/^SigLevel.*/SigLevel = Never/' /etc/pacman.conf \\
 && echo 'DisableSandbox' >> /etc/pacman.conf \\
 && echo 'DisableDownloadTimeout' >> /etc/pacman.conf \\
 && pacman -Sy --noconfirm --needed qt6-declarative qt6-svg quickshell \\
 && pacman -Scc --noconfirm
CONTAINERFILE
fi

echo "==> qmllint (Qt/Quickshell from snapshot ${SNAP})"
docker run --rm --platform linux/amd64 \
    -v "${REPO_ROOT}:/w:ro" -w /w "${IMAGE_TAG}" \
    bash -c '
set -euo pipefail
mapfile -t files < <(find shell -name "*.qml" | sort)
echo "    ${#files[@]} files"
# Quickshell installs its QML modules under its own prefix; qmllint needs to
# be pointed at it or every Quickshell.* import resolves to nothing and the
# run is a false pass.
# qmllint is not on PATH on Arch: qt6-declarative installs it under the Qt
# libexec/bin prefix. Resolve it rather than assuming, so a Qt layout change
# fails loudly instead of silently skipping the lint.
QMLLINT=$(command -v qmllint || find /usr/lib/qt6 /usr/bin -name qmllint -type f 2>/dev/null | head -1)
if [ -z "${QMLLINT}" ]; then
    echo "qmllint not found in the container — the lint did NOT run" >&2
    exit 1
fi
echo "    using ${QMLLINT}"
# qmllint EXITS 0 WHEN IT HAS WARNINGS. Verified against this exact build by
# injecting `Hyprland.thisPropertyDoesNotExist`: qmllint printed
# `Warning: ... [missing-property]` and still returned 0. Trusting its exit
# code is therefore a vacuous gate — it would report "clean" while naming the
# defect on the line above. The standard this repo holds the shell to is ZERO
# warnings, so any output at all is the failure.
# The greeter is a separate Quickshell configuration root and imports the
# shared Theme singleton by module name. Point qmllint at the product module
# root as well as the Quickshell system modules so that independent root is
# checked under the same resolution rules it uses in the image.
out=$("${QMLLINT}" --qmldirs /usr/lib/qt6/qml \
    --qmldirs shell/punar-shell "${files[@]}" 2>&1) || true
if [ -n "${out}" ]; then
    printf "%s\n" "${out}"
    echo "qmllint reported the above; the shell standard is zero warnings" >&2
    exit 1
fi
'
echo "==> qmllint clean"
