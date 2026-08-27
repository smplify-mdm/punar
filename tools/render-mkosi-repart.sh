#!/usr/bin/env bash
# Derive the ordinary mkosi image definition set from the canonical installer
# definitions. Layout facts (types, PARTUUIDs, labels, sizes and mounts) stay in
# one committed place; only population differs between install media and the
# directly bootable development image.
set -euo pipefail

if [ "$#" -ne 2 ]; then
    echo "usage: $0 OUTPUT_DIR INSTALL_DEFINITIONS_DIR" >&2
    exit 2
fi

OUTPUT_DIR="$1"
INSTALL_DIR="$2"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

"${REPO_ROOT}/tools/render-repart-definitions.sh" \
    "${OUTPUT_DIR}" "${INSTALL_DIR}"

# mkosi constructs the ESP from the staged /boot and /efi trees.
printf '%s\n' \
    'CopyFiles=/boot:/' \
    'CopyFiles=/efi:/' \
    >> "${OUTPUT_DIR}/10-esp.conf"

# mkosi builds slot A from the staged root tree; an installer instead copies a
# prebuilt release payload block-for-block. Keep mutable trees out of slot A.
sed -i '/^CopyBlocks=/d' "${OUTPUT_DIR}/20-root-a.conf"
printf '%s\n' \
    'Format=ext4' \
    'CopyFiles=/' \
    'ExcludeFiles=/boot/ /efi/ /var/ /home/' \
    'MakeDirectories=/boot /efi /var /home' \
    >> "${OUTPUT_DIR}/20-root-a.conf"

# Seed the shared subvolumes from the same staged tree. Runtime writes then
# remain outside both OS slots and survive slot changes.
printf '%s\n' \
    'CopyFiles=/var:/@var' \
    'CopyFiles=/home:/@home' \
    'Compression=zstd' \
    'CompressionLevel=1' \
    >> "${OUTPUT_DIR}/50-data.conf"
