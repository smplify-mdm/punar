#!/usr/bin/env bash
# Prepare a disposable ARM64 image and host-side TLS provider for Mail runtime
# acceptance. The derived image trusts one ephemeral test CA and maps one
# reserved test hostname to QEMU's host gateway. Neither the account, password,
# message, CA nor hostname enters a production image.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARM64_DIR="${REPO_ROOT}/os/images/arm64"
OUT_DIR="${REPO_ROOT}/os/images/out"

# shellcheck source=/dev/null
. "${ARM64_DIR}/snapshot.env"

SOURCE_IMAGE="${1:-${OUT_DIR}/punar-mail-acceptance-arm64.qcow2}"
OUTPUT_IMAGE="${2:-${OUT_DIR}/punar-mail-live-arm64.qcow2}"
SOURCE_LUKS_KEY="${PUNAR_MAIL_SOURCE_LUKS_KEY:-${OUT_DIR}/punar-mail-acceptance-arm64.luks-key}"
LAB_DIR="${OUTPUT_IMAGE%.qcow2}.lab"
BUILDER_TAG="punar-debian-builder:${PUNAR_DEBIAN_SNAPSHOT}-arm64"
HOST_UID="$(id -u)"
HOST_GID="$(id -g)"
BUILD_COMPLETE=0

die() {
    echo "error: $*" >&2
    exit 1
}

container_path() {
    local path="$1"
    case "${path}" in
        "${REPO_ROOT}"/*) printf '/work/%s\n' "${path#"${REPO_ROOT}"/}" ;;
        *) die "path must stay inside ${REPO_ROOT}: ${path}" ;;
    esac
}

[ "$#" -le 2 ] || die "usage: $0 [SOURCE_QCOW2] [OUTPUT_QCOW2]"
for command in docker openssl shasum; do
    command -v "${command}" >/dev/null 2>&1 || die "${command} is required"
done
[ -f "${SOURCE_IMAGE}" ] || die "source image is missing: ${SOURCE_IMAGE}"
[ -f "${SOURCE_LUKS_KEY}" ] || die "source LUKS key is missing: ${SOURCE_LUKS_KEY}"
[ ! -e "${OUTPUT_IMAGE}" ] || die "output already exists: ${OUTPUT_IMAGE}"
[ ! -e "${LAB_DIR}" ] || die "lab directory already exists: ${LAB_DIR}"

SOURCE_IMAGE="$(cd "$(dirname "${SOURCE_IMAGE}")" && pwd)/$(basename "${SOURCE_IMAGE}")"
SOURCE_LUKS_KEY="$(cd "$(dirname "${SOURCE_LUKS_KEY}")" && pwd)/$(basename "${SOURCE_LUKS_KEY}")"
OUTPUT_IMAGE="$(cd "$(dirname "${OUTPUT_IMAGE}")" && pwd)/$(basename "${OUTPUT_IMAGE}")"
LAB_DIR="${OUTPUT_IMAGE%.qcow2}.lab"
mkdir -p "${LAB_DIR}"
chmod 0700 "${LAB_DIR}"

cleanup_failed_build() {
    if [ "${BUILD_COMPLETE}" -ne 1 ]; then
        rm -f -- "${OUTPUT_IMAGE}.tmp" "${OUTPUT_IMAGE}"
        rm -rf -- "${LAB_DIR}"
    fi
}
trap cleanup_failed_build EXIT INT TERM

umask 077
openssl req -x509 -newkey rsa:3072 -nodes -days 2 -sha256 \
    -subj '/CN=Punar Mail Acceptance CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "${LAB_DIR}/ca.key" -out "${LAB_DIR}/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:3072 -nodes -sha256 \
    -subj '/CN=mail.acceptance.punar.invalid' \
    -addext 'subjectAltName=DNS:mail.acceptance.punar.invalid' \
    -keyout "${LAB_DIR}/server.key" -out "${LAB_DIR}/server.csr" >/dev/null 2>&1
cat > "${LAB_DIR}/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:mail.acceptance.punar.invalid
EOF
openssl x509 -req -days 2 -sha256 \
    -in "${LAB_DIR}/server.csr" \
    -CA "${LAB_DIR}/ca.crt" -CAkey "${LAB_DIR}/ca.key" -CAcreateserial \
    -extfile "${LAB_DIR}/server.ext" -out "${LAB_DIR}/server.crt" >/dev/null 2>&1
openssl verify -CAfile "${LAB_DIR}/ca.crt" \
    -verify_hostname mail.acceptance.punar.invalid "${LAB_DIR}/server.crt" >/dev/null
openssl rand -hex 24 | tr -d '\n' > "${LAB_DIR}/password"
printf '%s\n' 'mail@acceptance.punar.invalid' > "${LAB_DIR}/username"
# QMP keyboard injection is key-position based. Keep the separate disposable
# boot secret alphabetic so automated encrypted-boot acceptance does not
# depend on number-row translation in the firmware/initramfs console.
openssl rand -hex 16 | tr '0123456789abcdef' 'abcdefghijklmnop' \
    | tr -d '\n' > "${LAB_DIR}/unlock-password"
[ "$(wc -c < "${LAB_DIR}/unlock-password" | tr -d ' ')" -eq 32 ] \
    || die "could not generate the disposable boot secret"
chmod 0600 "${LAB_DIR}"/*

SOURCE_CONTAINER="$(container_path "${SOURCE_IMAGE}")"
OUTPUT_CONTAINER="$(container_path "${OUTPUT_IMAGE}")"
CA_CONTAINER="$(container_path "${LAB_DIR}/ca.crt")"
SOURCE_KEY_CONTAINER="$(container_path "${SOURCE_LUKS_KEY}")"
UNLOCK_KEY_CONTAINER="$(container_path "${LAB_DIR}/unlock-password")"

echo "==> Deriving the disposable Mail TLS lab image"
echo "    source: $(basename "${SOURCE_IMAGE}")"
echo "    output: $(basename "${OUTPUT_IMAGE}")"

docker run --rm --interactive --privileged \
    --platform linux/arm64 \
    --volume "${REPO_ROOT}:/work" \
    --workdir /work \
    --env "PUNAR_SOURCE_IMAGE=${SOURCE_CONTAINER}" \
    --env "PUNAR_OUTPUT_IMAGE=${OUTPUT_CONTAINER}" \
    --env "PUNAR_TEST_CA=${CA_CONTAINER}" \
    --env "PUNAR_SOURCE_LUKS_KEY=${SOURCE_KEY_CONTAINER}" \
    --env "PUNAR_LAB_UNLOCK_KEY=${UNLOCK_KEY_CONTAINER}" \
    --env "PUNAR_HOST_UID=${HOST_UID}" \
    --env "PUNAR_HOST_GID=${HOST_GID}" \
    "${BUILDER_TAG}" bash -s <<'CONTAINER'
set -euo pipefail

for command in qemu-img sfdisk jq losetup mount umount awk sha256sum cryptsetup; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "error: builder is missing ${command}" >&2
        exit 1
    }
done

work="$(mktemp -d /var/tmp/punar-mail-live.XXXXXX)"
raw="${work}/disk.raw"
layout="${work}/layout.json"
root_mount="${work}/root"
root_loop=''
data_loop=''
root_mounted=0

cleanup() {
    if [ "${root_mounted}" -eq 1 ]; then
        umount "${root_mount}" 2>/dev/null || true
    fi
    for loop in "${data_loop}" "${root_loop}"; do
        [ -n "${loop}" ] && losetup -d "${loop}" 2>/dev/null || true
    done
    [ -f "${raw}" ] && truncate --size 0 -- "${raw}" || true
    rm -rf -- "${work}"
}
trap cleanup EXIT INT TERM

qemu-img convert -p -O raw "${PUNAR_SOURCE_IMAGE}" "${raw}"
sfdisk --json "${raw}" > "${layout}"
sector="$(jq -er '.partitiontable.sectorsize // 512' "${layout}")"
[ "$(jq -er '.partitiontable.partitions | length' "${layout}")" -eq 4 ] || {
    echo 'error: expected the four-partition Punar A/B layout' >&2
    exit 1
}
start="$(jq -er '.partitiontable.partitions[1].start' "${layout}")"
size="$(jq -er '.partitiontable.partitions[1].size' "${layout}")"
root_loop="$(losetup --find --show \
    --offset "$((start * sector))" \
    --sizelimit "$((size * sector))" "${raw}")"
data_start="$(jq -er '.partitiontable.partitions[3].start' "${layout}")"
data_size="$(jq -er '.partitiontable.partitions[3].size' "${layout}")"
data_loop="$(losetup --find --show \
    --offset "$((data_start * sector))" \
    --sizelimit "$((data_size * sector))" "${raw}")"
cryptsetup isLuks --type luks2 "${data_loop}"
cryptsetup open --test-passphrase --key-file "${PUNAR_SOURCE_LUKS_KEY}" "${data_loop}"
cryptsetup luksAddKey --batch-mode \
    --key-file "${PUNAR_SOURCE_LUKS_KEY}" \
    --new-keyfile "${PUNAR_LAB_UNLOCK_KEY}" "${data_loop}"
cryptsetup open --test-passphrase --key-file "${PUNAR_LAB_UNLOCK_KEY}" "${data_loop}"
mkdir -p "${root_mount}"
mount "${root_loop}" "${root_mount}"
root_mounted=1

bundle="${root_mount}/etc/ssl/certs/ca-certificates.crt"
[ -f "${bundle}" ] || {
    echo 'error: image has no platform CA bundle' >&2
    exit 1
}
mkdir -p "${root_mount}/usr/local/share/ca-certificates"
install -m 0644 "${PUNAR_TEST_CA}" \
    "${root_mount}/usr/local/share/ca-certificates/punar-mail-acceptance.crt"
cat "${PUNAR_TEST_CA}" >> "${bundle}"
printf '\n10.0.2.2 mail.acceptance.punar.invalid\n' >> "${root_mount}/etc/hosts"
# The test-only image unlocks itself so unattended runtime acceptance does not
# depend on QEMU's firmware keyboard translation. This key is never placed in
# a release artifact, and the source image retains its interactive LUKS prompt.
install -m 0400 "${PUNAR_LAB_UNLOCK_KEY}" \
    "${root_mount}/etc/punar-mail-acceptance-unlock.key"
awk '
    $1 == "punar-data" { $3 = "/etc/punar-mail-acceptance-unlock.key" }
    { print }
' "${root_mount}/etc/crypttab" > "${root_mount}/etc/crypttab.punar-mail-lab"
mv "${root_mount}/etc/crypttab.punar-mail-lab" "${root_mount}/etc/crypttab"
chmod 0600 "${root_mount}/etc/crypttab"
grep -qx '10.0.2.2 mail.acceptance.punar.invalid' "${root_mount}/etc/hosts"
awk '$1 == "punar-data" && $3 == "/etc/punar-mail-acceptance-unlock.key" { found = 1 }
    END { exit !found }' "${root_mount}/etc/crypttab"
grep -q 'Punar Mail Acceptance CA' \
    <(openssl x509 -in "${root_mount}/usr/local/share/ca-certificates/punar-mail-acceptance.crt" -noout -subject)
sync
umount "${root_mount}"
root_mounted=0
losetup -d "${root_loop}"
root_loop=''
losetup -d "${data_loop}"
data_loop=''

temporary="${PUNAR_OUTPUT_IMAGE}.tmp"
qemu-img convert -p -O qcow2 -c "${raw}" "${temporary}"
qemu-img check "${temporary}"
mv "${temporary}" "${PUNAR_OUTPUT_IMAGE}"
chown "${PUNAR_HOST_UID}:${PUNAR_HOST_GID}" "${PUNAR_OUTPUT_IMAGE}"
CONTAINER

cat > "${LAB_DIR}/start-provider.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
PUNAR_MAIL_LAB_USERNAME="\$(cat '${LAB_DIR}/username')" \\
PUNAR_MAIL_LAB_PASSWORD="\$(cat '${LAB_DIR}/password')" \\
    exec python3 '${REPO_ROOT}/tests/acceptance/mail-tls-provider.py' \\
        --certificate '${LAB_DIR}/server.crt' \\
        --private-key '${LAB_DIR}/server.key' \\
        --imap-port 1993 --smtp-port 1465
EOF
chmod 0700 "${LAB_DIR}/start-provider.sh"
shasum -a 256 "${OUTPUT_IMAGE}" > "${LAB_DIR}/image.sha256"
chmod 0600 "${LAB_DIR}/image.sha256"
BUILD_COMPLETE=1

echo "==> Mail TLS lab ready"
echo "    start provider: ${LAB_DIR}/start-provider.sh"
echo "    boot persistently with PUNAR_VM_PERSIST=1"
echo "    server host: mail.acceptance.punar.invalid"
echo "    IMAP TLS: 1993; SMTP TLS: 1465"
echo "    username and password stay in mode-0600 files under ${LAB_DIR}"
echo "    the separate disposable VM unlock password is stored there too"
