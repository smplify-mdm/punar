#!/usr/bin/env bash
# Prepare a disposable ARM64 image and a host-side TLS edge so a Punar VM on
# this Mac enrolls into the LOCAL Smplify (Tilt's port-forward on
# 127.0.0.1:9003) over verified TLS, through the built-in punar-smplifyd.
#
# What the derived image gets, and nothing else:
#   - one ephemeral lab CA in the platform trust store;
#   - an /etc/hosts alias mapping the lab domain to QEMU's host gateway;
#   - a pinned organisation document under /etc/punar/smplify/, the
#     root-owned override org.discover consults before the well-known URL;
#   - on a dev/CI image only: a drop-in that points punard back at the
#     built-in agent instead of the mock.
# The CA, keys and document never enter a production image; the lab edge
# (tools/smplify-lab-edge.py, standard library only) terminates TLS on the
# Mac's loopback in front of the plain-HTTP port-forward — the guest reaches
# the host's loopback as 10.0.2.2, so nothing is exposed on another
# interface.
#
# Honest limits: the local edge does not request the device certificate, so
# the device presents none — server-side device identity (backend B1/B2 in
# docs/development/smplify-enrollment.md) is what makes that real.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARM64_DIR="${REPO_ROOT}/os/images/arm64"
OUT_DIR="${REPO_ROOT}/os/images/out"
# shellcheck source=/dev/null
. "${ARM64_DIR}/snapshot.env"

SOURCE_IMAGE="${1:-${OUT_DIR}/punar-release-arm64.qcow2}"
OUTPUT_IMAGE="${2:-${OUT_DIR}/punar-smplify-lab-arm64.qcow2}"
LAB_DOMAIN="${PUNAR_SMPLIFY_LAB_DOMAIN:-smplify.lab}"
LAB_PORT="${PUNAR_SMPLIFY_LAB_PORT:-8443}"
LAB_BACKEND="${PUNAR_SMPLIFY_LAB_BACKEND:-127.0.0.1:9003}"
LAB_ORG_ID="${PUNAR_SMPLIFY_LAB_ORG_ID:-smplify-lab}"
LAB_ORG_NAME="${PUNAR_SMPLIFY_LAB_ORG_NAME:-Smplify Lab}"
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
case "${LAB_DOMAIN}" in
    *[!a-z0-9.-]*|''|.*|*.|*..*) die "lab domain must be lowercase letters, digits, dots and hyphens: ${LAB_DOMAIN}" ;;
esac
[ -f "${SOURCE_IMAGE}" ] || die "source image is missing: ${SOURCE_IMAGE}"
[ ! -e "${OUTPUT_IMAGE}" ] || die "output already exists: ${OUTPUT_IMAGE}"
[ ! -e "${LAB_DIR}" ] || die "lab directory already exists: ${LAB_DIR}"
docker image inspect "${BUILDER_TAG}" >/dev/null 2>&1 \
    || die "builder image ${BUILDER_TAG} is missing; build the ARM64 image once (tools/build-arm64-image.sh)"

SOURCE_IMAGE="$(cd "$(dirname "${SOURCE_IMAGE}")" && pwd)/$(basename "${SOURCE_IMAGE}")"
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
# --- one lab CA and one server certificate for the lab domain ---------------
openssl req -x509 -newkey rsa:3072 -nodes -days 2 -sha256 \
    -subj '/CN=Punar Smplify Lab CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' \
    -keyout "${LAB_DIR}/ca.key" -out "${LAB_DIR}/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:3072 -nodes -sha256 \
    -subj "/CN=${LAB_DOMAIN}" \
    -addext "subjectAltName=DNS:${LAB_DOMAIN}" \
    -keyout "${LAB_DIR}/server.key" -out "${LAB_DIR}/server.csr" >/dev/null 2>&1
cat > "${LAB_DIR}/server.ext" <<EOT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${LAB_DOMAIN}
EOT
openssl x509 -req -days 2 -sha256 \
    -in "${LAB_DIR}/server.csr" \
    -CA "${LAB_DIR}/ca.crt" -CAkey "${LAB_DIR}/ca.key" -CAcreateserial \
    -extfile "${LAB_DIR}/server.ext" -out "${LAB_DIR}/server.crt" >/dev/null 2>&1
openssl verify -CAfile "${LAB_DIR}/ca.crt" \
    -verify_hostname "${LAB_DOMAIN}" "${LAB_DIR}/server.crt" >/dev/null

# --- the organisation document the image pins for the lab domain -----------
cat > "${LAB_DIR}/organization.json" <<EOT
{
  "id": "${LAB_ORG_ID}",
  "name": "${LAB_ORG_NAME}",
  "discovery": {
    "domain": "${LAB_DOMAIN}",
    "control_plane": "smplify",
    "endpoint": "https://${LAB_DOMAIN}:${LAB_PORT}"
  },
  "enrollment": {
    "display_name": "${LAB_ORG_NAME}",
    "server": "https://${LAB_DOMAIN}:${LAB_PORT}",
    "methods": ["code"],
    "remote_query_scopes": []
  }
}
EOT

# --- the host-side edge: TLS on loopback in front of the Tilt port-forward --
cat > "${LAB_DIR}/start-edge.sh" <<EOT
#!/usr/bin/env bash
# The lab edge: terminates TLS for ${LAB_DOMAIN}:${LAB_PORT} on 127.0.0.1 and
# forwards to ${LAB_BACKEND} (the local Smplify). Ctrl-C stops it.
set -euo pipefail
exec python3 '${REPO_ROOT}/tools/smplify-lab-edge.py' \\
    --certificate '${LAB_DIR}/server.crt' \\
    --private-key '${LAB_DIR}/server.key' \\
    --listen '127.0.0.1:${LAB_PORT}' \\
    --backend '${LAB_BACKEND}'
EOT
chmod 0700 "${LAB_DIR}/start-edge.sh"
chmod 0600 "${LAB_DIR}"/ca.* "${LAB_DIR}"/server.* "${LAB_DIR}/organization.json"

SOURCE_CONTAINER="$(container_path "${SOURCE_IMAGE}")"
OUTPUT_CONTAINER="$(container_path "${OUTPUT_IMAGE}")"
CA_CONTAINER="$(container_path "${LAB_DIR}/ca.crt")"
ORG_CONTAINER="$(container_path "${LAB_DIR}/organization.json")"

echo "==> Deriving the disposable Smplify lab image"
echo "    source: $(basename "${SOURCE_IMAGE}")"
echo "    output: $(basename "${OUTPUT_IMAGE}")"
docker run --rm --interactive --privileged \
    --platform linux/arm64 \
    --volume "${REPO_ROOT}:/work" \
    --workdir /work \
    --env "PUNAR_SOURCE_IMAGE=${SOURCE_CONTAINER}" \
    --env "PUNAR_OUTPUT_IMAGE=${OUTPUT_CONTAINER}" \
    --env "PUNAR_LAB_CA=${CA_CONTAINER}" \
    --env "PUNAR_LAB_ORG=${ORG_CONTAINER}" \
    --env "PUNAR_LAB_DOMAIN=${LAB_DOMAIN}" \
    --env "PUNAR_HOST_UID=${HOST_UID}" \
    --env "PUNAR_HOST_GID=${HOST_GID}" \
    "${BUILDER_TAG}" bash -s <<'CONTAINER'
set -euo pipefail
for command in qemu-img sfdisk jq losetup mount umount; do
    command -v "${command}" >/dev/null 2>&1 || {
        echo "error: builder is missing ${command}" >&2
        exit 1
    }
done
work="$(mktemp -d /var/tmp/punar-smplify-lab.XXXXXX)"
raw="${work}/disk.raw"
layout="${work}/layout.json"
root_mount="${work}/root"
root_loop=''
root_mounted=0
cleanup() {
    if [ "${root_mounted}" -eq 1 ]; then
        umount "${root_mount}" 2>/dev/null || true
    fi
    [ -n "${root_loop}" ] && losetup -d "${root_loop}" 2>/dev/null || true
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
mkdir -p "${root_mount}"
mount "${root_loop}" "${root_mount}"
root_mounted=1

bundle="${root_mount}/etc/ssl/certs/ca-certificates.crt"
[ -f "${bundle}" ] || {
    echo 'error: image has no platform CA bundle' >&2
    exit 1
}
[ -x "${root_mount}/usr/bin/punar-smplifyd" ] || {
    echo 'error: this image has no punar-smplifyd; build from a branch that ships it' >&2
    exit 1
}
mkdir -p "${root_mount}/usr/local/share/ca-certificates"
install -m 0644 "${PUNAR_LAB_CA}" \
    "${root_mount}/usr/local/share/ca-certificates/punar-smplify-lab.crt"
cat "${PUNAR_LAB_CA}" >> "${bundle}"
printf '\n10.0.2.2 %s\n' "${PUNAR_LAB_DOMAIN}" >> "${root_mount}/etc/hosts"
install -d -m 0755 "${root_mount}/etc/punar/smplify"
install -m 0644 "${PUNAR_LAB_ORG}" "${root_mount}/etc/punar/smplify/${PUNAR_LAB_DOMAIN}.json"
# A dev/CI image points punard at the mock through a drop-in; the lab wants
# the real agent, so a later drop-in wins.
if [ -f "${root_mount}/usr/lib/systemd/system/punard.service.d/10-mock-control-plane.conf" ]; then
    cat > "${root_mount}/usr/lib/systemd/system/punard.service.d/20-smplify-lab.conf" <<'DROPIN'
[Service]
Environment=PUNAR_CONTROL_PLANE_SOCKET=/run/punar-smplifyd/api.sock
DROPIN
fi
grep -qx "10.0.2.2 ${PUNAR_LAB_DOMAIN}" "${root_mount}/etc/hosts"
grep -q 'Punar Smplify Lab CA' \
    <(openssl x509 -in "${root_mount}/usr/local/share/ca-certificates/punar-smplify-lab.crt" -noout -subject)
jq -e --arg d "${PUNAR_LAB_DOMAIN}" '.discovery.domain == $d and (.enrollment.server | startswith("https://"))' \
    "${root_mount}/etc/punar/smplify/${PUNAR_LAB_DOMAIN}.json" >/dev/null
sync
umount "${root_mount}"
root_mounted=0
losetup -d "${root_loop}"
root_loop=''
temporary="${PUNAR_OUTPUT_IMAGE}.tmp"
qemu-img convert -p -O qcow2 -c "${raw}" "${temporary}"
qemu-img check "${temporary}"
mv "${temporary}" "${PUNAR_OUTPUT_IMAGE}"
chown "${PUNAR_HOST_UID}:${PUNAR_HOST_GID}" "${PUNAR_OUTPUT_IMAGE}"
CONTAINER

shasum -a 256 "${OUTPUT_IMAGE}" > "${LAB_DIR}/image.sha256"
chmod 0600 "${LAB_DIR}/image.sha256"
BUILD_COMPLETE=1
echo "==> Smplify lab ready"
echo "    1. start the edge:      ${LAB_DIR}/start-edge.sh"
echo "    2. boot the VM:         PUNAR_VM_PERSIST=1 ${REPO_ROOT}/tools/demo-arm64-vm.sh ${OUTPUT_IMAGE}"
echo "    3. issue a code:        smplify linux enrollment-token issue --file token.json --yes"
echo "    4. in the VM:           sudo punarctl enroll start ${LAB_DOMAIN}   (paste the code at the prompt)"
echo "    organisation document: /etc/punar/smplify/${LAB_DOMAIN}.json in the image"
echo "    CA and keys stay in mode-0600 files under ${LAB_DIR}; nothing here is a production artifact"
